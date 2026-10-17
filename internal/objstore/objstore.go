// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

// Package objstore migrates object storage off a hyperscaler (Cloudflare R2 or
// AWS S3) onto EU-sovereign object storage: self-hosted Garage (the default), an
// existing self-hosted MinIO, or a managed EU S3. It applies the same 0% false-positive
// discipline as the edge migration: it maps bucket *configuration* faithfully
// (versioning, CORS, lifecycle) and refuses to guess the dangerous parts:
// public access is an explicit ASK, an IAM/bucket policy is MANUAL, never
// silently reproduced or dropped. The actual object copy is left to rclone
// (the engine emits the plan, it does not move terabytes itself).
package objstore

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/fabriziosalmi/flareover/internal/report"
	"github.com/fabriziosalmi/flareover/internal/textguard"
)

// Snapshot is a provider-native capture of an object-storage account's buckets.
type Snapshot struct {
	SchemaVersion int      `json:"schema_version"`
	Source        string   `json:"source"` // "r2" | "s3"
	Account       string   `json:"account,omitempty"`
	Buckets       []Bucket `json:"buckets"`
	// ExtractionGaps are the bucket facets the extractor could not read. Same
	// contract as cloudflare.Snapshot: a facet that could not be read is not a
	// facet that is absent, and Classify reports each one MANUAL so the
	// difference is visible.
	ExtractionGaps []Gap `json:"extraction_gaps,omitempty"`
}

// CurrentSchemaVersion is the snapshot shape this build writes.
//
//	1 — the original shape.
//	2 — adds extraction_gaps, so a partial capture says so.
//
// This constant exists because the version previously did not: both extractors
// wrote the literal 1 independently and nothing read it back, which is a label
// rather than a control. A version only controls compatibility if something
// declines to proceed on a mismatch.
const CurrentSchemaVersion = 2

// Gap is one bucket facet the extractor could not read, and why.
type Gap struct {
	// Bucket is the bucket the facet belongs to; empty for an account-level gap.
	Bucket string `json:"bucket,omitempty"`
	// Facet names what could not be read, e.g. "versioning".
	Facet  string `json:"facet"`
	Detail string `json:"detail,omitempty"`
}

// CheckSchemaVersion refuses a snapshot this build does not understand.
//
// 0 is accepted: hand-authored fixtures predate the field and a zero value is
// indistinguishable from absent. A shape below CurrentSchemaVersion is readable
// but cannot declare a gap, which Classify reports.
func (s Snapshot) CheckSchemaVersion() error {
	switch s.SchemaVersion {
	case 0, 1, CurrentSchemaVersion:
		return nil
	default:
		return fmt.Errorf("buckets snapshot schema_version %d is not supported by this build (understands up to %d): re-run `flareover storage --extract-s3` or `--extract-r2`",
			s.SchemaVersion, CurrentSchemaVersion)
	}
}

// PredatesGapReporting reports the shape that cannot declare an unread facet.
func (s Snapshot) PredatesGapReporting() bool { return s.SchemaVersion < CurrentSchemaVersion }

// bucketNameRe is the S3 bucket naming rule, which every destination here
// enforces: 3-63 chars, lowercase alphanumerics with dots and hyphens, starting
// and ending alphanumeric. It matters because the name is interpolated into the
// generated provisioning and rclone commands, which an operator runs as shell.
var bucketNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// Validate checks a snapshot before any generator interpolates it into a shell
// script. The zone snapshot has had this since the traversal work; the bucket
// snapshot reached the same generators with nothing.
func (s Snapshot) Validate() error {
	var problems []string
	note := func(format string, args ...any) {
		if len(problems) < 20 {
			problems = append(problems, fmt.Sprintf(format, args...))
		}
	}
	for _, bad := range textguard.FindControlStrings(s, "buckets") {
		note("%s", bad)
	}
	for i, b := range s.Buckets {
		if !bucketNameRe.MatchString(b.Name) {
			note("buckets.Buckets[%d].Name %q is not a valid bucket name", i, b.Name)
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("buckets snapshot failed validation:\n  - %s", strings.Join(problems, "\n  - "))
}

// Bucket is one bucket's configuration.
type Bucket struct {
	Name       string          `json:"name"`
	Region     string          `json:"region,omitempty"` // S3 region or R2 location hint
	Versioning bool            `json:"versioning"`
	PublicRead bool            `json:"public_read"`
	CORS       []CORSRule      `json:"cors,omitempty"`
	Lifecycle  []LifecycleRule `json:"lifecycle,omitempty"`
	// PolicyJSON is the raw IAM/bucket policy, if any.
	PolicyJSON string `json:"policy_json,omitempty"`
	ApproxObjs int64  `json:"approx_objects,omitempty"`
	ApproxGB   int64  `json:"approx_gb,omitempty"`
}

// CORSRule mirrors an S3/R2 CORS rule.
type CORSRule struct {
	AllowedOrigins []string `json:"allowed_origins"`
	AllowedMethods []string `json:"allowed_methods"`
	AllowedHeaders []string `json:"allowed_headers,omitempty"`
	MaxAgeSeconds  int      `json:"max_age_seconds,omitempty"`
}

// LifecycleRule mirrors an object-expiry lifecycle rule (transitions omitted).
type LifecycleRule struct {
	ID         string `json:"id"`
	Prefix     string `json:"prefix,omitempty"`
	ExpireDays int    `json:"expire_days,omitempty"`
	// Transition is set when the rule tiers objects to another storage class,
	// which no destination here reproduces without a tiering target.
	Transition bool `json:"transition,omitempty"`
}

// Classify assigns a verdict to each bucket setting for the default
// destination (self-hosted Garage). Use ClassifyFor when a destination is chosen:
// what is AUTO depends on what the destination implements.
func Classify(s Snapshot) report.Report { return ClassifyFor(s, GenOptions{}) }

// ClassifyFor assigns a verdict to each bucket setting for the destination
// opts selects. It must agree with Generate for the same opts (classify ⟺
// generate): a setting is AUTO only if Generate emits it.
func ClassifyFor(s Snapshot, opts GenOptions) report.Report {
	d := resolveDest(opts)
	r := report.Report{Zone: s.Source + ":" + s.Account}
	add := func(f report.Finding) { r.Findings = append(r.Findings, f) }

	classifyStaleCapture(s, add)
	classifyExtractionGaps(s, add)

	for _, b := range s.Buckets {
		// The bucket itself maps cleanly.
		bucketWhy := fmt.Sprintf("Bucket → %s bucket (aws s3api create-bucket). Data copied by rclone as a separate step.", d.name)
		if d.garage {
			bucketWhy = "Bucket → Garage bucket (garage bucket create, global alias, granted to the migration key). Data copied by rclone as a separate step."
		}
		add(report.Finding{Kind: "bucket", Name: b.Name, Verdict: report.Auto, Target: d.target, Rationale: bucketWhy})

		if b.Versioning {
			if d.versioning {
				add(report.Finding{Kind: "versioning", Name: b.Name, Verdict: report.Auto, Target: d.target,
					Rationale: fmt.Sprintf("Object versioning → %s versioning (aws s3api put-bucket-versioning).", d.name)})
			} else {
				add(report.Finding{Kind: "versioning", Name: b.Name, Verdict: report.Manual,
					Rationale: fmt.Sprintf("Object versioning is enabled on the source, and %s does not implement S3 versioning (PutBucketVersioning answers NotImplemented). The bucket migrates without it: earlier versions are not copied and overwrites become final. Choose a destination that versions, or accept the loss explicitly.", d.name)})
			}
		}
		for i := range b.CORS {
			add(report.Finding{Kind: "cors", Name: fmt.Sprintf("%s#%d", b.Name, i), Verdict: report.Auto, Target: d.target,
				Rationale: fmt.Sprintf("CORS rule → %s bucket CORS (aws s3api put-bucket-cors).", d.name)})
		}
		for _, lc := range b.Lifecycle {
			switch {
			case lc.Transition:
				add(report.Finding{Kind: "lifecycle", Name: b.Name + "/" + lc.ID, Verdict: report.Manual,
					Rationale: fmt.Sprintf("Lifecycle rule uses storage-class transitions (tiering) with no %s target: recreate manually if needed.", d.name)})
			case lc.ExpireDays > 0:
				// AUTO only when there is a positive expiry to emit. Generate skips
				// any rule with ExpireDays <= 0, so classify must too (classify ⟺
				// generate). A multipart-abort-only / noncurrent-version-only rule
				// (ExpireDays == 0) has no expiry to reproduce here.
				add(report.Finding{Kind: "lifecycle", Name: b.Name + "/" + lc.ID, Verdict: report.Auto, Target: d.target,
					Rationale: fmt.Sprintf("Expiry lifecycle (%dd) → %s lifecycle expiration (aws s3api put-bucket-lifecycle-configuration).", lc.ExpireDays, d.name)})
			default:
				add(report.Finding{Kind: "lifecycle", Name: b.Name + "/" + lc.ID, Verdict: report.Manual,
					Rationale: "Lifecycle rule has no reproducible object-expiry (e.g. multipart-abort / noncurrent-version only): recreate manually if needed."})
			}
		}
		if b.PublicRead {
			// Never make a bucket public without an explicit yes.
			why := fmt.Sprintf("Bucket is publicly readable. Reproducing public access is a security decision. %s can do it (a public-read bucket policy, aws s3api put-bucket-policy) but only on your explicit confirmation.", d.name)
			prompt := fmt.Sprintf("Reproduce public read access on %s bucket %q?", d.name, b.Name)
			if d.garage {
				why = "Bucket is publicly readable. Garage has no ACLs or bucket policies: public read is served by Garage's web endpoint (website mode, aws s3api put-bucket-website), not by anonymous S3 GETs, so public URLs change to <bucket>.<web root domain>. Reproduced only on your explicit confirmation."
				prompt = fmt.Sprintf("Serve bucket %q publicly through Garage's web endpoint?", b.Name)
			}
			add(report.Finding{Kind: "public-access", Name: b.Name, Verdict: report.Ask, Target: d.target,
				Rationale: why,
				Question: &report.Question{ID: "public-read:" + b.Name,
					Prompt:  prompt,
					Options: []string{"yes", "no"}, Default: "no"}})
		}
		if strings.TrimSpace(b.PolicyJSON) != "" {
			// IAM/bucket policies never map 1:1, never guessed.
			why := fmt.Sprintf("A bucket/IAM policy is attached. S3 IAM policy semantics differ from %s's; translate it by hand: do not assume equivalence.", d.name)
			if d.garage {
				why = "A bucket/IAM policy is attached. Garage does not implement bucket policies (PutBucketPolicy answers NotImplemented); its access model is per-key, per-bucket read/write/owner grants (garage bucket allow). Translate the policy into key grants by hand."
			}
			add(report.Finding{Kind: "policy", Name: b.Name, Verdict: report.Manual, Rationale: why})
		}
	}
	return r
}

// classifyExtractionGaps turns every bucket facet the extractor could not read
// into a MANUAL finding.
//
// The four per-bucket reads are best-effort by design: a 404 on ?cors means the
// bucket genuinely has none. But any other failure used to produce the same
// zero value, so "versioning is off" and "versioning could not be read" were
// the same snapshot — and the second one migrates a bucket without versioning
// while the report calls it covered.
func classifyExtractionGaps(s Snapshot, add func(report.Finding)) {
	for _, g := range s.ExtractionGaps {
		name := g.Facet
		if g.Bucket != "" {
			name = g.Bucket + "/" + g.Facet
		}
		why := fmt.Sprintf("Extraction could not read this setting, so the snapshot does not describe it: whatever is configured there is NOT covered by this report and was NOT migrated. Re-run the extraction once the cause below is addressed. Cause: %s",
			gapDetail(g))
		add(report.Finding{Kind: "extraction-gap", Name: name, Verdict: report.Manual, Rationale: why})
	}
}

// classifyStaleCapture reports a snapshot written before gaps could be recorded.
func classifyStaleCapture(s Snapshot, add func(report.Finding)) {
	if !s.PredatesGapReporting() || len(s.Buckets) == 0 {
		return
	}
	shape := fmt.Sprintf("schema_version %d", s.SchemaVersion)
	if s.SchemaVersion == 0 {
		shape = "no schema_version at all"
	}
	add(report.Finding{Kind: "extraction-gap", Name: "snapshot schema_version", Verdict: report.Manual,
		Rationale: fmt.Sprintf("This buckets snapshot carries %s; this build writes %d. A snapshot written before that version could not record which settings extraction failed to read, so a bucket reported as having no versioning, no lifecycle rules and no attached policy may simply never have been asked. Re-extract before trusting this report.",
			shape, CurrentSchemaVersion)})
}

func gapDetail(g Gap) string {
	if strings.TrimSpace(g.Detail) == "" {
		return "not reported"
	}
	return g.Detail
}

// GenOptions parameterizes classification and generation.
type GenOptions struct {
	MinIOAlias    string // rclone remote name for the destination, e.g. "eu"
	MinIOEndpoint string // S3 endpoint, e.g. https://s3.example.eu (any destination)
	Decisions     map[string]string
	// Dest selects the destination preset: "" / "garage" (self-hosted Garage,
	// default), "minio" (an existing self-hosted MinIO), or a managed EU S3:
	// "scaleway" / "ovh" / "contabo" (fixed region hosts) or "aruba" (endpoint
	// operator-supplied via MinIOEndpoint, account-specific).
	Dest string
	// Region is the provider region (Scaleway/OVH/Contabo) when set; Aruba takes
	// its endpoint from MinIOEndpoint instead.
	Region string
}

// destination is the resolved target. Everything downstream is S3 and is
// driven by the AWS CLI (`aws s3api`), the maintained reference client: the
// MinIO client `mc` this used before is archived upstream, and its download
// endpoint answers 410. Garage additionally needs its own CLI for the two
// things S3 cannot express there (a bucket with a global alias, and a key grant).
type destination struct {
	dir       string // artifact folder + provisioning label base
	alias     string // rclone remote name
	endpoint  string // S3 endpoint
	accessEnv string // env var holding the access key
	secretEnv string // env var holding the secret key
	label     string // human note, carries the sovereignty tier
	target    string // report Target
	name      string // product name used in rationales
	// region is the SigV4 signing region. Empty means it is not known for this
	// provider and must come from S3_REGION at run time: never guessed.
	region     string
	versioning bool // implements S3 bucket versioning
	garage     bool // Garage-native provisioning (garage CLI + website mode)
}

// ScalewayRegions are the EU regions Scaleway Object Storage runs in.
var ScalewayRegions = []string{"fr-par", "nl-ams", "pl-waw", "it-mil"}

// ValidScalewayRegion reports whether region is a known Scaleway region.
func ValidScalewayRegion(region string) bool {
	return contains(ScalewayRegions, region)
}

// ContaboStorageRegions are the EU Contabo Object Storage regions. Contabo's
// only EU-resident region is the European Union one (eu2, Germany); its other
// regions (US/Asia/Australia) are deliberately excluded to keep the migration
// EU-scoped.
var ContaboStorageRegions = []string{"eu2"}

// ValidContaboStorageRegion reports whether region is a known EU Contabo region.
func ValidContaboStorageRegion(region string) bool {
	return contains(ContaboStorageRegions, region)
}

// OVHStorageRegions are OVHcloud Object Storage regions that keep data inside
// the EU. OVH also runs uk (London) and bhs (Beauharnois, Canada); those are
// deliberately excluded so an OVH destination provably stays EU-scoped.
var OVHStorageRegions = []string{"gra", "sbg", "de", "waw"}

// ValidOVHStorageRegion reports whether region is a known EU OVH region.
func ValidOVHStorageRegion(region string) bool {
	return contains(OVHStorageRegions, region)
}

// Dests are the --dest values the CLI accepts; "" means the default (garage).
var Dests = []string{"garage", "minio", "scaleway", "ovh", "contabo", "aruba"}

// ValidDest reports whether dest names a destination preset ("" is the default).
func ValidDest(dest string) bool { return dest == "" || contains(Dests, dest) }

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// resolveDest turns the options into a concrete destination. It trusts the
// caller (the CLI) to have validated Dest/Region, and defaults defensively.
func resolveDest(opts GenOptions) destination {
	switch opts.Dest {
	case "scaleway":
		region := orDefault(opts.Region, "fr-par")
		return destination{
			dir: "scaleway-object-storage", alias: orDefault(opts.MinIOAlias, "scw"),
			endpoint:  "https://s3." + region + ".scw.cloud",
			accessEnv: "SCW_ACCESS_KEY", secretEnv: "SCW_SECRET_KEY",
			label:  "Scaleway Object Storage (EU-owned, " + region + ")",
			target: "scaleway", name: "Scaleway Object Storage", region: region, versioning: true,
		}
	case "ovh":
		region := orDefault(opts.Region, "gra")
		return destination{
			dir: "ovh-object-storage", alias: orDefault(opts.MinIOAlias, "ovh"),
			endpoint:  "https://s3." + region + ".io.cloud.ovh.net",
			accessEnv: "OVH_S3_ACCESS_KEY", secretEnv: "OVH_S3_SECRET_KEY",
			label:  "OVHcloud Object Storage (EU-owned, " + region + ")",
			target: "ovh", name: "OVHcloud Object Storage", region: region, versioning: true,
		}
	case "contabo":
		region := orDefault(opts.Region, "eu2")
		return destination{
			dir: "contabo-object-storage", alias: orDefault(opts.MinIOAlias, "contabo"),
			endpoint:  "https://" + region + ".contabostorage.com",
			accessEnv: "CONTABO_S3_ACCESS_KEY", secretEnv: "CONTABO_S3_SECRET_KEY",
			label:  "Contabo Object Storage (EU-owned, " + region + ")",
			target: "contabo", name: "Contabo Object Storage", versioning: true,
		}
	case "aruba":
		// Aruba's S3 endpoint is account-specific (the "Service Point URL" from the
		// Object Storage account page), not a fixed public region host, so it is
		// operator-supplied (--minio-endpoint), never guessed. The CLI enforces it.
		return destination{
			dir: "aruba-object-storage", alias: orDefault(opts.MinIOAlias, "aruba"),
			endpoint:  opts.MinIOEndpoint,
			accessEnv: "ARUBA_S3_ACCESS_KEY", secretEnv: "ARUBA_S3_SECRET_KEY",
			label:  "Aruba Cloud Object Storage (EU-owned, IT · endpoint " + opts.MinIOEndpoint + ")",
			target: "aruba", name: "Aruba Cloud Object Storage", versioning: true,
		}
	case "minio":
		return destination{
			dir: "minio", alias: orDefault(opts.MinIOAlias, "eu"),
			endpoint:  orDefault(opts.MinIOEndpoint, "https://MINIO_ENDPOINT"),
			accessEnv: "MINIO_ACCESS_KEY", secretEnv: "MINIO_SECRET_KEY",
			label:  "self-hosted MinIO",
			target: "minio", name: "MinIO", region: "us-east-1", versioning: true,
		}
	}
	return destination{
		dir: "garage", alias: orDefault(opts.MinIOAlias, "eu"),
		endpoint:  orDefault(opts.MinIOEndpoint, "https://GARAGE_S3_ENDPOINT"),
		accessEnv: "GARAGE_ACCESS_KEY", secretEnv: "GARAGE_SECRET_KEY",
		label:  "self-hosted Garage",
		target: "garage", name: "Garage", region: "garage", garage: true,
	}
}

// Artifact is a generated file (mirrors target.Artifact to avoid a dependency).
type Artifact struct {
	Path    string
	Content []byte
	Note    string
}

// awsCORS is the CORS document `aws s3api put-bucket-cors` reads.
type awsCORS struct {
	CORSRules []awsCORSRule `json:"CORSRules"`
}

type awsCORSRule struct {
	AllowedOrigins []string `json:"AllowedOrigins"`
	AllowedMethods []string `json:"AllowedMethods"`
	AllowedHeaders []string `json:"AllowedHeaders,omitempty"`
	MaxAgeSeconds  int      `json:"MaxAgeSeconds,omitempty"`
}

// expiryRules are the lifecycle rules Generate reproduces: positive expiry, no
// tiering. Classify marks exactly these AUTO.
func expiryRules(b Bucket) []LifecycleRule {
	var out []LifecycleRule
	for _, lc := range b.Lifecycle {
		if lc.Transition || lc.ExpireDays <= 0 {
			continue
		}
		out = append(out, lc)
	}
	return out
}

// Generate emits the provisioning script, its JSON documents (CORS, lifecycle,
// public-read policy), the rclone data-copy plan, for the AUTO plus
// answered-ASK surface only.
func Generate(s Snapshot, opts GenOptions) []Artifact {
	d := resolveDest(opts)

	var prov strings.Builder
	prov.WriteString("#!/usr/bin/env bash\n")
	fmt.Fprintf(&prov, "# flareover-generated provisioning for %s.\n", d.label)
	prov.WriteString("# Requires the AWS CLI v2 (`aws`): it speaks plain S3 to any endpoint.\n")
	if d.garage {
		prov.WriteString("# Also requires the Garage CLI on a cluster node, for the two things S3 cannot\n")
		prov.WriteString("# express on Garage: a bucket with a global alias, and a key grant. Point\n")
		prov.WriteString("# GARAGE_CLI at it (default: garage). With flareover's deploy/ compose:\n")
		prov.WriteString("#   GARAGE_CLI=\"docker compose exec -T garage /garage\"\n")
		prov.WriteString("# GARAGE_KEY is the name or ID of the Garage key the buckets are granted to;\n")
		fmt.Fprintf(&prov, "# %s / %s are that key's credentials.\n", d.accessEnv, d.secretEnv)
	} else {
		fmt.Fprintf(&prov, "# Set %s / %s in the environment first.\n", d.accessEnv, d.secretEnv)
	}
	prov.WriteString("set -euo pipefail\n")
	prov.WriteString("HERE=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")\" && pwd)\"\n")
	if d.region != "" {
		fmt.Fprintf(&prov, "REGION=\"${S3_REGION:-%s}\"\n", d.region)
	} else {
		fmt.Fprintf(&prov, "REGION=\"${S3_REGION:?set S3_REGION to the signing region of your %s endpoint: it is not guessed}\"\n", d.name)
	}
	if d.garage {
		prov.WriteString("read -r -a GARAGE <<< \"${GARAGE_CLI:-garage}\"\n")
		prov.WriteString(": \"${GARAGE_KEY:?set GARAGE_KEY to the name or ID of the Garage key the buckets are granted to}\"\n")
	}
	prov.WriteString("s3() {\n")
	fmt.Fprintf(&prov, "  AWS_ACCESS_KEY_ID=\"$%s\" AWS_SECRET_ACCESS_KEY=\"$%s\" AWS_DEFAULT_REGION=\"$REGION\" \\\n", d.accessEnv, d.secretEnv)
	fmt.Fprintf(&prov, "    aws --endpoint-url %q s3api \"$@\"\n", d.endpoint)
	prov.WriteString("}\n\n")

	var arts []Artifact
	for _, b := range s.Buckets {
		fmt.Fprintf(&prov, "# --- bucket %s ---\n", b.Name)
		if d.garage {
			// Created through the Garage CLI, not S3 CreateBucket: a bucket created
			// over S3 gets only a key-local alias, which the web endpoint and every
			// other key cannot see. Idempotent, like the old `mc mb -p`.
			fmt.Fprintf(&prov, "\"${GARAGE[@]}\" bucket info %s >/dev/null 2>&1 || \"${GARAGE[@]}\" bucket create %s\n", b.Name, b.Name)
			fmt.Fprintf(&prov, "\"${GARAGE[@]}\" bucket allow --read --write --owner %s --key \"$GARAGE_KEY\"\n", b.Name)
		} else {
			fmt.Fprintf(&prov, "s3 head-bucket --bucket %s >/dev/null 2>&1 || s3 create-bucket --bucket %s\n", b.Name, b.Name)
			if b.Versioning {
				fmt.Fprintf(&prov, "s3 put-bucket-versioning --bucket %s --versioning-configuration Status=Enabled\n", b.Name)
			}
		}
		if rules := expiryRules(b); len(rules) > 0 {
			var lc []map[string]any
			for _, r := range rules {
				lc = append(lc, map[string]any{
					"ID": r.ID, "Status": "Enabled",
					"Filter":     map[string]any{"Prefix": r.Prefix},
					"Expiration": map[string]any{"Days": r.ExpireDays},
				})
			}
			body, _ := json.MarshalIndent(map[string]any{"Rules": lc}, "", "  ")
			path := "lifecycle/" + b.Name + ".json"
			arts = append(arts, Artifact{Path: d.dir + "/" + path, Content: append(body, '\n')})
			fmt.Fprintf(&prov, "s3 put-bucket-lifecycle-configuration --bucket %s --lifecycle-configuration \"file://$HERE/%s\"\n", b.Name, path)
		}
		if len(b.CORS) > 0 {
			doc := awsCORS{}
			for _, c := range b.CORS {
				doc.CORSRules = append(doc.CORSRules, awsCORSRule(c))
			}
			body, _ := json.MarshalIndent(doc, "", "  ")
			path := "cors/" + b.Name + ".json"
			arts = append(arts, Artifact{Path: d.dir + "/" + path, Content: append(body, '\n')})
			fmt.Fprintf(&prov, "s3 put-bucket-cors --bucket %s --cors-configuration \"file://$HERE/%s\"\n", b.Name, path)
		}
		switch {
		case b.PublicRead && answered(opts.Decisions, "public-read:"+b.Name, "yes") && d.garage:
			fmt.Fprintf(&prov, "s3 put-bucket-website --bucket %s --website-configuration '{\"IndexDocument\":{\"Suffix\":\"index.html\"}}'   # confirmed public read: served by Garage's web endpoint, not anonymous S3\n", b.Name)
		case b.PublicRead && answered(opts.Decisions, "public-read:"+b.Name, "yes"):
			policy := map[string]any{
				"Version": "2012-10-17",
				"Statement": []map[string]any{{
					"Sid": "PublicRead", "Effect": "Allow", "Principal": "*",
					"Action": []string{"s3:GetObject"}, "Resource": []string{"arn:aws:s3:::" + b.Name + "/*"},
				}},
			}
			body, _ := json.MarshalIndent(policy, "", "  ")
			path := "policy/" + b.Name + ".json"
			arts = append(arts, Artifact{Path: d.dir + "/" + path, Content: append(body, '\n')})
			fmt.Fprintf(&prov, "s3 put-bucket-policy --bucket %s --policy \"file://$HERE/%s\"   # confirmed public read\n", b.Name, path)
		case b.PublicRead:
			prov.WriteString("# public read NOT reproduced (unanswered/declined): bucket stays private\n")
		}
		prov.WriteString("\n")
	}

	note := fmt.Sprintf("run with aws installed + %s / %s set", d.accessEnv, d.secretEnv)
	if d.garage {
		note = fmt.Sprintf("run with aws + the garage CLI (GARAGE_CLI) + GARAGE_KEY, %s / %s set", d.accessEnv, d.secretEnv)
	}
	arts = append([]Artifact{{Path: d.dir + "/provision.sh", Content: []byte(prov.String()), Note: note}}, arts...)

	// rclone data-copy plan.
	var rc strings.Builder
	rc.WriteString("#!/usr/bin/env bash\n")
	rc.WriteString("# flareover-generated rclone data migration. The engine maps config; rclone copies data.\n")
	rc.WriteString("# Configure two rclone remotes first:\n")
	fmt.Fprintf(&rc, "#   [src]   = the %s source (endpoint + keys)\n", strings.ToUpper(s.Source))
	fmt.Fprintf(&rc, "#   [%s] = %s (%s)\n", d.alias, d.label, d.endpoint)
	rc.WriteString("set -euo pipefail\n\n")
	for _, b := range s.Buckets {
		sz := ""
		if b.ApproxGB > 0 {
			sz = fmt.Sprintf("  # ~%dGB, %d objects", b.ApproxGB, b.ApproxObjs)
		}
		fmt.Fprintf(&rc, "rclone sync --progress src:%s %s:%s%s\n", b.Name, d.alias, b.Name, sz)
	}
	arts = append(arts, Artifact{Path: "rclone/migrate.sh", Content: []byte(rc.String()),
		Note: fmt.Sprintf("no-egress-fee copy into %s; run once to seed, again to catch up before cutover", d.label)})

	return arts
}

func answered(d map[string]string, id, want string) bool {
	return d != nil && strings.EqualFold(strings.TrimSpace(d[id]), want)
}
