// Package objstore migrates object storage off a hyperscaler (Cloudflare R2 or
// AWS S3) onto EU-sovereign MinIO. It applies the same 0% false-positive
// discipline as the edge migration: it maps bucket *configuration* faithfully
// (versioning, CORS, lifecycle) and refuses to guess the dangerous parts —
// public access is an explicit ASK, an IAM/bucket policy is MANUAL, never
// silently reproduced or dropped. The actual object copy is left to rclone
// (the engine emits the plan, it does not move terabytes itself).
package objstore

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fabriziosalmi/flareover/internal/report"
)

// Snapshot is a provider-native capture of an object-storage account's buckets.
type Snapshot struct {
	SchemaVersion int      `json:"schema_version"`
	Source        string   `json:"source"` // "r2" | "s3"
	Account       string   `json:"account,omitempty"`
	Buckets       []Bucket `json:"buckets"`
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
	// which MinIO cannot reproduce without a tiering target.
	Transition bool `json:"transition,omitempty"`
}

// Classify assigns a verdict to each bucket setting.
func Classify(s Snapshot) report.Report {
	r := report.Report{Zone: s.Source + ":" + s.Account}
	add := func(f report.Finding) { r.Findings = append(r.Findings, f) }

	for _, b := range s.Buckets {
		// The bucket itself maps cleanly.
		add(report.Finding{Kind: "bucket", Name: b.Name, Verdict: report.Auto, Target: "minio",
			Rationale: "Bucket → MinIO bucket (mc mb). Data copied by rclone as a separate step."})

		if b.Versioning {
			add(report.Finding{Kind: "versioning", Name: b.Name, Verdict: report.Auto, Target: "minio",
				Rationale: "Object versioning → MinIO versioning (mc version enable)."})
		}
		for i := range b.CORS {
			add(report.Finding{Kind: "cors", Name: fmt.Sprintf("%s#%d", b.Name, i), Verdict: report.Auto, Target: "minio",
				Rationale: "CORS rule → MinIO bucket CORS (mc cors set)."})
		}
		for _, lc := range b.Lifecycle {
			if lc.Transition {
				add(report.Finding{Kind: "lifecycle", Name: b.Name + "/" + lc.ID, Verdict: report.Manual,
					Rationale: "Lifecycle rule uses storage-class transitions (tiering) with no MinIO target — recreate manually if needed."})
			} else {
				add(report.Finding{Kind: "lifecycle", Name: b.Name + "/" + lc.ID, Verdict: report.Auto, Target: "minio",
					Rationale: fmt.Sprintf("Expiry lifecycle (%dd) → MinIO ILM (mc ilm rule add).", lc.ExpireDays)})
			}
		}
		if b.PublicRead {
			// Never make a bucket public without an explicit yes.
			add(report.Finding{Kind: "public-access", Name: b.Name, Verdict: report.Ask, Target: "minio",
				Rationale: "Bucket is publicly readable. Reproducing public access is a security decision — MinIO can do it (mc anonymous set download) but only on your explicit confirmation.",
				Question: &report.Question{ID: "public-read:" + b.Name,
					Prompt:  fmt.Sprintf("Reproduce public read access on MinIO bucket %q?", b.Name),
					Options: []string{"yes", "no"}, Default: "no"}})
		}
		if strings.TrimSpace(b.PolicyJSON) != "" {
			// IAM/bucket policies don't map 1:1 to MinIO policies — never guessed.
			add(report.Finding{Kind: "policy", Name: b.Name, Verdict: report.Manual,
				Rationale: "A bucket/IAM policy is attached. S3 IAM policy semantics differ from MinIO's; translate it by hand into a MinIO policy — do not assume equivalence."})
		}
	}
	return r
}

// GenOptions parameterizes generation.
type GenOptions struct {
	MinIOAlias    string // mc alias name, e.g. "eu"
	MinIOEndpoint string // e.g. https://s3.contabo.example
	Decisions     map[string]string
}

// Artifact is a generated file (mirrors target.Artifact to avoid a dependency).
type Artifact struct {
	Path    string
	Content []byte
	Note    string
}

// Generate emits the MinIO provisioning script, the rclone data-copy plan, and a
// runbook — for the AUTO plus answered-ASK surface only.
func Generate(s Snapshot, opts GenOptions) []Artifact {
	if opts.MinIOAlias == "" {
		opts.MinIOAlias = "eu"
	}
	if opts.MinIOEndpoint == "" {
		opts.MinIOEndpoint = "https://MINIO_ENDPOINT"
	}
	alias := opts.MinIOAlias

	var prov strings.Builder
	prov.WriteString("#!/usr/bin/env bash\n")
	prov.WriteString("# flareover-generated MinIO provisioning. Requires the MinIO client `mc`.\n")
	prov.WriteString("# Set MINIO_ACCESS_KEY / MINIO_SECRET_KEY in the environment first.\n")
	prov.WriteString("set -euo pipefail\n\n")
	fmt.Fprintf(&prov, "mc alias set %s %s \"$MINIO_ACCESS_KEY\" \"$MINIO_SECRET_KEY\"\n\n", alias, opts.MinIOEndpoint)

	for _, b := range s.Buckets {
		fmt.Fprintf(&prov, "# --- bucket %s ---\n", b.Name)
		fmt.Fprintf(&prov, "mc mb -p %s/%s\n", alias, b.Name)
		if b.Versioning {
			fmt.Fprintf(&prov, "mc version enable %s/%s\n", alias, b.Name)
		}
		for _, lc := range b.Lifecycle {
			if lc.Transition || lc.ExpireDays <= 0 {
				continue
			}
			fmt.Fprintf(&prov, "mc ilm rule add --expire-days %d %s %s/%s\n",
				lc.ExpireDays, ilmPrefix(lc.Prefix), alias, b.Name)
		}
		if len(b.CORS) > 0 {
			fmt.Fprintf(&prov, "mc cors set %s/%s /etc/minio/cors/%s.json  # see cors artifact\n", alias, b.Name, b.Name)
		}
		if b.PublicRead && answered(opts.Decisions, "public-read:"+b.Name, "yes") {
			fmt.Fprintf(&prov, "mc anonymous set download %s/%s   # confirmed public read\n", alias, b.Name)
		} else if b.PublicRead {
			fmt.Fprintf(&prov, "# public read NOT reproduced (unanswered/declined) — bucket stays private\n")
		}
		prov.WriteString("\n")
	}

	arts := []Artifact{{Path: "minio/provision.sh", Content: []byte(prov.String()), Note: "run with mc installed + MINIO_* creds set"}}

	// CORS artifacts (one JSON per bucket that has rules).
	for _, b := range s.Buckets {
		if len(b.CORS) == 0 {
			continue
		}
		body, _ := json.MarshalIndent(map[string]any{"corsRules": b.CORS}, "", "  ")
		arts = append(arts, Artifact{Path: "minio/cors/" + b.Name + ".json", Content: append(body, '\n')})
	}

	// rclone data-copy plan.
	var rc strings.Builder
	rc.WriteString("#!/usr/bin/env bash\n")
	rc.WriteString("# flareover-generated rclone data migration. The engine maps config; rclone copies data.\n")
	rc.WriteString("# Configure two rclone remotes first:\n")
	fmt.Fprintf(&rc, "#   [src]  = the %s source (endpoint + keys)\n", strings.ToUpper(s.Source))
	rc.WriteString("#   [eu]   = the MinIO destination (endpoint + keys)\n")
	rc.WriteString("set -euo pipefail\n\n")
	for _, b := range s.Buckets {
		sz := ""
		if b.ApproxGB > 0 {
			sz = fmt.Sprintf("  # ~%dGB, %d objects", b.ApproxGB, b.ApproxObjs)
		}
		fmt.Fprintf(&rc, "rclone sync --progress src:%s eu:%s%s\n", b.Name, b.Name, sz)
	}
	arts = append(arts, Artifact{Path: "rclone/migrate.sh", Content: []byte(rc.String()),
		Note: "no-egress-fee copy into EU MinIO; run once to seed, again to catch up before cutover"})

	return arts
}

func ilmPrefix(p string) string {
	if p == "" {
		return "--prefix \"\""
	}
	return "--prefix " + p
}

func answered(d map[string]string, id, want string) bool {
	return d != nil && strings.EqualFold(strings.TrimSpace(d[id]), want)
}
