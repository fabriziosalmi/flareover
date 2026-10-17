// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package objstore

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/fabriziosalmi/flareover/internal/report"
)

func load(t *testing.T) Snapshot {
	t.Helper()
	b, err := os.ReadFile("../../testdata/fixtures/storage.snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func find(r report.Report, kind, name string) *report.Finding {
	for i := range r.Findings {
		if r.Findings[i].Kind == kind && r.Findings[i].Name == name {
			return &r.Findings[i]
		}
	}
	return nil
}

func TestClassifyVerdictsGarageDefault(t *testing.T) {
	r := Classify(load(t))
	cases := []struct {
		kind, name string
		want       report.Verdict
	}{
		{"bucket", "public-assets", report.Auto},
		// Garage does not implement S3 versioning: never a silent AUTO.
		{"versioning", "public-assets", report.Manual},
		{"cors", "public-assets#0", report.Auto},
		{"lifecycle", "public-assets/expire-temp", report.Auto},
		{"public-access", "public-assets", report.Ask}, // never public silently
		{"bucket", "private-backups", report.Auto},
		{"policy", "private-backups", report.Manual},            // IAM policy not guessed
		{"lifecycle", "private-backups/glacier", report.Manual}, // tiering has no target
	}
	for _, c := range cases {
		f := find(r, c.kind, c.name)
		if f == nil {
			t.Errorf("missing %s/%s", c.kind, c.name)
			continue
		}
		if f.Verdict != c.want {
			t.Errorf("%s/%s: %s, want %s", c.kind, c.name, f.Verdict, c.want)
		}
	}
	if f := find(r, "bucket", "public-assets"); f == nil || f.Target != "garage" {
		t.Errorf("default target must be garage, got %v", f)
	}
	if f := find(r, "public-access", "public-assets"); f == nil || !strings.Contains(f.Rationale, "web endpoint") {
		t.Error("Garage public read must say it is served by the web endpoint, not anonymous S3")
	}
}

func TestClassifyVerdictsMinIO(t *testing.T) {
	r := ClassifyFor(load(t), GenOptions{Dest: "minio"})
	if f := find(r, "versioning", "public-assets"); f == nil || f.Verdict != report.Auto || f.Target != "minio" {
		t.Errorf("MinIO implements versioning: want AUTO/minio, got %v", f)
	}
}

// TestClassifyAgreesWithGenerate is the classify ⟺ generate contract, per
// destination: a setting is AUTO exactly when the script reproduces it.
func TestClassifyAgreesWithGenerate(t *testing.T) {
	for _, dest := range Dests {
		opts := GenOptions{Dest: dest, MinIOEndpoint: "https://s3.example.eu"}
		r := ClassifyFor(load(t), opts)
		var prov string
		for _, a := range Generate(load(t), opts) {
			if strings.HasSuffix(a.Path, "/provision.sh") {
				prov = string(a.Content)
			}
		}
		f := find(r, "versioning", "public-assets")
		auto := f != nil && f.Verdict == report.Auto
		emitted := strings.Contains(prov, "put-bucket-versioning --bucket public-assets")
		if auto != emitted {
			t.Errorf("%s: versioning AUTO=%v but emitted=%v", dest, auto, emitted)
		}
		lc := find(r, "lifecycle", "public-assets/expire-temp")
		if (lc != nil && lc.Verdict == report.Auto) != strings.Contains(prov, "put-bucket-lifecycle-configuration --bucket public-assets") {
			t.Errorf("%s: lifecycle verdict and script disagree", dest)
		}
	}
}

// TestGarageProvisioning pins what was measured against Garage v2.4.1: a bucket
// created over S3 gets only a key-local alias (invisible to the web endpoint and
// to every other key), so buckets are created through the Garage CLI and granted
// to the migration key; versioning (NotImplemented) is never emitted.
func TestGarageProvisioning(t *testing.T) {
	arts := Generate(load(t), GenOptions{})
	prov := artifact(arts, "garage/provision.sh")
	if prov == "" {
		t.Fatal("no garage/provision.sh artifact")
	}
	for _, want := range []string{
		`read -r -a GARAGE <<< "${GARAGE_CLI:-garage}"`,
		`: "${GARAGE_KEY:?`,
		`REGION="${S3_REGION:-garage}"`,
		`"${GARAGE[@]}" bucket info public-assets >/dev/null 2>&1 || "${GARAGE[@]}" bucket create public-assets`,
		`"${GARAGE[@]}" bucket allow --read --write --owner public-assets --key "$GARAGE_KEY"`,
		`s3 put-bucket-lifecycle-configuration --bucket public-assets --lifecycle-configuration "file://$HERE/lifecycle/public-assets.json"`,
		`s3 put-bucket-cors --bucket public-assets --cors-configuration "file://$HERE/cors/public-assets.json"`,
		`aws --endpoint-url "https://GARAGE_S3_ENDPOINT" s3api "$@"`,
	} {
		if !strings.Contains(prov, want) {
			t.Errorf("garage provision.sh missing %q", want)
		}
	}
	for _, bad := range []string{"create-bucket", "put-bucket-versioning", "put-bucket-policy"} {
		if strings.Contains(prov, bad) {
			t.Errorf("garage provision.sh must not use %s", bad)
		}
	}
	var lc struct {
		Rules []struct {
			ID         string
			Status     string
			Filter     struct{ Prefix string }
			Expiration struct{ Days int }
		}
	}
	if err := json.Unmarshal([]byte(artifact(arts, "garage/lifecycle/public-assets.json")), &lc); err != nil {
		t.Fatal(err)
	}
	if len(lc.Rules) != 1 || lc.Rules[0].Expiration.Days != 30 || lc.Rules[0].Status != "Enabled" {
		t.Errorf("lifecycle document: %+v", lc)
	}
	var cors awsCORS
	if err := json.Unmarshal([]byte(artifact(arts, "garage/cors/public-assets.json")), &cors); err != nil || len(cors.CORSRules) == 0 || len(cors.CORSRules[0].AllowedOrigins) == 0 {
		t.Errorf("CORS document must be the aws s3api shape (CORSRules/AllowedOrigins), err=%v doc=%+v", err, cors)
	}
}

// TestPublicNotReproducedWithoutYes is the 0% FP guard for storage, on every
// destination: a public bucket becomes public only on an explicit yes.
func TestPublicNotReproducedWithoutYes(t *testing.T) {
	yes := map[string]string{"public-read:public-assets": "yes"}
	for _, dest := range Dests {
		opts := GenOptions{Dest: dest, MinIOEndpoint: "https://s3.example.eu"}
		prov := func(o GenOptions) string {
			for _, a := range Generate(load(t), o) {
				if strings.HasSuffix(a.Path, "/provision.sh") {
					return string(a.Content)
				}
			}
			return ""
		}
		no := prov(opts)
		if strings.Contains(no, "put-bucket-website") || strings.Contains(no, "put-bucket-policy") {
			t.Errorf("%s: public read reproduced without an explicit yes", dest)
		}
		if !strings.Contains(no, "stays private") {
			t.Errorf("%s: declined public read should be noted, not silent", dest)
		}
		opts.Decisions = yes
		got := prov(opts)
		want := "s3 put-bucket-policy --bucket public-assets"
		if dest == "garage" {
			want = "s3 put-bucket-website --bucket public-assets"
		}
		if !strings.Contains(got, want) {
			t.Errorf("%s: confirmed public read should emit %q", dest, want)
		}
	}
	// The policy document grants anonymous GetObject on that bucket only.
	arts := Generate(load(t), GenOptions{Dest: "minio", Decisions: yes})
	pol := artifact(arts, "minio/policy/public-assets.json")
	for _, want := range []string{`"Principal": "*"`, `"s3:GetObject"`, `"arn:aws:s3:::public-assets/*"`} {
		if !strings.Contains(pol, want) {
			t.Errorf("public-read policy missing %s:\n%s", want, pol)
		}
	}
}

func TestRcloneArtifacts(t *testing.T) {
	rc := artifact(Generate(load(t), GenOptions{}), "rclone/migrate.sh")
	if !strings.Contains(rc, "rclone sync --progress src:private-backups eu:private-backups") {
		t.Error("rclone plan missing a bucket sync")
	}
	if !strings.Contains(rc, "900GB") {
		t.Error("rclone plan should surface the data volume")
	}
}

// TestLifecycleZeroExpiryIsManual pins the audit fix: a lifecycle rule with no
// positive object-expiry (multipart-abort / noncurrent-version only) is MANUAL
// and is not in the generated lifecycle document (classify ⟺ generate).
func TestLifecycleZeroExpiryIsManual(t *testing.T) {
	snap := Snapshot{Source: "s3", Buckets: []Bucket{{
		Name: "b", Lifecycle: []LifecycleRule{
			{ID: "abort-only", ExpireDays: 0}, // no expiry → MANUAL, not emitted
			{ID: "expire-30", ExpireDays: 30}, // positive → AUTO, emitted
		},
	}}}
	r := Classify(snap)
	if f := find(r, "lifecycle", "b/abort-only"); f == nil || f.Verdict != report.Manual {
		t.Errorf("zero-expiry lifecycle must be MANUAL, got %v", f)
	}
	if f := find(r, "lifecycle", "b/expire-30"); f == nil || f.Verdict != report.Auto {
		t.Errorf("positive-expiry lifecycle must be AUTO, got %v", f)
	}
	doc := artifact(Generate(snap, GenOptions{}), "garage/lifecycle/b.json")
	if strings.Contains(doc, "abort-only") {
		t.Error("the zero-expiry rule must not be emitted")
	}
	if !strings.Contains(doc, "expire-30") || !strings.Contains(doc, `"Days": 30`) {
		t.Error("the positive-expiry rule must be emitted")
	}
}

// TestNoArchivedClientInAnyScript: the MinIO client is archived upstream and its
// download endpoint answers 410; no destination may still depend on it.
func TestNoArchivedClientInAnyScript(t *testing.T) {
	for _, dest := range Dests {
		for _, a := range Generate(load(t), GenOptions{Dest: dest, MinIOEndpoint: "https://s3.example.eu"}) {
			for _, line := range strings.Split(string(a.Content), "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "mc ") {
					t.Errorf("%s %s still calls mc: %q", dest, a.Path, line)
				}
			}
		}
	}
}

func TestValidDest(t *testing.T) {
	for _, d := range append([]string{""}, Dests...) {
		if !ValidDest(d) {
			t.Errorf("%q should be valid", d)
		}
	}
	if ValidDest("s3") {
		t.Error("unknown destinations must be rejected")
	}
}

// TestScalewayDestination checks the managed-EU-S3 preset: endpoint, signing
// region, credentials env, rclone remote, and artifact folder.
func TestScalewayDestination(t *testing.T) {
	arts := Generate(load(t), GenOptions{Dest: "scaleway"})
	prov := artifact(arts, "scaleway-object-storage/provision.sh")
	if prov == "" {
		t.Fatal("no scaleway-object-storage/provision.sh artifact")
	}
	for _, want := range []string{
		`aws --endpoint-url "https://s3.fr-par.scw.cloud" s3api "$@"`,
		`AWS_ACCESS_KEY_ID="$SCW_ACCESS_KEY" AWS_SECRET_ACCESS_KEY="$SCW_SECRET_KEY"`,
		`REGION="${S3_REGION:-fr-par}"`,
		"s3 head-bucket --bucket public-assets >/dev/null 2>&1 || s3 create-bucket --bucket public-assets",
		"s3 put-bucket-versioning --bucket public-assets --versioning-configuration Status=Enabled",
		"Scaleway Object Storage (EU-owned, fr-par)",
	} {
		if !strings.Contains(prov, want) {
			t.Errorf("scaleway provision.sh missing %q", want)
		}
	}
	if strings.Contains(prov, "MINIO_ACCESS_KEY") || strings.Contains(prov, "GARAGE") {
		t.Error("scaleway provision leaked another destination's creds")
	}
	rc := artifact(arts, "rclone/migrate.sh")
	if !strings.Contains(rc, "rclone sync --progress src:public-assets scw:public-assets") {
		t.Error("rclone plan should target the scw: remote")
	}
	nl := artifact(Generate(load(t), GenOptions{Dest: "scaleway", Region: "nl-ams"}), "scaleway-object-storage/provision.sh")
	if !strings.Contains(nl, "https://s3.nl-ams.scw.cloud") || !strings.Contains(nl, `REGION="${S3_REGION:-nl-ams}"`) {
		t.Error("region override did not reach the endpoint and the signing region")
	}
}

func TestValidScalewayRegion(t *testing.T) {
	for _, r := range ScalewayRegions {
		if !ValidScalewayRegion(r) {
			t.Errorf("%q should be valid", r)
		}
	}
	if ValidScalewayRegion("us-east-1") {
		t.Error("us-east-1 must not be a valid Scaleway region")
	}
}

// TestOVHDestination checks the OVHcloud managed-S3 preset.
func TestOVHDestination(t *testing.T) {
	prov := artifact(Generate(load(t), GenOptions{Dest: "ovh"}), "ovh-object-storage/provision.sh")
	for _, want := range []string{
		`aws --endpoint-url "https://s3.gra.io.cloud.ovh.net" s3api "$@"`,
		`AWS_ACCESS_KEY_ID="$OVH_S3_ACCESS_KEY"`,
		`REGION="${S3_REGION:-gra}"`,
		"OVHcloud Object Storage (EU-owned, gra)",
	} {
		if !strings.Contains(prov, want) {
			t.Errorf("ovh provision.sh missing %q", want)
		}
	}
	de := artifact(Generate(load(t), GenOptions{Dest: "ovh", Region: "de"}), "ovh-object-storage/provision.sh")
	if !strings.Contains(de, "https://s3.de.io.cloud.ovh.net") {
		t.Error("OVH region override did not reach the endpoint")
	}
}

// TestContaboAndArubaSigningRegionIsNeverGuessed: their SigV4 region is not
// known here, so the script demands S3_REGION instead of inventing one.
func TestContaboAndArubaSigningRegionIsNeverGuessed(t *testing.T) {
	ep := "https://sp-eu-it1.arubacloud.example"
	for _, c := range []struct{ dest, path, endpoint, env string }{
		{"contabo", "contabo-object-storage/provision.sh", "https://eu2.contabostorage.com", "CONTABO_S3_ACCESS_KEY"},
		{"aruba", "aruba-object-storage/provision.sh", ep, "ARUBA_S3_ACCESS_KEY"},
	} {
		prov := artifact(Generate(load(t), GenOptions{Dest: c.dest, MinIOEndpoint: ep}), c.path)
		if !strings.Contains(prov, `REGION="${S3_REGION:?`) {
			t.Errorf("%s: S3_REGION must be required, not defaulted", c.dest)
		}
		if !strings.Contains(prov, `aws --endpoint-url "`+c.endpoint+`"`) || !strings.Contains(prov, c.env) {
			t.Errorf("%s: wrong endpoint or credentials env", c.dest)
		}
	}
}

func TestValidContaboStorageRegion(t *testing.T) {
	if !ValidContaboStorageRegion("eu2") {
		t.Error("eu2 must be a valid Contabo region")
	}
	if ValidContaboStorageRegion("usc1") {
		t.Error("non-EU Contabo regions must be rejected (EU-scoped migration)")
	}
}

// TestValidOVHStorageRegion: only EU regions are accepted (uk/bhs excluded).
func TestValidOVHStorageRegion(t *testing.T) {
	for _, r := range OVHStorageRegions {
		if !ValidOVHStorageRegion(r) {
			t.Errorf("%q should be valid", r)
		}
	}
	for _, bad := range []string{"uk", "bhs", "us-east-1"} {
		if ValidOVHStorageRegion(bad) {
			t.Errorf("%q must not be a valid EU OVH region", bad)
		}
	}
}

func artifact(arts []Artifact, path string) string {
	for _, a := range arts {
		if a.Path == path {
			return string(a.Content)
		}
	}
	return ""
}

// --- the guards the zone snapshot had and this one did not -----------------

// A failed read of a bucket facet used to be recorded as the facet being
// absent, which is the permissive answer: "versioning off" rather than
// "versioning could not be read". The migration then drops the setting and the
// report calls the bucket covered.
func TestUnreadableFacetBecomesAGapNotAFalseNegative(t *testing.T) {
	s := Snapshot{
		SchemaVersion: CurrentSchemaVersion,
		Source:        "s3",
		Buckets:       []Bucket{{Name: "media"}},
		ExtractionGaps: []Gap{
			{Bucket: "media", Facet: "versioning", Detail: "HTTP 403 (key cannot read bucket configuration)"},
		},
	}
	rep := Classify(s)
	var found *report.Finding
	for i, f := range rep.Findings {
		if f.Kind == "extraction-gap" {
			found = &rep.Findings[i]
			break
		}
	}
	if found == nil {
		t.Fatal("an unreadable facet produced no finding: the report would claim coverage it does not have")
	}
	if found.Verdict != report.Manual {
		t.Errorf("verdict = %s, want MANUAL", found.Verdict)
	}
	if found.Name != "media/versioning" {
		t.Errorf("name = %q, want the bucket and the facet", found.Name)
	}
	if !strings.Contains(found.Rationale, "403") {
		t.Errorf("rationale should carry the cause: %q", found.Rationale)
	}
	if rep.Counts()[report.Manual] == 0 {
		t.Error("a snapshot with gaps would exit 0 as a clean migration")
	}
}

// A 404 means the bucket genuinely has no such configuration, which is the
// normal case for CORS and lifecycle. It must not become noise.
func TestAbsentConfigurationIsNotAGap(t *testing.T) {
	for _, msg := range []string{
		"/media?cors: HTTP 404: NoSuchCORSConfiguration",
		"/media?policy: HTTP 404",
		"NoSuchLifecycleConfiguration",
	} {
		if !isAbsent(errors.New(msg)) {
			t.Errorf("isAbsent(%q) = false; a genuinely absent configuration would be reported as unread", msg)
		}
	}
	for _, msg := range []string{
		"/media?versioning: HTTP 403",
		"/media?policy: HTTP 429 rate limited",
		"context deadline exceeded",
	} {
		if isAbsent(errors.New(msg)) {
			t.Errorf("isAbsent(%q) = true; an unread facet would be recorded as absent", msg)
		}
	}
}

// A snapshot too old to declare a gap cannot be trusted to mean what it says.
func TestAStaleBucketSnapshotIsFlagged(t *testing.T) {
	for _, v := range []int{0, 1} {
		rep := Classify(Snapshot{SchemaVersion: v, Source: "s3", Buckets: []Bucket{{Name: "media"}}})
		var flagged bool
		for _, f := range rep.Findings {
			if f.Name == "snapshot schema_version" && f.Verdict == report.Manual {
				flagged = true
			}
		}
		if !flagged {
			t.Errorf("schema_version %d was not flagged: an unread facet is indistinguishable from an absent one", v)
		}
	}
	rep := Classify(Snapshot{SchemaVersion: CurrentSchemaVersion, Source: "s3", Buckets: []Bucket{{Name: "media"}}})
	for _, f := range rep.Findings {
		if f.Name == "snapshot schema_version" {
			t.Fatalf("a current snapshot was flagged as stale: %+v", f)
		}
	}
}

// Bucket names reach the generated provisioning and rclone commands, which an
// operator runs as shell.
func TestValidateRejectsBucketNamesThatReachAShell(t *testing.T) {
	for _, bad := range []string{"", "a", "UPPER", "has space", "semi;colon", "../etc", "trailing-", strings.Repeat("x", 64)} {
		s := Snapshot{SchemaVersion: CurrentSchemaVersion, Source: "s3", Buckets: []Bucket{{Name: bad}}}
		if err := s.Validate(); err == nil {
			t.Errorf("Validate accepted bucket name %q", bad)
		}
	}
	ok := Snapshot{SchemaVersion: CurrentSchemaVersion, Source: "s3", Buckets: []Bucket{
		{Name: "media"}, {Name: "my-bucket.eu"}, {Name: "a1b"},
	}}
	if err := ok.Validate(); err != nil {
		t.Errorf("Validate rejected ordinary bucket names: %v", err)
	}
}

func TestValidateRejectsControlCharacters(t *testing.T) {
	s := Snapshot{SchemaVersion: CurrentSchemaVersion, Source: "s3", Buckets: []Bucket{
		{Name: "media", PolicyJSON: "{\"Statement\":[]}\n\x00"},
	}}
	if err := s.Validate(); err == nil {
		t.Error("Validate accepted a control character in a policy that reaches a generated file")
	}
}

func TestCheckSchemaVersionRefusesWhatThisBuildCannotRead(t *testing.T) {
	if err := (Snapshot{SchemaVersion: CurrentSchemaVersion + 1}).CheckSchemaVersion(); err == nil {
		t.Error("a newer schema version was accepted")
	}
	for _, v := range []int{0, 1, CurrentSchemaVersion} {
		if err := (Snapshot{SchemaVersion: v}).CheckSchemaVersion(); err != nil {
			t.Errorf("schema_version %d rejected: %v", v, err)
		}
	}
}
