// SPDX-License-Identifier: AGPL-3.0-only

package objstore

import (
	"encoding/json"
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

func TestClassifyVerdicts(t *testing.T) {
	r := Classify(load(t))
	cases := []struct {
		kind, name string
		want       report.Verdict
	}{
		{"bucket", "public-assets", report.Auto},
		{"versioning", "public-assets", report.Auto},
		{"cors", "public-assets#0", report.Auto},
		{"lifecycle", "public-assets/expire-temp", report.Auto},
		{"public-access", "public-assets", report.Ask}, // never public silently
		{"bucket", "private-backups", report.Auto},
		{"policy", "private-backups", report.Manual},            // IAM policy not guessed
		{"lifecycle", "private-backups/glacier", report.Manual}, // tiering has no MinIO target
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
}

// TestPublicNotReproducedWithoutYes is the 0% FP guard for storage: a public
// bucket must not become public on MinIO unless explicitly answered yes.
func TestPublicNotReproducedWithoutYes(t *testing.T) {
	s := load(t)

	// No decision → provisioning must NOT set anonymous download.
	arts := Generate(s, GenOptions{})
	prov := artifact(arts, "minio/provision.sh")
	if strings.Contains(prov, "anonymous set download") {
		t.Error("public read reproduced without an explicit yes")
	}
	if !strings.Contains(prov, "stays private") {
		t.Error("declined public read should be noted, not silent")
	}

	// Explicit yes → provisioning sets anonymous download.
	arts = Generate(s, GenOptions{Decisions: map[string]string{"public-read:public-assets": "yes"}})
	prov = artifact(arts, "minio/provision.sh")
	if !strings.Contains(prov, "anonymous set download eu/public-assets") {
		t.Error("confirmed public read should be reproduced")
	}
}

func TestRcloneAndProvisionArtifacts(t *testing.T) {
	arts := Generate(load(t), GenOptions{MinIOAlias: "eu"})
	prov := artifact(arts, "minio/provision.sh")
	for _, want := range []string{"mc mb -p eu/public-assets", "mc version enable eu/public-assets", "mc ilm rule add --expire-days 30"} {
		if !strings.Contains(prov, want) {
			t.Errorf("provision.sh missing %q", want)
		}
	}
	rc := artifact(arts, "rclone/migrate.sh")
	if !strings.Contains(rc, "rclone sync --progress src:private-backups eu:private-backups") {
		t.Error("rclone plan missing a bucket sync")
	}
	if !strings.Contains(rc, "900GB") {
		t.Error("rclone plan should surface the data volume")
	}
}

// TestLifecycleZeroExpiryIsManual pins the audit fix: a lifecycle rule with no
// positive object-expiry (multipart-abort / noncurrent-version only) has no
// MinIO ILM equivalent, so classify must mark it MANUAL — it was a false-AUTO
// before — and Generate must emit no `mc ilm` line for it (classify ⟺ generate).
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
	prov := artifact(Generate(snap, GenOptions{}), "minio/provision.sh")
	if strings.Contains(prov, "--expire-days 0") {
		t.Error("Generate must not emit an mc ilm line for the zero-expiry rule")
	}
	if !strings.Contains(prov, "--expire-days 30") {
		t.Error("Generate must emit the positive-expiry rule")
	}
}

// TestScalewayDestination checks the managed-EU-S3 preset: right endpoint,
// region, credentials env, alias, and artifact folder.
func TestScalewayDestination(t *testing.T) {
	arts := Generate(load(t), GenOptions{Dest: "scaleway"})
	prov := artifact(arts, "scaleway-object-storage/provision.sh")
	if prov == "" {
		t.Fatal("no scaleway-object-storage/provision.sh artifact")
	}
	for _, want := range []string{
		"mc alias set scw https://s3.fr-par.scw.cloud \"$SCW_ACCESS_KEY\" \"$SCW_SECRET_KEY\"",
		"mc mb -p scw/public-assets",
		"mc version enable scw/public-assets",
		"Scaleway Object Storage (EU-owned, fr-par)",
	} {
		if !strings.Contains(prov, want) {
			t.Errorf("scaleway provision.sh missing %q", want)
		}
	}
	// It must NOT leak the MinIO defaults.
	if strings.Contains(prov, "MINIO_ACCESS_KEY") || strings.Contains(prov, "mc mb -p eu/") {
		t.Error("scaleway provision leaked MinIO alias/creds")
	}
	// rclone destination remote follows the alias.
	rc := artifact(arts, "rclone/migrate.sh")
	if !strings.Contains(rc, "rclone sync --progress src:public-assets scw:public-assets") {
		t.Error("rclone plan should target the scw: remote")
	}

	// Region override flows into the endpoint.
	nl := artifact(Generate(load(t), GenOptions{Dest: "scaleway", Region: "nl-ams"}), "scaleway-object-storage/provision.sh")
	if !strings.Contains(nl, "https://s3.nl-ams.scw.cloud") {
		t.Error("region override did not reach the endpoint")
	}
}

// TestScalewayPublicGuard: the 0%-FP public-read guard holds for Scaleway too.
func TestScalewayPublicGuard(t *testing.T) {
	prov := artifact(Generate(load(t), GenOptions{Dest: "scaleway"}), "scaleway-object-storage/provision.sh")
	if strings.Contains(prov, "anonymous set download") {
		t.Error("public read reproduced on Scaleway without an explicit yes")
	}
	prov = artifact(Generate(load(t), GenOptions{Dest: "scaleway", Decisions: map[string]string{"public-read:public-assets": "yes"}}), "scaleway-object-storage/provision.sh")
	if !strings.Contains(prov, "mc anonymous set download scw/public-assets") {
		t.Error("confirmed public read should be reproduced on Scaleway")
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
	if prov == "" {
		t.Fatal("no ovh-object-storage/provision.sh artifact")
	}
	for _, want := range []string{
		"mc alias set ovh https://s3.gra.io.cloud.ovh.net \"$OVH_S3_ACCESS_KEY\" \"$OVH_S3_SECRET_KEY\"",
		"mc mb -p ovh/public-assets",
		"OVHcloud Object Storage (EU-owned, gra)",
	} {
		if !strings.Contains(prov, want) {
			t.Errorf("ovh provision.sh missing %q", want)
		}
	}
	if strings.Contains(prov, "scw/") || strings.Contains(prov, "MINIO_ACCESS_KEY") {
		t.Error("ovh provision leaked another destination's alias/creds")
	}
	// Region override → endpoint.
	de := artifact(Generate(load(t), GenOptions{Dest: "ovh", Region: "de"}), "ovh-object-storage/provision.sh")
	if !strings.Contains(de, "https://s3.de.io.cloud.ovh.net") {
		t.Error("OVH region override did not reach the endpoint")
	}
	// The public-read guard holds here too.
	if strings.Contains(prov, "anonymous set download") {
		t.Error("public read reproduced on OVH without an explicit yes")
	}
}

// TestContaboDestination checks the Contabo managed-S3 preset (EU-owned,
// S3-compatible; region eu2 in the endpoint hostname, not an "s3." prefix).
func TestContaboDestination(t *testing.T) {
	prov := artifact(Generate(load(t), GenOptions{Dest: "contabo"}), "contabo-object-storage/provision.sh")
	if prov == "" {
		t.Fatal("no contabo-object-storage/provision.sh artifact")
	}
	for _, want := range []string{
		"mc alias set contabo https://eu2.contabostorage.com \"$CONTABO_S3_ACCESS_KEY\" \"$CONTABO_S3_SECRET_KEY\"",
		"mc mb -p contabo/public-assets",
		"Contabo Object Storage (EU-owned, eu2)",
	} {
		if !strings.Contains(prov, want) {
			t.Errorf("contabo provision.sh missing %q", want)
		}
	}
	if strings.Contains(prov, "scw/") || strings.Contains(prov, "ovh/") || strings.Contains(prov, "MINIO_ACCESS_KEY") {
		t.Error("contabo provision leaked another destination's alias/creds")
	}
	// The public-read guard holds here too.
	if strings.Contains(prov, "anonymous set download") {
		t.Error("public read reproduced on Contabo without an explicit yes")
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

// TestArubaDestination checks the Aruba preset: EU-owned (IT) tier label, Aruba
// env vars, and the operator-supplied endpoint carried through verbatim (Aruba's
// S3 host is account-specific, so it is never baked in / guessed).
func TestArubaDestination(t *testing.T) {
	ep := "https://sp-eu-it1.arubacloud.example"
	prov := artifact(Generate(load(t), GenOptions{Dest: "aruba", MinIOEndpoint: ep}), "aruba-object-storage/provision.sh")
	if prov == "" {
		t.Fatal("no aruba-object-storage/provision.sh artifact")
	}
	for _, want := range []string{
		"mc alias set aruba " + ep + " \"$ARUBA_S3_ACCESS_KEY\" \"$ARUBA_S3_SECRET_KEY\"",
		"mc mb -p aruba/public-assets",
		"Aruba Cloud Object Storage (EU-owned, IT",
	} {
		if !strings.Contains(prov, want) {
			t.Errorf("aruba provision.sh missing %q", want)
		}
	}
	if strings.Contains(prov, "scw/") || strings.Contains(prov, "ovh/") || strings.Contains(prov, "contabo/") || strings.Contains(prov, "MINIO_ACCESS_KEY") {
		t.Error("aruba provision leaked another destination's alias/creds")
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
