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

func artifact(arts []Artifact, path string) string {
	for _, a := range arts {
		if a.Path == path {
			return string(a.Content)
		}
	}
	return ""
}
