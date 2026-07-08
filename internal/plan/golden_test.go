package plan_test

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	cf "github.com/fabriziosalmi/flareover/internal/cloudflare"
	"github.com/fabriziosalmi/flareover/internal/plan"
	"github.com/fabriziosalmi/flareover/internal/stack"
)

var update = flag.Bool("update", false, "update golden files")

// TestGoldenConformance is the regression net: the full free-tier conformance
// zone (a sanitized capture of a real Cloudflare free-tier torture zone) must
// generate byte-identical artifacts. Any catalog or generator change that alters output
// fails here — run `go test ./internal/plan -run Golden -update` to review and
// accept an intended change.
func TestGoldenConformance(t *testing.T) {
	snap := readSnapshot(t, "../../testdata/fixtures/conformance.snapshot.json")
	decisions := readDecisions(t, "../../testdata/fixtures/conformance.decisions.json")

	p, err := plan.Build(snap, plan.Options{EdgeIP: "203.0.113.1", CA: "actalis", Decisions: decisions})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := stack.Profile("caddy")
	if err != nil {
		t.Fatal(err)
	}
	arts, err := profile.Generate(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(arts) == 0 {
		t.Fatal("no artifacts generated")
	}

	base := "../../testdata/golden/conformance"
	for _, a := range arts {
		golden := filepath.Join(base, a.Path)
		if *update {
			if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(golden, a.Content, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Errorf("missing golden for %s (run -update): %v", a.Path, err)
			continue
		}
		if string(want) != string(a.Content) {
			t.Errorf("golden mismatch for %s\n--- want ---\n%s\n--- got ---\n%s", a.Path, want, a.Content)
		}
	}
}

func readSnapshot(t *testing.T, path string) cf.Snapshot {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var s cf.Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func readDecisions(t *testing.T, path string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}
