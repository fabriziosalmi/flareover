// SPDX-License-Identifier: AGPL-3.0-only

package docsgen

import (
	"encoding/json"
	"flag"
	"os"
	"testing"

	cf "github.com/fabriziosalmi/flareover/internal/cloudflare"
)

var update = flag.Bool("update", false, "regenerate the coverage-matrix docs page from the classifier")

// genPath is the canonical, generated docs page inside the Starlight site.
const genPath = "../../website/src/content/docs/coverage-matrix.md"

func load(t *testing.T, p string) cf.Snapshot {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var s cf.Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestCoverageMatrixInSync is the moat: the published coverage matrix is
// generated from flareover's own classifier, and this test fails if the
// committed page drifts from what the code produces. Change classify → run
// `go test ./internal/docsgen -update` → the docs update with it, provably.
func TestCoverageMatrixInSync(t *testing.T) {
	got := Coverage(
		load(t, "../../testdata/fixtures/example.snapshot.json"),
		load(t, "../../testdata/fixtures/conformance.snapshot.json"),
	)
	if *update {
		if err := os.WriteFile(genPath, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", genPath)
		return
	}
	want, err := os.ReadFile(genPath)
	if err != nil {
		t.Fatalf("read generated docs (run `go test ./internal/docsgen -update`): %v", err)
	}
	if string(want) != got {
		t.Errorf("coverage-matrix.md is out of sync with the classifier — run:\n" +
			"  go test ./internal/docsgen -update\n" +
			"(The docs are generated from the code and must not drift — that is the 0%%FP guarantee applied to the docs themselves.)")
	}
}
