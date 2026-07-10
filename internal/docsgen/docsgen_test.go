// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
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

// Canonical, generated docs pages inside the Starlight site.
const (
	genPath       = "../../website/src/content/docs/coverage-matrix.md"
	sovereigntyMD = "../../website/src/content/docs/sovereignty-tiers.md"
)

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
		load(t, "../../testdata/fixtures/strict-ssl.snapshot.json"),
	)
	syncCheck(t, genPath, got, "coverage-matrix.md", "the classifier")
}

// TestSovereigntyInSync keeps the sovereignty-tiers catalogue generated from the
// same provider.Registry the CLI uses: a hyperscaler can't be silently retiered.
func TestSovereigntyInSync(t *testing.T) {
	syncCheck(t, sovereigntyMD, Sovereignty(), "sovereignty-tiers.md", "provider.Registry")
}

// syncCheck writes the generated page when -update is set, otherwise fails if the
// committed page has drifted from what the code produces.
func syncCheck(t *testing.T, path, got, name, source string) {
	t.Helper()
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated docs (run `go test ./internal/docsgen -update`): %v", err)
	}
	if string(want) != got {
		t.Errorf("%s is out of sync with %s. Run:\n"+
			"  go test ./internal/docsgen -update\n"+
			"(The docs are generated from the code and must not drift: the 0%%FP guarantee applied to the docs themselves.)", name, source)
	}
}
