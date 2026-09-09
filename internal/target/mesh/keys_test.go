// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package mesh

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fabriziosalmi/flareover/internal/target"
)

func writeArts(t *testing.T, dir string, arts []target.Artifact) {
	t.Helper()
	for _, a := range arts {
		dst := filepath.Join(dir, a.Path)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(a.Mode)
		if mode == 0 {
			mode = 0o644
		}
		if err := os.WriteFile(dst, a.Content, mode); err != nil {
			t.Fatal(err)
		}
	}
}

func cfg(edges ...Edge) Config { return Config{Edges: edges} }

// The defect this pins: every `prepare` minted fresh keys, and the artifact
// write replaced the previous config — so an ordinary re-run invalidated a
// deployed tunnel and destroyed the only copy of the keys that worked.
func TestRegeneratingWithLoadedKeysIsByteIdentical(t *testing.T) {
	dir := t.TempDir()
	c := cfg(Edge{Name: "hetzner", Endpoint: "5.9.1.1:51820"})

	first, err := GenerateWireGuard(c)
	if err != nil {
		t.Fatal(err)
	}
	writeArts(t, dir, first)

	keys, err := LoadKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 { // origin + one edge
		t.Fatalf("LoadKeys found %d keys, want 2 (origin + edge)", len(keys))
	}

	c.Keys = keys
	second, err := GenerateWireGuard(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != len(second) {
		t.Fatalf("artifact count changed: %d -> %d", len(first), len(second))
	}
	for i := range first {
		if first[i].Path != second[i].Path {
			t.Fatalf("artifact %d path changed: %q -> %q", i, first[i].Path, second[i].Path)
		}
		if string(first[i].Content) != string(second[i].Content) {
			t.Errorf("%s is not byte-identical on re-run; the determinism claim still fails", first[i].Path)
		}
	}
}

// Without the loaded keys, regeneration must still produce different material —
// otherwise the keys would be deterministic, which would be far worse.
func TestFirstRunGeneratesFreshKeys(t *testing.T) {
	c := cfg(Edge{Name: "edge", Endpoint: "5.9.1.1:51820"})
	a, err := GenerateWireGuard(c)
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateWireGuard(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(a[0].Content) == string(b[0].Content) {
		t.Fatal("two independent first runs produced identical keys: the keys are predictable")
	}
}

func TestLoadKeysOnAnEmptyDirectoryIsNotAnError(t *testing.T) {
	keys, err := LoadKeys(t.TempDir())
	if err != nil {
		t.Fatalf("a first run must not fail for lack of previous keys: %v", err)
	}
	if keys != nil {
		t.Errorf("keys = %v, want nil", keys)
	}
}

func TestLoadedKeyIsActuallyUsedForItsPeer(t *testing.T) {
	dir := t.TempDir()
	c := cfg(Edge{Name: "hetzner", Endpoint: "5.9.1.1:51820"})
	first, err := GenerateWireGuard(c)
	if err != nil {
		t.Fatal(err)
	}
	writeArts(t, dir, first)
	keys, err := LoadKeys(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Add a second edge: the existing peer keeps its key, the new one gets a
	// fresh key rather than the whole mesh being re-keyed.
	c2 := cfg(
		Edge{Name: "hetzner", Endpoint: "5.9.1.1:51820"},
		Edge{Name: "scaleway", Endpoint: "51.1.1.1:51820"},
	)
	c2.Keys = keys
	second, err := GenerateWireGuard(c2)
	if err != nil {
		t.Fatal(err)
	}

	var oldHetzner, newHetzner string
	for _, a := range first {
		if a.Path == "mesh/hetzner.wg0.conf" {
			oldHetzner = privKeyOf(string(a.Content))
		}
	}
	for _, a := range second {
		if a.Path == "mesh/hetzner.wg0.conf" {
			newHetzner = privKeyOf(string(a.Content))
		}
	}
	if oldHetzner == "" || oldHetzner != newHetzner {
		t.Errorf("the existing edge was re-keyed when a second edge was added (%q -> %q)", oldHetzner, newHetzner)
	}
}

func TestAMalformedStoredKeyIsAnErrorNotASilentRegeneration(t *testing.T) {
	c := cfg(Edge{Name: "edge", Endpoint: "5.9.1.1:51820"})
	c.Keys = map[string]string{"edge": "not-base64!!"}
	if _, err := GenerateWireGuard(c); err == nil {
		t.Fatal("a corrupt stored key was silently replaced with a new one")
	}

	c.Keys = map[string]string{"edge": "c2hvcnQ="} // valid base64, wrong length
	if _, err := GenerateWireGuard(c); err == nil {
		t.Fatal("a non-X25519 stored key was silently replaced with a new one")
	}
}

func privKeyOf(conf string) string {
	for _, line := range strings.Split(conf, "\n") {
		if k, ok := strings.CutPrefix(strings.TrimSpace(line), "PrivateKey = "); ok {
			return k
		}
	}
	return ""
}
