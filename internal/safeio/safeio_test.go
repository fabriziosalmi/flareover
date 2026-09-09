// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package safeio

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteFileIsAtomicAndLeavesNoStagingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "zone.txt")

	if err := WriteFile(path, []byte("first"), 0o644); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := WriteFile(path, []byte("second"), 0o644); err != nil {
		t.Fatalf("second write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "second" {
		t.Errorf("content = %q, want %q", got, "second")
	}

	// The staged temp file must not survive a successful write: a leftover
	// ".zone.txt.tmp-*" would be mistaken for an artifact by anything that
	// globs the output directory.
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != "zone.txt" {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want only zone.txt", names)
	}
}

func TestWriteFileAppliesModeBeforePublishing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "origin.wg0.conf")

	// 0600 matters here: this is the mode the mesh and cloud-init artifacts use
	// because they carry a private key. CreateTemp makes files 0600, so the
	// interesting direction is that a wider mode is applied too.
	if err := WriteFile(path, []byte("PrivateKey = x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %04o, want 0600", got)
	}

	wide := filepath.Join(dir, "Caddyfile")
	if err := WriteFile(wide, []byte("example.com {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	fi, err = os.Stat(wide)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o644 {
		t.Errorf("mode = %04o, want 0644", got)
	}
}

func TestWriteFileZeroModeDefaultsTo0644(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := WriteFile(path, []byte("x"), 0); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o644 {
		t.Errorf("mode = %04o, want 0644", got)
	}
}

func TestWriteFileFailureLeavesTheOldContentIntact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "zone.txt")
	if err := WriteFile(path, []byte("good"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A destination whose parent is not a directory: staging fails, and the
	// point is that the previously written file is untouched.
	bad := filepath.Join(path, "nested")
	if err := WriteFile(bad, []byte("bad"), 0o644); err == nil {
		t.Fatal("expected an error writing under a non-directory")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "good" {
		t.Errorf("content = %q, want the original %q", got, "good")
	}
}

func TestSecureJoinAcceptsOrdinaryArtifactPaths(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{
		"caddy/Caddyfile",
		"powerdns/example.com.zone",
		"mesh/origin.wg0.conf",
		"MIGRATION.md",
	} {
		got, err := SecureJoin(root, rel)
		if err != nil {
			t.Errorf("SecureJoin(%q) = error %v, want it accepted", rel, err)
			continue
		}
		if !strings.HasPrefix(got, root) {
			t.Errorf("SecureJoin(%q) = %q, outside root %q", rel, got, root)
		}
	}
}

func TestSecureJoinRefusesEscapes(t *testing.T) {
	root := t.TempDir()
	// The middle case is the one filepath.Join alone gets wrong: it cleans the
	// "../" away and returns a path outside root without complaint.
	for _, rel := range []string{
		"../etc/cron.d/evil",
		"powerdns/../../../../etc/cron.d/evil.zone",
		"/etc/passwd",
		"..",
		"",
	} {
		if got, err := SecureJoin(root, rel); err == nil {
			t.Errorf("SecureJoin(%q) = %q with no error, want refusal", rel, got)
		}
	}
}
