// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

// Package safeio is the single place this project writes a file to disk.
//
// Two properties, both of which a bare os.WriteFile lacks:
//
//   - Atomicity. os.WriteFile opens O_TRUNC, so an interruption mid-write
//     leaves a prefix of the new content where the old file was. For JSON that
//     fails to parse and the damage is loud; for a BIND zone file or a Caddyfile
//     it does not — a truncated zone is a shorter but structurally valid zone,
//     and validate.Zone will pass it. WriteFile here stages into a temp file in
//     the destination directory, fsyncs it, and renames it into place, so a
//     reader sees either the whole old file or the whole new one.
//
//   - Containment. Artifact paths are built by string concatenation from
//     snapshot-derived values (a zone name), and filepath.Join *cleans* "../"
//     rather than rejecting it, so a crafted zone name escapes the output
//     directory. SecureJoin refuses instead of cleaning.
package safeio

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WriteFile atomically writes data to path with the given mode: stage into a
// temp file beside the destination, fsync, rename. A mode of 0 means 0o644.
//
// The rename is atomic within a filesystem, which is why the temp file is
// created in filepath.Dir(path) rather than in the system temp directory.
func WriteFile(path string, data []byte, mode os.FileMode) (err error) {
	if mode == 0 {
		mode = 0o644
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("staging %s: %w", path, err)
	}
	tmpName := tmp.Name()
	// On any failure past this point the staged file must not survive.
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()

	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	// Chmod the staged file, not the destination: the mode must be in place
	// before the rename publishes it, or a secret-bearing artifact is briefly
	// world-readable. CreateTemp makes it 0600, so this only ever widens.
	if err = tmp.Chmod(mode); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	// Sync before rename: without it the rename can be durable while the
	// contents are not, which is the classic way to end up with an empty file
	// after a power loss.
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("syncing %s: %w", path, err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", path, err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("publishing %s: %w", path, err)
	}
	// Fsync the directory so the new name itself survives a crash. Best-effort:
	// some filesystems refuse to open a directory for sync, and the file
	// contents are already durable at this point.
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// SecureJoin joins rel onto root and refuses anything that would escape it.
//
// filepath.Join cleans "a/../../b" into "../b" and returns it happily, so it is
// the opposite of a containment check. This rejects an absolute rel, any ".."
// element, and (belt and braces) any result that does not stay under root.
func SecureJoin(root, rel string) (string, error) {
	if rel == "" {
		return "", fmt.Errorf("empty artifact path")
	}
	if filepath.IsAbs(rel) || strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, `\`) {
		return "", fmt.Errorf("artifact path %q is absolute", rel)
	}
	// Check the elements as written, before any cleaning can hide a "..".
	for _, el := range strings.FieldsFunc(rel, func(r rune) bool { return r == '/' || r == '\\' }) {
		if el == ".." {
			return "", fmt.Errorf("artifact path %q escapes the output directory", rel)
		}
	}
	if strings.ContainsRune(rel, 0) {
		return "", fmt.Errorf("artifact path %q contains a NUL byte", rel)
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolving output directory %s: %w", root, err)
	}
	joined := filepath.Join(absRoot, rel)
	if joined != absRoot && !strings.HasPrefix(joined, absRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("artifact path %q escapes the output directory", rel)
	}
	return joined, nil
}
