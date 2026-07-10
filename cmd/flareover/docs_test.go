// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"testing"

	"github.com/fabriziosalmi/flareover/internal/docsgen"
)

// cliReferencePath is the hand-written (rich, with examples) CLI reference in the
// Starlight docs. It stays hand-written on purpose, but must not silently omit a
// command or flag the binary ships.
const cliReferencePath = "../../website/src/content/docs/cli-reference.md"

// TestCLIReferenceComplete is the moat for the CLI reference: every phase and
// flag in the binary's own `usage` text must appear in the published reference.
// Add a command or flag to the CLI and this fails until the docs cover it, so
// the reference can never fall behind the code.
func TestCLIReferenceComplete(t *testing.T) {
	md, err := os.ReadFile(cliReferencePath)
	if err != nil {
		t.Fatalf("read CLI reference: %v", err)
	}
	if gaps := docsgen.CLIRefGaps(usage, string(md)); len(gaps) > 0 {
		t.Errorf("cli-reference.md is missing %d item(s) from the binary's usage. Document them in %s:\n  %v",
			len(gaps), cliReferencePath, gaps)
	}
}
