// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	cf "github.com/fabriziosalmi/flareover/internal/cloudflare"
)

// The audit found that no test anywhere invoked any cmd* function, so 39 flags,
// six exit codes and the two --dns dispatches were verified by nothing. These
// tests drive the verbs directly. They deliberately exercise only paths that
// touch no network and no credentials: argument parsing, the documented exit
// codes, and the vocabulary the two DNS-taking verbs must share.

func fixture(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join("..", "..", "testdata", "fixtures", name)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return p
}

// silence sends the verbs' stdout/stderr to a temp file for the duration of a
// test: these functions write directly to os.Stdout, and a passing run should
// not bury the test output.
func silence(t *testing.T) {
	t.Helper()
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = devnull, devnull
	t.Cleanup(func() {
		os.Stdout, os.Stderr = oldOut, oldErr
		devnull.Close()
	})
}

// --- exit codes ------------------------------------------------------------

// cli-reference.md presents these as a CI gate, so they are a contract.
func TestAssessExitCodesMatchTheDocumentedContract(t *testing.T) {
	silence(t)
	// The example fixture carries MANUAL items (workers, snippets, email
	// routing), which outrank ASK.
	if got := cmdAssess([]string{fixture(t, "example.snapshot.json")}); got != exitManual {
		t.Errorf("assess on a snapshot with MANUAL items = %d, want %d", got, exitManual)
	}
}

func TestAssessRejectsUnknownFlagsAndMissingArguments(t *testing.T) {
	silence(t)
	if got := cmdAssess([]string{"--nope", fixture(t, "example.snapshot.json")}); got != exitUsage {
		t.Errorf("unknown flag = %d, want %d", got, exitUsage)
	}
	if got := cmdAssess(nil); got != exitUsage {
		t.Errorf("no snapshot argument = %d, want %d", got, exitUsage)
	}
}

func TestAssessOnAMissingFileIsARuntimeErrorNotAUsageError(t *testing.T) {
	silence(t)
	if got := cmdAssess([]string{filepath.Join(t.TempDir(), "absent.json")}); got != exitRuntime {
		t.Errorf("missing file = %d, want %d", got, exitRuntime)
	}
}

// prepare now gates on verdicts like assess and storage. The artifacts must
// still be written: they are the AUTO plus answered-ASK surface and correct.
func TestPrepareExitsOnManualButStillWritesArtifacts(t *testing.T) {
	silence(t)
	out := t.TempDir()
	got := cmdPrepare([]string{
		fixture(t, "example.snapshot.json"),
		"--decisions", fixture(t, "example.decisions.json"),
		"--edge-ip", "5.9.1.1", "--out", out,
	})
	if got != exitManual {
		t.Errorf("prepare = %d, want %d", got, exitManual)
	}
	for _, want := range []string{"caddy/Caddyfile", "MIGRATION.md"} {
		if _, err := os.Stat(filepath.Join(out, want)); err != nil {
			t.Errorf("%s was not written: %v", want, err)
		}
	}
}

// --- the two verbs must share one --dns vocabulary -------------------------

// The defect: prepare accepted "bunny" and provision rejected it as unknown,
// mid-migration, with artifacts already on disk. Both now resolve through one
// registry, so no value can be valid for one verb and unknown to the other.
func TestPrepareAndProvisionAgreeOnEveryDNSValue(t *testing.T) {
	silence(t)
	snap := fixture(t, "example.snapshot.json")

	for _, dns := range []string{"powerdns", "bunny", "scaleway", "ovh", "gandi",
		"leaseweb", "hetzner", "route53", "clouddns", "azure"} {
		// prepare: stdout preview, no --out, so nothing is written.
		p := cmdPrepare([]string{snap, "--dns", dns})
		if p == exitUsage {
			t.Errorf("prepare --dns %s was rejected as a usage error", dns)
		}

		// provision: it must not reject the value as *unknown*. It may still
		// exit 2 for a missing credential or because the target is
		// generate-only, which is a different, informative refusal.
		v := cmdProvision([]string{"--snapshot", snap, "--dns", dns})
		if v == exitOK {
			t.Errorf("provision --dns %s unexpectedly succeeded with no credentials", dns)
		}
	}
}

func TestBothVerbsRejectTheSameUnknownDNSValue(t *testing.T) {
	silence(t)
	snap := fixture(t, "example.snapshot.json")
	if got := cmdPrepare([]string{snap, "--dns", "nonsense"}); got != exitUsage {
		t.Errorf("prepare --dns nonsense = %d, want %d", got, exitUsage)
	}
	if got := cmdProvision([]string{"--snapshot", snap, "--dns", "nonsense"}); got != exitUsage {
		t.Errorf("provision --dns nonsense = %d, want %d", got, exitUsage)
	}
}

// --- credentials are never accepted on argv --------------------------------

func TestSecretBearingFlagsAreRefused(t *testing.T) {
	silence(t)
	for _, flag := range []string{"--pdns-key", "--certmate-token"} {
		if got := cmdProvision([]string{"--snapshot", fixture(t, "example.snapshot.json"), flag, "s3cret"}); got != exitUsage {
			t.Errorf("provision %s = %d, want %d (a secret must never be accepted on argv)", flag, got, exitUsage)
		}
		if got := cmdDoctor([]string{flag, "s3cret"}); got != exitUsage {
			t.Errorf("doctor %s = %d, want %d", flag, got, exitUsage)
		}
	}
}

// --- guard flag parsing ----------------------------------------------------

func TestGuardRequiresAURL(t *testing.T) {
	silence(t)
	if got := cmdGuard(nil); got != exitUsage {
		t.Errorf("guard with no --url = %d, want %d", got, exitUsage)
	}
}

// A malformed numeric flag used to be swallowed by fmt.Sscanf, leaving the
// default silently in place — so a typo in --expect-status could arm an
// automatic rollback against a healthy site.
func TestGuardRejectsMalformedNumericFlags(t *testing.T) {
	silence(t)
	for _, args := range [][]string{
		{"--url", "https://example.com", "--expect-status", "3O1"},
		{"--url", "https://example.com", "--fails", "abc"},
		{"--url", "https://example.com", "--interval", "soon"},
	} {
		if got := cmdGuard(args); got != exitUsage {
			t.Errorf("guard %v = %d, want %d", args, got, exitUsage)
		}
	}
}

// --- shared helpers --------------------------------------------------------

func TestSplitCSVTrimsAndDropsEmpties(t *testing.T) {
	got := splitCSV(" ns1.example.com , ,ns2.example.com,")
	want := []string{"ns1.example.com", "ns2.example.com"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("splitCSV = %v, want %v", got, want)
	}
	if len(splitCSV("")) != 0 {
		t.Error("splitCSV(\"\") should be empty")
	}
}

// --- extraction is not silently partial ------------------------------------

// A partial capture used to exit 0, so `flareover extract … && deploy` carried
// on against a snapshot that might be missing the WAF rules or the Access apps
// — the warnings went to stderr, which a pipeline routinely discards.
func TestExtractExitsManualWhenSurfacesWereUnreadable(t *testing.T) {
	if got := extractExit(cf.Snapshot{Zone: cf.Zone{Name: "example.com"}}); got != exitOK {
		t.Errorf("a complete extraction = %d, want %d", got, exitOK)
	}
	partial := cf.Snapshot{
		Zone:           cf.Zone{Name: "example.com"},
		ExtractionGaps: []cf.Gap{{Surface: "ip access rules", Detail: "HTTP 403"}},
	}
	if got := extractExit(partial); got != exitManual {
		t.Errorf("a partial extraction = %d, want %d: a gap is a MANUAL item", got, exitManual)
	}
}

// --- flag values that used to be accepted and then quietly ignored ----------

// opts.edge() returns --edge-ip verbatim and buildDNS writes it as the content
// of every de-proxied A record, while ir.Plan.Validate checks a record's Name
// and not its Content. So a typo produced a zone file the operator was invited
// to review and then apply, failing at resolution time rather than at parse
// time.
func TestEdgeIPMustBeAnIPv4Address(t *testing.T) {
	for _, bad := range []string{"203.0.113", "not-an-ip", "203.0.113.10:443", "2001:db8::1"} {
		if err := checkEdgeIP("prepare", bad); err == nil {
			t.Errorf("--edge-ip %q was accepted; it would become the content of every A record", bad)
		}
	}
	for _, ok := range []string{"", "203.0.113.10", "198.51.100.7"} {
		if err := checkEdgeIP("prepare", ok); err != nil {
			t.Errorf("--edge-ip %q rejected: %v", ok, err)
		}
	}
}

// `--vps 12,50` is what a European operator types. It used to parse as 12
// through a Sscanf whose error was discarded; `--vps twelve` left the default 0
// and the cost report then compared against a stack that appeared free.
func TestCostRejectsAPriceItCannotParse(t *testing.T) {
	silence(t)
	snap := fixture(t, "example.snapshot.json")
	for _, bad := range []string{"12,50", "twelve", "€12", "-5"} {
		if got := cmdCost([]string{snap, "--vps", bad}); got != exitUsage {
			t.Errorf("cost --vps %q = %d, want %d", bad, got, exitUsage)
		}
	}
	if got := cmdCost([]string{snap, "--vps", "12.50"}); got == exitUsage {
		t.Error("cost --vps 12.50 was rejected")
	}
}

// --- execute: the verb that authorises a cutover ---------------------------
//
// Nothing invoked cmdExecute. It is the one verb that decides whether a
// migration may proceed to the DNS flip, and its refusals are the asymmetric
// kind: a gate that stops working does not fail loudly, it lets a cutover
// through that should have been blocked. These drive the decision points that
// need no network.

func TestExecuteRefusesWhenMANUALItemsAreOutstanding(t *testing.T) {
	silence(t)
	snap := fixture(t, "example.snapshot.json")
	got := cmdExecute([]string{"--snapshot", snap, "--after-addr", "127.0.0.1:1"})
	if got != exitManual {
		t.Fatalf("execute with MANUAL items = %d, want %d: it must not authorize a cutover "+
			"while a control the generated stack does not reproduce is outstanding", got, exitManual)
	}
}

// --accept-manual is the operator overriding that refusal explicitly. It must
// get past the MANUAL gate — and then fail for a different reason (there is no
// staged edge at 127.0.0.1:1), which is what distinguishes "the gate let it
// through" from "the gate never ran".
func TestExecuteAcceptManualGetsPastTheManualGate(t *testing.T) {
	silence(t)
	snap := fixture(t, "example.snapshot.json")
	got := cmdExecute([]string{"--snapshot", snap, "--after-addr", "127.0.0.1:1", "--accept-manual"})
	if got == exitManual {
		t.Error("--accept-manual did not override the MANUAL gate")
	}
}

func TestExecuteRejectsUnknownFlagsAndMissingArguments(t *testing.T) {
	silence(t)
	snap := fixture(t, "example.snapshot.json")
	for _, args := range [][]string{
		{},                                   // no --snapshot, no --after-addr
		{"--snapshot", snap},                 // no --after-addr
		{"--after-addr", "127.0.0.1:1"},      // no --snapshot
		{"--snapshot"},                       // flag without a value
		{"--snapshot", snap, "--nonesuch"},   // unknown flag
		{"--snapshot", snap, "--after-addr"}, // trailing flag without a value
	} {
		if got := cmdExecute(args); got != exitUsage {
			t.Errorf("execute %v = %d, want %d", args, got, exitUsage)
		}
	}
}

func TestExecuteOnAMissingSnapshotIsARuntimeErrorNotAUsageError(t *testing.T) {
	silence(t)
	got := cmdExecute([]string{"--snapshot", "/nonexistent/zone.json", "--after-addr", "127.0.0.1:1"})
	if got != exitRuntime {
		t.Errorf("execute on a missing snapshot = %d, want %d", got, exitRuntime)
	}
}
