// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package classify

import (
	"strings"
	"testing"

	cf "github.com/fabriziosalmi/flareover/internal/cloudflare"
	"github.com/fabriziosalmi/flareover/internal/report"
)

// The 0% false-positive contract's boundary condition: an absence must be
// reported as "not read", never as "not present". A token without
// Firewall Services:Read yields a snapshot with no IP access rules, and without
// this the report would claim full coverage of a zone whose security controls
// were never seen.
func TestExtractionGapBecomesManual(t *testing.T) {
	s := cf.Snapshot{
		SchemaVersion: cf.CurrentSchemaVersion,
		Zone:          cf.Zone{Name: "example.com"},
		ExtractionGaps: []cf.Gap{
			{Surface: "ip access rules", Detail: "HTTP 403 (token missing scope?)"},
		},
	}
	rep := Classify(s)

	var found *report.Finding
	for i, f := range rep.Findings {
		if f.Kind == "extraction-gap" {
			found = &rep.Findings[i]
			break
		}
	}
	if found == nil {
		t.Fatal("an extraction gap produced no finding: the report would claim coverage it does not have")
	}
	if found.Verdict != report.Manual {
		t.Errorf("verdict = %s, want MANUAL: the tool cannot know what it did not read", found.Verdict)
	}
	if found.Name != "ip access rules" {
		t.Errorf("name = %q, want the surface", found.Name)
	}
	if !strings.Contains(found.Rationale, "NOT covered") {
		t.Errorf("rationale should say the surface is not covered, got: %q", found.Rationale)
	}
	if !strings.Contains(found.Rationale, "403") {
		t.Errorf("rationale should carry the cause, got: %q", found.Rationale)
	}
	// MANUAL findings carry no target: nothing was mapped onto anything.
	if found.Target != "" {
		t.Errorf("target = %q, want empty for MANUAL", found.Target)
	}
}

func TestExtractionGapsRaiseTheManualCount(t *testing.T) {
	clean := Classify(cf.Snapshot{SchemaVersion: cf.CurrentSchemaVersion, Zone: cf.Zone{Name: "example.com"}})
	gapped := Classify(cf.Snapshot{
		SchemaVersion: cf.CurrentSchemaVersion,
		Zone:          cf.Zone{Name: "example.com"},
		ExtractionGaps: []cf.Gap{
			{Surface: "ip access rules", Detail: "HTTP 403"},
			{Surface: "ua blocking rules", Detail: "HTTP 403"},
		},
	})
	before := clean.Counts()[report.Manual]
	after := gapped.Counts()[report.Manual]
	if after != before+2 {
		t.Errorf("MANUAL count went %d -> %d, want +2", before, after)
	}
	// The count is what cmdAssess/cmdPrepare/cmdExecute gate on, so a gapped
	// snapshot must not be able to exit 0.
	if after == 0 {
		t.Error("a snapshot with extraction gaps would exit 0 as a clean migration")
	}
}

func TestNoGapsMeansNoGapFindings(t *testing.T) {
	rep := Classify(cf.Snapshot{SchemaVersion: cf.CurrentSchemaVersion, Zone: cf.Zone{Name: "example.com"}})
	for _, f := range rep.Findings {
		if f.Kind == "extraction-gap" {
			t.Fatalf("a complete extraction produced a gap finding: %+v", f)
		}
	}
}

// A snapshot written before extraction gaps existed cannot declare one, so an
// unread surface and an absent surface are the same empty slice. The dangerous
// instance is Cloudflare Access: plan.accessGatedHosts reads an empty
// AccessApps as "no host needs an identity gate" and emits a plain
// reverse_proxy for every host, so an old file could publish an application
// that today requires a login — with the report claiming full coverage.
func TestAStaleSnapshotCannotClaimCoverageItCannotHave(t *testing.T) {
	for _, v := range []int{0, 1} {
		rep := Classify(cf.Snapshot{SchemaVersion: v, Zone: cf.Zone{Name: "example.com"}})
		var found *report.Finding
		for i, f := range rep.Findings {
			if f.Kind == "extraction-gap" {
				found = &rep.Findings[i]
				break
			}
		}
		if found == nil {
			t.Fatalf("schema_version %d produced no finding: the report would claim coverage on the strength of a file's age", v)
		}
		if found.Verdict != report.Manual {
			t.Errorf("schema_version %d: verdict = %s, want MANUAL", v, found.Verdict)
		}
		if !strings.Contains(found.Rationale, "Access") {
			t.Errorf("schema_version %d: rationale should name the control at risk, got: %q", v, found.Rationale)
		}
		if rep.Counts()[report.Manual] == 0 {
			t.Errorf("schema_version %d would exit 0 as a clean migration", v)
		}
	}
}

// The current shape declares what it read, so it must not be flagged as stale.
func TestACurrentSnapshotIsNotFlaggedAsStale(t *testing.T) {
	rep := Classify(cf.Snapshot{SchemaVersion: cf.CurrentSchemaVersion, Zone: cf.Zone{Name: "example.com"}})
	for _, f := range rep.Findings {
		if f.Name == "snapshot schema_version" {
			t.Fatalf("a current snapshot was flagged as stale: %+v", f)
		}
	}
}

// warn() is called for every non-fatal read failure, so one remedy text covered
// four different causes and named the first for all of them. An operator
// throttled halfway through an account-wide extraction got a list of MANUAL
// items each telling them to widen a token that was already wide enough.
func TestTheGapRemedyMatchesTheCause(t *testing.T) {
	cases := []struct {
		detail    string
		wantSays  string
		wantNever string
	}{
		{"rulesets: HTTP 429 rate limited after 4 attempts: wait for the limit to reset and re-run", "wait for the limit", "token that can read"},
		{"page rules: HTTP 503 from the API after 4 attempts (transient): re-run", "transiently", "token that can read"},
		{"R2 buckets + Access apps: skipped (set CLOUDFLARE_ACCOUNT_ID)", "CLOUDFLARE_ACCOUNT_ID", "token that can read"},
		{"ip access rules: HTTP 403 (token missing scope?)", "token that can read", "rate limited"},
	}
	for _, c := range cases {
		rep := Classify(cf.Snapshot{
			SchemaVersion:  cf.CurrentSchemaVersion,
			Zone:           cf.Zone{Name: "example.com"},
			ExtractionGaps: []cf.Gap{{Surface: "surface", Detail: c.detail}},
		})
		var got string
		for _, f := range rep.Findings {
			if f.Kind == "extraction-gap" {
				got = f.Rationale
			}
		}
		if !strings.Contains(got, c.wantSays) {
			t.Errorf("detail %q: rationale should say %q, got: %s", c.detail, c.wantSays, got)
		}
		if strings.Contains(got, c.wantNever) {
			t.Errorf("detail %q: rationale wrongly says %q", c.detail, c.wantNever)
		}
	}
}
