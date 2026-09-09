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
		Zone: cf.Zone{Name: "example.com"},
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
	clean := Classify(cf.Snapshot{Zone: cf.Zone{Name: "example.com"}})
	gapped := Classify(cf.Snapshot{
		Zone: cf.Zone{Name: "example.com"},
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
	rep := Classify(cf.Snapshot{Zone: cf.Zone{Name: "example.com"}})
	for _, f := range rep.Findings {
		if f.Kind == "extraction-gap" {
			t.Fatalf("a complete extraction produced a gap finding: %+v", f)
		}
	}
}
