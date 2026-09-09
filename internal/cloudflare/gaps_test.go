// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package cloudflare

import (
	"encoding/json"
	"strings"
	"testing"
)

// A warning that lives only on the Client dies when the snapshot is written to
// a file, and every later phase then reads "this zone has no IP access rules"
// where the truth was "this token could not read them". These tests pin the
// structural half that survives serialization.
func TestWarnRecordsAStructuredGapAlongsideTheMessage(t *testing.T) {
	c := &Client{}
	c.warn("ip access rules: %v", "HTTP 403 (token missing scope?)")

	if len(c.Warnings) != 1 {
		t.Fatalf("Warnings = %d entries, want 1", len(c.Warnings))
	}
	if len(c.Gaps) != 1 {
		t.Fatalf("Gaps = %d entries, want 1", len(c.Gaps))
	}
	if c.Gaps[0].Surface != "ip access rules" {
		t.Errorf("Surface = %q, want %q", c.Gaps[0].Surface, "ip access rules")
	}
	if !strings.Contains(c.Gaps[0].Detail, "403") {
		t.Errorf("Detail = %q, should carry the cause", c.Gaps[0].Detail)
	}
}

func TestWarnWithoutADetailIsAllSurface(t *testing.T) {
	c := &Client{}
	c.warn("R2 buckets + Access apps: skipped (set CLOUDFLARE_ACCOUNT_ID)")
	if got := c.Gaps[0].Surface; got != "R2 buckets + Access apps" {
		t.Errorf("Surface = %q", got)
	}
}

// An API error can carry a multi-line body of arbitrary size, and it ends up in
// the snapshot and then in a rendered report row. If it were carried verbatim
// the snapshot would fail its own validation.
func TestWarnCollapsesAndBoundsTheDetail(t *testing.T) {
	c := &Client{}
	c.warn("rulesets: %v", "API error:\n{\n  \"errors\": [\n    "+strings.Repeat("x", 2000)+"\n  ]\n}")

	g := c.Gaps[0]
	if strings.ContainsAny(g.Detail, "\n\r\t") {
		t.Error("detail still carries whitespace control characters")
	}
	if len(g.Detail) > 520 {
		t.Errorf("detail is %d bytes, should be bounded", len(g.Detail))
	}

	// The decisive property: a snapshot carrying this gap still validates.
	s := Snapshot{SchemaVersion: CurrentSchemaVersion, Zone: Zone{Name: "example.com"}, ExtractionGaps: c.Gaps}
	if err := s.Validate(); err != nil {
		t.Errorf("a snapshot carrying a recorded gap failed validation: %v", err)
	}
}

func TestExtractionGapsSurviveTheSnapshotRoundTrip(t *testing.T) {
	c := &Client{}
	c.warn("ip access rules: %v", "HTTP 403")
	c.warn("ua blocking rules: %v", "HTTP 403")

	s := Snapshot{SchemaVersion: CurrentSchemaVersion, Zone: Zone{Name: "example.com"}, ExtractionGaps: c.Gaps}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "extraction_gaps") {
		t.Fatal("gaps are not serialized: they would die with the process")
	}

	// Read it back the way loadSnapshot does, strictly.
	var back Snapshot
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&back); err != nil {
		t.Fatalf("strict decode of our own output failed: %v", err)
	}
	if len(back.ExtractionGaps) != 2 {
		t.Fatalf("read back %d gaps, want 2", len(back.ExtractionGaps))
	}
	if back.ExtractionGaps[0].Surface != "ip access rules" {
		t.Errorf("Surface = %q after round trip", back.ExtractionGaps[0].Surface)
	}
}

// A snapshot written before this field existed must still read.
func TestSnapshotWithoutGapsStillDecodes(t *testing.T) {
	const old = `{"schema_version":1,"zone":{"id":"z","name":"example.com"},"settings":{}}`
	var s Snapshot
	dec := json.NewDecoder(strings.NewReader(old))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		t.Fatalf("a v1 snapshot no longer decodes: %v", err)
	}
	if err := s.CheckSchemaVersion(); err != nil {
		t.Fatalf("a v1 snapshot was refused: %v", err)
	}
	if len(s.ExtractionGaps) != 0 {
		t.Error("expected no gaps")
	}
}
