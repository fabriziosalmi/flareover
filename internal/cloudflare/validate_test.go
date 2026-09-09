// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package cloudflare

import (
	"strings"
	"testing"
)

// validSnapshot is the shape a real extraction produces: it must always pass,
// or the boundary check is a false-failure machine rather than a guard.
func validSnapshot() Snapshot {
	return Snapshot{
		SchemaVersion: CurrentSchemaVersion,
		Zone:          Zone{ID: "z1", Name: "example.com"},
		Settings:      ZoneSettings{SSL: "strict"},
		DNSRecords: []DNSRecord{
			{Type: "A", Name: "example.com", Content: "192.0.2.1", TTL: 300, Proxied: true},
			{Type: "AAAA", Name: "www.example.com", Content: "2001:db8::1", TTL: 300},
			{Type: "CNAME", Name: "alias.example.com", Content: "www.example.com.", TTL: 300},
			{Type: "TXT", Name: "_dmarc.example.com", Content: "v=DMARC1; p=none;", TTL: 300},
			{Type: "MX", Name: "example.com", Content: "mail.example.com", TTL: 300},
			{Type: "A", Name: "*.example.com", Content: "192.0.2.9", TTL: 300},
		},
	}
}

func TestValidateAcceptsARealisticSnapshot(t *testing.T) {
	if err := validSnapshot().Validate(); err != nil {
		t.Fatalf("a valid snapshot was rejected: %v", err)
	}
}

// The injection this exists to stop: a newline in a value that is interpolated
// into a generated config with a bare %s.
func TestValidateRejectsControlCharactersAnywhere(t *testing.T) {
	cases := map[string]func(*Snapshot){
		"dns record content": func(s *Snapshot) {
			s.DNSRecords[0].Content = "192.0.2.1\nwww\t300\tIN\tA\t198.51.100.66"
		},
		"page rule target": func(s *Snapshot) {
			s.PageRules = []PageRule{{Target: "example.com/x\n\tfile_server browse root /", Status: "active"}}
		},
		"ip access rule value": func(s *Snapshot) {
			s.IPAccessRules = []IPAccessRule{{Mode: "block", Target: "ip", Value: "1.2.3.4\rX"}}
		},
		"zone name": func(s *Snapshot) { s.Zone.Name = "example.com\n" },
	}
	for name, mutate := range cases {
		s := validSnapshot()
		mutate(&s)
		err := s.Validate()
		if err == nil {
			t.Errorf("%s: a control character was accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), "control character") {
			t.Errorf("%s: error %q does not name the problem", name, err)
		}
	}
}

// The traversal this exists to stop: Zone.Name is concatenated into artifact
// paths ("powerdns/" + name + ".zone").
func TestValidateRejectsATraversingZoneName(t *testing.T) {
	for _, bad := range []string{
		"../../../../etc/cron.d/evil",
		"/etc/passwd",
		"example.com/../..",
		"exa mple.com",
	} {
		s := validSnapshot()
		s.Zone.Name = bad
		if err := s.Validate(); err == nil {
			t.Errorf("zone name %q was accepted", bad)
		}
	}
}

func TestValidateRejectsAddressRecordsThatAreNotAddresses(t *testing.T) {
	s := validSnapshot()
	s.DNSRecords[0].Content = "not-an-ip"
	if err := s.Validate(); err == nil {
		t.Error("an A record with non-address content was accepted")
	}

	// An IPv6 literal in an A record is wrong in the direction that matters:
	// it would be written into the zone file as a syntactically fine but
	// unusable record.
	s = validSnapshot()
	s.DNSRecords[0].Content = "2001:db8::1"
	if err := s.Validate(); err == nil {
		t.Error("an A record holding an IPv6 address was accepted")
	}
}

func TestValidateReportsEveryProblemItFinds(t *testing.T) {
	s := validSnapshot()
	s.Zone.Name = "bad name"
	s.DNSRecords[0].Content = "not-an-ip"
	err := s.Validate()
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "zone.name") || !strings.Contains(err.Error(), "dns_records[0]") {
		t.Errorf("error should name both problems, got: %v", err)
	}
}

func TestCheckSchemaVersionRefusesWhatThisBuildCannotRead(t *testing.T) {
	// 0 is an old hand-authored fixture, 1 the original shape, 2 the current.
	for _, v := range []int{0, 1, CurrentSchemaVersion} {
		s := Snapshot{SchemaVersion: v}
		if err := s.CheckSchemaVersion(); err != nil {
			t.Errorf("schema_version %d was refused: %v", v, err)
		}
	}
	s := Snapshot{SchemaVersion: CurrentSchemaVersion + 1}
	err := s.CheckSchemaVersion()
	if err == nil {
		t.Fatal("a future schema_version was accepted; the field would be decoration again")
	}
	if !strings.Contains(err.Error(), "flareover extract") {
		t.Errorf("error should tell the operator what to do, got: %v", err)
	}
}
