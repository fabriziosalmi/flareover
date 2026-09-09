// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package textguard

import (
	"strings"
	"testing"
)

// This package had no tests of its own. It is the single check both
// cloudflare.Snapshot.Validate and ir.Plan.Validate delegate to, and its stated
// value is completeness — the comment on FindControlStrings says the walk is
// reflective rather than field-by-field because "a hand-written list stops
// being complete the day somebody adds one". That completeness is a property of
// the walk over Go's kinds, and it was exercised only through whatever shapes a
// Snapshot and a Plan happen to contain today. A walk that silently skipped map
// values or a nested pointer would have kept passing every existing test while
// no longer protecting the sink it exists for.

type inner struct {
	Deep string
}

type walkable struct {
	Plain    string
	Ptr      *inner
	NilPtr   *inner
	Slice    []inner
	Map      map[string]string
	MapVal   map[string]inner
	Iface    any
	Unexp    string //nolint:unused // reached by the walk, not by name
	Array    [2]string
	NoString int
}

// Every kind the walk must descend into, each carrying the offending value in a
// different position.
func TestFindControlStringsReachesEveryKind(t *testing.T) {
	cases := map[string]walkable{
		"plain field":      {Plain: "a\x00b"},
		"through pointer":  {Ptr: &inner{Deep: "a\nb"}},
		"slice element":    {Slice: []inner{{Deep: "ok"}, {Deep: "a\rb"}}},
		"map value":        {Map: map[string]string{"k": "a\x1bb"}},
		"struct in a map":  {MapVal: map[string]inner{"k": {Deep: "a\tb"}}},
		"interface value":  {Iface: inner{Deep: "a\x07b"}},
		"array element":    {Array: [2]string{"ok", "a\x00b"}},
		"unexported field": {Unexp: "a\nb"},
	}
	for name, v := range cases {
		if got := FindControlStrings(v, "root"); len(got) == 0 {
			t.Errorf("%s: a control character was not reported; the walk does not reach there", name)
		}
	}
}

// A clean structure must not be reported, or the check is noise and gets
// disabled.
func TestFindControlStringsAcceptsOrdinaryText(t *testing.T) {
	v := walkable{
		Plain:  "example.com",
		Ptr:    &inner{Deep: "v=spf1 include:_spf.example.net ~all"},
		Slice:  []inner{{Deep: "/api/v1"}},
		Map:    map[string]string{"k": "Bearer-ish but fine"},
		MapVal: map[string]inner{"k": {Deep: "café — unicode is not a control character"}},
		Array:  [2]string{"a", "b"},
	}
	if got := FindControlStrings(v, "root"); len(got) != 0 {
		t.Errorf("clean input reported: %v", got)
	}
}

// The report has to name where the offending value is, or an operator cannot
// find it in a snapshot with hundreds of records.
func TestFindControlStringsNamesTheLocation(t *testing.T) {
	got := FindControlStrings(walkable{Slice: []inner{{Deep: "ok"}, {Deep: "bad\n"}}}, "plan")
	if len(got) != 1 {
		t.Fatalf("got %d problems, want 1: %v", len(got), got)
	}
	for _, want := range []string{"plan", "Slice", "1", "Deep"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("the path %q does not mention %q", got[0], want)
		}
	}
}

// MaxStringLen is the only thing between a pathological field in a snapshot and
// a generated configuration file. Nothing named it, so raising it, removing it,
// or flipping the comparison by one would all have passed silently.
func TestMaxStringLenIsEnforcedAtItsEdge(t *testing.T) {
	atLimit := walkable{Plain: strings.Repeat("x", MaxStringLen)}
	if got := FindControlStrings(atLimit, "root"); len(got) != 0 {
		t.Errorf("a string of exactly MaxStringLen (%d) was rejected: %v", MaxStringLen, got)
	}

	overLimit := walkable{Plain: strings.Repeat("x", MaxStringLen+1)}
	got := FindControlStrings(overLimit, "root")
	if len(got) != 1 {
		t.Fatalf("MaxStringLen+1 gave %d problems, want 1", len(got))
	}
	// The message must carry both numbers: "too long" alone does not tell an
	// operator whether they are over by one byte or by a megabyte.
	for _, want := range []string{"8193", "8192"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("the message %q does not carry %q", got[0], want)
		}
	}
}

func TestIsHostname(t *testing.T) {
	for _, ok := range []string{
		"example.com", "a.example.com", "EXAMPLE.com", "xn--80ak6aa92e.com",
		"a-b.example.co.uk", "localhost", "1.example.com",
		// Deliberately accepted, and documented as such: Cloudflare wildcard
		// records, the apex, a trailing dot, and the underscore labels every
		// real zone carries (_dmarc, _acme-challenge).
		"*.example.com", "example.com.", "@", "_dmarc.example.com",
	} {
		if !IsHostname(ok) {
			t.Errorf("IsHostname(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{
		"", ".", "..", ".example.com", "example..com", "-example.com",
		"example-.com", "exa mple.com", "example.com/path", "example.com:443",
		"exa\x00mple.com", strings.Repeat("a", 64) + ".com",
		strings.Repeat("a.", 200) + "com",
	} {
		if IsHostname(bad) {
			t.Errorf("IsHostname(%q) = true, want false", bad)
		}
	}
}
