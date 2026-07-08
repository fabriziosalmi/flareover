// SPDX-License-Identifier: AGPL-3.0-only

package parity

import (
	"strings"
	"testing"
)

func TestDiffHardVsSoft(t *testing.T) {
	base := response{status: 200, location: "", headers: map[string]string{"Content-Type": "text/html"}, bodyHash: "aaa"}

	// Identical → no divergence.
	if d := diff(base, base); len(d) != 0 {
		t.Errorf("identical responses diverge: %+v", d)
	}
	// Status differs → HARD.
	if d := diff(base, response{status: 403, headers: base.headers, bodyHash: "aaa"}); len(d) != 1 || d[0].Field != "status" || !d[0].Hard {
		t.Errorf("status change must be a HARD divergence: %+v", d)
	}
	// Redirect target differs → HARD.
	b := response{status: 301, location: "https://a/", headers: map[string]string{}}
	a := response{status: 301, location: "https://b/", headers: map[string]string{}}
	if d := diff(b, a); len(d) != 1 || d[0].Field != "redirect" || !d[0].Hard {
		t.Errorf("redirect change must be HARD: %+v", d)
	}
	// A significant header differs → SOFT.
	d := diff(base, response{status: 200, headers: map[string]string{"Content-Type": "application/json"}, bodyHash: "aaa"})
	if len(d) != 1 || d[0].Field != "header:Content-Type" || d[0].Hard {
		t.Errorf("header change must be SOFT: %+v", d)
	}
	// Body differs on a 200 → SOFT; but body is ignored on a redirect.
	if d := diff(base, response{status: 200, headers: base.headers, bodyHash: "bbb"}); len(d) != 1 || d[0].Field != "body" || d[0].Hard {
		t.Errorf("body change on 200 must be SOFT: %+v", d)
	}
	red := response{status: 301, location: "x", headers: map[string]string{}, bodyHash: "aaa"}
	if d := diff(red, response{status: 301, location: "x", headers: map[string]string{}, bodyHash: "zzz"}); len(d) != 0 {
		t.Errorf("body must be ignored on a redirect: %+v", d)
	}
}

func TestGateAndText(t *testing.T) {
	// One clean probe, one soft-only probe → gate PASSES.
	soft := Report{Before: "b", After: "a", Results: []Result{
		{Probe: Probe{Name: "home"}},
		{Probe: Probe{Name: "hdr"}, Divergences: []Divergence{{Field: "header:Vary", Hard: false}}},
	}}
	if !soft.Gate() {
		t.Error("soft-only divergences must not block cutover")
	}
	if txt := soft.Text(); !strings.Contains(txt, "GATE: PASS") {
		t.Errorf("expected PASS, got:\n%s", txt)
	}
	// Add a hard divergence → gate FAILS.
	hard := soft
	hard.Results = append(hard.Results, Result{Probe: Probe{Name: "waf"}, Divergences: []Divergence{{Field: "status", Hard: true}}})
	if hard.Gate() {
		t.Error("a hard divergence must block cutover")
	}
	if txt := hard.Text(); !strings.Contains(txt, "GATE: FAIL") {
		t.Errorf("expected FAIL, got:\n%s", txt)
	}
}

func TestConcretizeHost(t *testing.T) {
	if h := concretizeHost("*.example.com"); strings.HasPrefix(h, "*") {
		t.Errorf("wildcard host must be concretized, got %q", h)
	}
	if h := concretizeHost("www.example.com"); h != "www.example.com" {
		t.Errorf("a concrete host must pass through, got %q", h)
	}
}
