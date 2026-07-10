// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

// Package report holds the verdict vocabulary and the honest coverage report
// that the Assessment phase produces. A Finding is the atomic unit: one
// Cloudflare element, one verdict, one rationale. The report is the contract
// with the user: behavior-changing config is only ever generated for AUTO and
// answered-ASK findings; MANUAL findings are surfaced, never guessed.
package report

import (
	"fmt"
	"sort"
	"strings"
)

// Verdict is the deterministic classification of a single Cloudflare element.
type Verdict string

const (
	// Auto: a provably-equivalent target mapping exists; config will be emitted.
	Auto Verdict = "AUTO"
	// Ask: a faithful mapping exists but with a bounded ambiguity; one yes/no
	// resolves it. Treated as Auto once answered.
	Ask Verdict = "ASK"
	// Manual: no faithful deterministic mapping; documented, never guessed.
	Manual Verdict = "MANUAL"
)

// Rank orders verdicts by how much attention they demand (Manual first).
func (v Verdict) Rank() int {
	switch v {
	case Manual:
		return 0
	case Ask:
		return 1
	case Auto:
		return 2
	default:
		return 3
	}
}

// Finding is one classified Cloudflare element.
type Finding struct {
	// Kind is the Cloudflare feature family, e.g. "dns", "tls", "redirect",
	// "transform", "waf-custom", "waf-managed", "ratelimit", "worker".
	Kind string `json:"kind"`
	// Name identifies the specific element (hostname, rule description, ...).
	Name string `json:"name"`
	// Verdict is the classification.
	Verdict Verdict `json:"verdict"`
	// Target names the EU-stack tool this maps onto ("caddy", "powerdns",
	// "certmate", "caddy-waf", ...). Empty for MANUAL.
	Target string `json:"target,omitempty"`
	// Rationale explains the mapping (or why it can't be made faithfully). This
	// is the equivalence note that makes the 0% FP claim auditable.
	Rationale string `json:"rationale"`
	// Question, present only for ASK findings, is the single yes/no we need.
	Question *Question `json:"question,omitempty"`
}

// Question is a bounded, enumerable ambiguity surfaced to the user. The default
// is what a re-run assumes if left unanswered in non-interactive mode; it must
// be the conservative, no-surprise choice.
type Question struct {
	// ID is a stable key used to record the answer in decisions.lock.
	ID string `json:"id"`
	// Prompt is shown to the user.
	Prompt string `json:"prompt"`
	// Options are the allowed answers (typically "yes"/"no").
	Options []string `json:"options"`
	// Default is the conservative choice assumed absent an explicit answer.
	Default string `json:"default"`
}

// Report is the full set of findings for a zone.
type Report struct {
	Zone     string    `json:"zone"`
	Findings []Finding `json:"findings"`
}

// Counts returns the number of findings per verdict.
func (r Report) Counts() map[Verdict]int {
	c := map[Verdict]int{Auto: 0, Ask: 0, Manual: 0}
	for _, f := range r.Findings {
		c[f.Verdict]++
	}
	return c
}

// Sorted returns findings ordered Manual → Ask → Auto, then by kind and name,
// so the things needing attention are always on top.
func (r Report) Sorted() []Finding {
	out := make([]Finding, len(r.Findings))
	copy(out, r.Findings)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Verdict.Rank() != b.Verdict.Rank() {
			return a.Verdict.Rank() < b.Verdict.Rank()
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Name < b.Name
	})
	return out
}

// Text renders a compact, terminal-friendly summary.
func (r Report) Text() string {
	var b strings.Builder
	c := r.Counts()
	fmt.Fprintf(&b, "flareover assessment: %s\n", r.Zone)
	fmt.Fprintf(&b, "%d elements: %d AUTO, %d ASK, %d MANUAL\n\n",
		len(r.Findings), c[Auto], c[Ask], c[Manual])
	for _, f := range r.Sorted() {
		tgt := f.Target
		if tgt == "" {
			tgt = "-"
		}
		fmt.Fprintf(&b, "  [%-6s] %-13s %s  → %s\n", f.Verdict, f.Kind, f.Name, tgt)
		fmt.Fprintf(&b, "            %s\n", f.Rationale)
		if f.Question != nil {
			fmt.Fprintf(&b, "            ? %s (%s; default %s)\n",
				f.Question.Prompt, strings.Join(f.Question.Options, "/"), f.Question.Default)
		}
	}
	if c[Manual] == 0 && c[Ask] == 0 {
		b.WriteString("\nFully deterministic: every element maps AUTO. No decisions required.\n")
	}
	return b.String()
}

// Markdown renders the report as a migration-report fragment.
func (r Report) Markdown() string {
	var b strings.Builder
	c := r.Counts()
	fmt.Fprintf(&b, "# flareover assessment: `%s`\n\n", r.Zone)
	fmt.Fprintf(&b, "**%d** elements: %d AUTO · %d ASK · %d MANUAL\n\n",
		len(r.Findings), c[Auto], c[Ask], c[Manual])
	b.WriteString("| Verdict | Kind | Element | Target | Rationale |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for _, f := range r.Sorted() {
		tgt := f.Target
		if tgt == "" {
			tgt = "-"
		}
		rat := f.Rationale
		if f.Question != nil {
			rat += fmt.Sprintf(" _(ASK: %s; default %s)_", f.Question.Prompt, f.Question.Default)
		}
		fmt.Fprintf(&b, "| %s | %s | `%s` | %s | %s |\n",
			f.Verdict, f.Kind, f.Name, tgt, escapePipes(rat))
	}
	return b.String()
}

func escapePipes(s string) string { return strings.ReplaceAll(s, "|", "\\|") }
