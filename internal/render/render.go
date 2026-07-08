// SPDX-License-Identifier: AGPL-3.0-only

// Package render turns the engine's reports into terminal output that reads at
// a glance — colored verdict badges, boxed summaries, aligned columns. It is
// pure presentation over the same data the plain Text() renderers use, and it
// degrades to no-color automatically when stdout is not a terminal or NO_COLOR
// is set, so pipes, CI, and --json stay clean.
package render

import (
	"fmt"
	"os"
	"strings"

	"github.com/fabriziosalmi/flareover/internal/cost"
	"github.com/fabriziosalmi/flareover/internal/doctor"
	"github.com/fabriziosalmi/flareover/internal/parity"
	"github.com/fabriziosalmi/flareover/internal/report"
)

// Enabled reports whether colored output should be used for the given file.
// FLAREOVER_COLOR=1 forces color on (useful for `| less -R`); NO_COLOR forces
// it off; otherwise color is used only when the file is a terminal.
func Enabled(f *os.File) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("FLAREOVER_COLOR") == "1" {
		return true
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// IsTTY reports whether the file is a terminal (for in-place animation).
func IsTTY(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// palette holds the ANSI codes, or empties when color is off.
type palette struct{ reset, bold, dim, red, green, yellow, cyan, gray string }

func newPalette(color bool) palette {
	if !color {
		return palette{}
	}
	return palette{
		reset: "\033[0m", bold: "\033[1m", dim: "\033[2m",
		red: "\033[31m", green: "\033[32m", yellow: "\033[33m",
		cyan: "\033[36m", gray: "\033[90m",
	}
}

func (p palette) verdictColor(v report.Verdict) string {
	switch v {
	case report.Auto:
		return p.green
	case report.Ask:
		return p.yellow
	case report.Manual:
		return p.red
	default:
		return p.reset
	}
}

// dot returns a colored bullet for a verdict.
func (p palette) dot(v report.Verdict) string { return p.verdictColor(v) + "●" + p.reset }

const boxW = 62

func (p palette) box(title string, lines []string) string {
	var b strings.Builder
	head := "─ " + title + " "
	fmt.Fprintf(&b, "%s╭%s%s╮%s\n", p.cyan, head, strings.Repeat("─", max(0, boxW-len(title)-3)), p.reset)
	for _, ln := range lines {
		fmt.Fprintf(&b, "%s│%s %s\n", p.cyan, p.reset, ln)
	}
	fmt.Fprintf(&b, "%s╰%s╯%s\n", p.cyan, strings.Repeat("─", boxW), p.reset)
	return b.String()
}

// Doctor renders the pre-flight checks: a boxed GO / NO-GO with one colored line
// per probe.
func Doctor(checks []doctor.Check, color bool) string {
	p := newPalette(color)
	statusColor := func(s doctor.Status) string {
		switch s {
		case doctor.OK:
			return p.green
		case doctor.Warn:
			return p.yellow
		default:
			return p.red
		}
	}
	lines := make([]string, 0, len(checks)+1)
	go_ := true
	for _, c := range checks {
		if c.Status == doctor.Fail {
			go_ = false
		}
		lines = append(lines, fmt.Sprintf("%s%-5s%s %-22s %s%s%s",
			statusColor(c.Status), c.Status, p.reset, c.Name, p.dim, c.Detail, p.reset))
	}
	verdict := p.green + "GO — target ready to provision" + p.reset
	if !go_ {
		verdict = p.red + "NO-GO — resolve the FAIL items before provisioning" + p.reset
	}
	if len(checks) == 0 {
		verdict = p.dim + "no checks configured (pass --pdns-url / --certmate-url / --spm-url / --minio-endpoint / --check-caddy)" + p.reset
	}
	lines = append(lines, verdict)
	return p.box("flareover · doctor · pre-flight", lines)
}

// Assess renders an assessment report.
func Assess(r report.Report, color bool) string {
	p := newPalette(color)
	c := r.Counts()
	var b strings.Builder

	summary := fmt.Sprintf("%s%d elements%s   %s %d AUTO   %s %d ASK   %s %d MANUAL",
		p.bold, len(r.Findings), p.reset,
		p.dot(report.Auto), c[report.Auto],
		p.dot(report.Ask), c[report.Ask],
		p.dot(report.Manual), c[report.Manual])
	b.WriteString(p.box("flareover · assessment · "+r.Zone, []string{summary}))
	b.WriteString("\n")

	groups := []struct {
		v     report.Verdict
		label string
	}{
		{report.Manual, "MANUAL — surfaced, never guessed"},
		{report.Ask, "ASK — one yes/no each"},
		{report.Auto, "AUTO — generated"},
	}
	sorted := r.Sorted()
	for _, g := range groups {
		var items []report.Finding
		for _, f := range sorted {
			if f.Verdict == g.v {
				items = append(items, f)
			}
		}
		if len(items) == 0 {
			continue
		}
		col := p.verdictColor(g.v)
		fmt.Fprintf(&b, "%s%s%s %s(%d)%s\n", col, badge(g.v), p.reset, p.dim, len(items), p.reset)
		for _, f := range items {
			tgt := f.Target
			if tgt == "" {
				tgt = "—"
			}
			fmt.Fprintf(&b, "  %s %s%-13s%s %s %s→%s %s%s%s\n",
				p.dot(f.Verdict), p.bold, f.Kind, p.reset, f.Name, p.gray, p.reset, p.cyan, tgt, p.reset)
			fmt.Fprintf(&b, "     %s%s%s\n", p.dim, f.Rationale, p.reset)
			if f.Question != nil {
				fmt.Fprintf(&b, "     %s? %s (%s)%s\n", p.yellow, f.Question.Prompt,
					strings.Join(f.Question.Options, "/"), p.reset)
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

func badge(v report.Verdict) string {
	return " " + string(v) + " "
}

// Cost renders a cost report.
func Cost(r cost.Report, color bool) string {
	p := newPalette(color)
	var b strings.Builder
	b.WriteString(p.box("flareover · cost · "+r.Zone, []string{
		fmt.Sprintf("Cloudflare floor: %s%s%s   %s%.2f %s/mo%s",
			p.bold, r.CloudflarePlan, p.reset, p.yellow, r.CloudflareMonthlyMin, r.Currency, p.reset),
		fmt.Sprintf("EU sovereign:                %s%.2f %s/mo%s", p.green, r.EUStackMonthly, r.Currency, p.reset),
	}))
	b.WriteString("\n")
	if len(r.Drivers) > 0 {
		fmt.Fprintf(&b, "%sCost drivers%s\n", p.bold, p.reset)
		for _, d := range r.Drivers {
			amt := "usage-priced"
			if d.Monthly > 0 {
				amt = fmt.Sprintf("~%.2f %s/mo", d.Monthly, r.Currency)
			}
			fmt.Fprintf(&b, "  %s●%s %s%-16s%s %s  %s[%s · %s]%s\n",
				p.yellow, p.reset, p.bold, d.Feature, p.reset, d.Detail, p.gray, d.MinTier, amt, p.reset)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "%sEU stack%s\n", p.bold, p.reset)
	for _, it := range r.EUStackItems {
		fmt.Fprintf(&b, "  %s✓%s %s\n", p.green, p.reset, it)
	}
	b.WriteString("\n")
	if r.SavingsMonthly > 0 {
		fmt.Fprintf(&b, "%s%s→ saving %.2f %s/mo  (%.0f %s/yr)%s\n",
			p.bold, p.green, r.SavingsMonthly, r.Currency, r.SavingsMonthly*12, r.Currency, p.reset)
	} else {
		fmt.Fprintf(&b, "%s%s→ flat sovereign cost %.2f %s/mo — no egress fees, no lock-in%s\n",
			p.bold, p.green, r.EUStackMonthly, r.Currency, p.reset)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "  %snote: %s%s\n", p.dim, n, p.reset)
	}
	return b.String()
}

// Parity renders a parity report and its gate verdict.
func Parity(r parity.Report, color bool) string {
	p := newPalette(color)
	var b strings.Builder
	match, hard, soft := 0, 0, 0
	for _, res := range r.Results {
		if res.Match() {
			match++
		}
		for _, d := range res.Divergences {
			if d.Hard {
				hard++
			} else {
				soft++
			}
		}
	}
	b.WriteString(p.box("flareover · parity gate", []string{
		fmt.Sprintf("%s  vs  %s", r.Before, r.After),
		fmt.Sprintf("%d probes   %s%d match%s   %s%d hard%s   %s%d soft%s",
			len(r.Results), p.green, match, p.reset, p.red, hard, p.reset, p.gray, soft, p.reset),
	}))
	b.WriteString("\n")
	for _, res := range r.Results {
		mark, col := p.green+"✓"+p.reset, p.reset
		if res.HardFail() {
			mark, col = p.red+"✗"+p.reset, p.red
		} else if !res.Match() {
			mark = p.gray + "~" + p.reset
		}
		fmt.Fprintf(&b, "  %s %s%s%s\n", mark, col, res.Probe.Name, p.reset)
		for _, d := range res.Divergences {
			tag := p.gray + "soft" + p.reset
			if d.Hard {
				tag = p.red + "HARD" + p.reset
			}
			fmt.Fprintf(&b, "      [%s] %s: %q → %q\n", tag, d.Field, d.Before, d.After)
		}
	}
	b.WriteString("\n")
	greenBg, redBg := "", ""
	if color {
		greenBg, redBg = "\033[42;30m", "\033[41;30m"
	}
	if r.Gate() {
		fmt.Fprintf(&b, "%s  GATE: PASS  %s  no behavior-changing divergence — cutover permitted\n", greenBg, p.reset)
	} else {
		fmt.Fprintf(&b, "%s  GATE: FAIL  %s  hard divergence — cutover blocked\n", redBg, p.reset)
	}
	return b.String()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
