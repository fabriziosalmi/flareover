// SPDX-License-Identifier: AGPL-3.0-only

// Package docsgen renders documentation straight from the engine, so the docs
// can never claim coverage the code does not deliver. The coverage matrix is
// produced by running the REAL classifier over reference zones — the same code
// that enforces the 0% false-positive contract — and a test fails if the
// committed page drifts from what the code produces. That is the moat: the docs
// are provably as honest as the tool.
package docsgen

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fabriziosalmi/flareover/internal/classify"
	cf "github.com/fabriziosalmi/flareover/internal/cloudflare"
	"github.com/fabriziosalmi/flareover/internal/report"
)

type row struct{ kind, target, rationale string }

// Coverage renders the coverage matrix as Starlight-flavored Markdown from the
// classifier's verdicts over the given reference snapshots (deduped across all
// of them). AUTO includes PARTIAL findings (they are emitted, approximately).
func Coverage(snaps ...cf.Snapshot) string {
	byVerdict := map[report.Verdict]map[string]row{
		report.Auto:   {},
		report.Ask:    {},
		report.Manual: {},
	}
	for _, s := range snaps {
		for _, f := range classify.Classify(s).Findings {
			m, ok := byVerdict[f.Verdict]
			if !ok {
				continue
			}
			key := f.Kind + "\x00" + f.Target + "\x00" + f.Rationale
			m[key] = row{kind: f.Kind, target: f.Target, rationale: f.Rationale}
		}
	}
	rows := func(v report.Verdict) []row {
		rs := make([]row, 0, len(byVerdict[v]))
		for _, r := range byVerdict[v] {
			rs = append(rs, r)
		}
		sort.Slice(rs, func(i, j int) bool {
			if rs[i].kind != rs[j].kind {
				return rs[i].kind < rs[j].kind
			}
			return rs[i].rationale < rs[j].rationale
		})
		return rs
	}
	esc := func(s string) string {
		return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ")
	}
	tgt := func(t string) string {
		if t == "" {
			return "—"
		}
		return "`" + t + "`"
	}

	var b strings.Builder
	b.WriteString("---\n")
	b.WriteString("title: Coverage matrix\n")
	b.WriteString("description: \"Exactly what flareover carries over — AUTO, ASK, or MANUAL — generated from its own classifier, so the docs can never overstate coverage.\"\n")
	b.WriteString("---\n\n")
	b.WriteString(":::note[Generated from the code]\n")
	b.WriteString("This matrix is produced by running flareover's **own classifier** over reference zones — the same code that enforces the [0% false-positive contract](/docs/the-contract/). It cannot claim coverage the engine does not deliver, and a test fails if it drifts from the code. For the exact verdicts on *your* zone, run `flareover assess your.snapshot.json`.\n")
	b.WriteString(":::\n\n")

	b.WriteString("Every element gets exactly one verdict. **AUTO** = a proven equivalent is generated. **ASK** = one bounded yes/no stands between it and AUTO. **MANUAL** = surfaced, never guessed.\n\n")

	b.WriteString("## AUTO — a proven equivalent is generated\n\n")
	b.WriteString("| Feature | Target | What flareover does |\n|---|---|---|\n")
	for _, r := range rows(report.Auto) {
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", r.kind, tgt(r.target), esc(r.rationale))
	}

	b.WriteString("\n## ASK — one bounded yes/no, then AUTO\n\n")
	b.WriteString("| Feature | Target | The decision |\n|---|---|---|\n")
	for _, r := range rows(report.Ask) {
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", r.kind, tgt(r.target), esc(r.rationale))
	}

	b.WriteString("\n## MANUAL — surfaced, never guessed\n\n")
	b.WriteString("| Feature | Why it can't be mapped faithfully |\n|---|---|\n")
	for _, r := range rows(report.Manual) {
		fmt.Fprintf(&b, "| `%s` | %s |\n", r.kind, esc(r.rationale))
	}

	b.WriteString("\n## Deliberately out of scope\n\n")
	b.WriteString("Two things have **no faithful deterministic mapping** and are excluded on purpose — surfaced honestly, never faked:\n\n")
	b.WriteString("- **Geographic traffic steering** — routing users to different origins by region (a paid load-balancing feature, distinct from country *blocking*, which **is** supported).\n")
	b.WriteString("- **Cache-hit-ratio parity** — a self-hosted edge cache behaves differently from a global anycast one.\n\n")
	b.WriteString("One honest caveat on rate limiting: a per-IP limit maps AUTO, but the source enforces the threshold across its whole anycast edge, so several independent self-hosted edge nodes each count locally unless they share a counter — a distributed-systems limit, noted rather than faked.\n")
	return b.String()
}
