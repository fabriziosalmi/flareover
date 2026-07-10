// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

// Package docsgen renders documentation straight from the engine, so the docs
// can never claim coverage the code does not deliver. The coverage matrix is
// produced by running the REAL classifier over reference zones (the same code
// that enforces the 0% false-positive contract) and a test fails if the
// committed page drifts from what the code produces. That is the moat: the docs
// are provably as honest as the tool.
package docsgen

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/fabriziosalmi/flareover/internal/classify"
	cf "github.com/fabriziosalmi/flareover/internal/cloudflare"
	"github.com/fabriziosalmi/flareover/internal/provider"
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
			return "-"
		}
		return "`" + t + "`"
	}

	var b strings.Builder
	b.WriteString("---\n")
	b.WriteString("title: Coverage matrix\n")
	b.WriteString("description: \"Exactly what flareover carries over (AUTO, ASK, or MANUAL), generated from its own classifier, so the docs can never overstate coverage.\"\n")
	b.WriteString("---\n\n")
	b.WriteString(":::note[Generated from the code]\n")
	b.WriteString("This matrix is produced by running flareover's **own classifier** over reference zones: the same code that enforces the [0% false-positive contract](/docs/the-contract/). It cannot claim coverage the engine does not deliver, and a test fails if it drifts from the code. For the exact verdicts on *your* zone, run `flareover assess your.snapshot.json`.\n")
	b.WriteString(":::\n\n")

	b.WriteString("Every element gets exactly one verdict. **AUTO** = a proven equivalent is generated. **ASK** = one bounded yes/no stands between it and AUTO. **MANUAL** = surfaced, never guessed.\n\n")

	b.WriteString("## AUTO: a proven equivalent is generated\n\n")
	b.WriteString("| Feature | Target | What flareover does |\n|---|---|---|\n")
	for _, r := range rows(report.Auto) {
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", r.kind, tgt(r.target), esc(r.rationale))
	}

	b.WriteString("\n## ASK: one bounded yes/no, then AUTO\n\n")
	b.WriteString("| Feature | Target | The decision |\n|---|---|---|\n")
	for _, r := range rows(report.Ask) {
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", r.kind, tgt(r.target), esc(r.rationale))
	}

	b.WriteString("\n## MANUAL: surfaced, never guessed\n\n")
	b.WriteString("| Feature | Why it can't be mapped faithfully |\n|---|---|\n")
	for _, r := range rows(report.Manual) {
		fmt.Fprintf(&b, "| `%s` | %s |\n", r.kind, esc(r.rationale))
	}

	b.WriteString("\n## Deliberately out of scope\n\n")
	b.WriteString("Two things have **no faithful deterministic mapping** and are excluded on purpose, surfaced honestly, never faked:\n\n")
	b.WriteString("- **Geographic traffic steering**: routing users to different origins by region (a paid load-balancing feature, distinct from country *blocking*, which **is** supported).\n")
	b.WriteString("- **Cache-hit-ratio parity**: a self-hosted edge cache behaves differently from a global anycast one.\n\n")
	b.WriteString("One honest caveat on rate limiting: a per-IP limit maps AUTO, but the source enforces the threshold across its whole anycast edge, so several independent self-hosted edge nodes each count locally unless they share a counter, a distributed-systems limit, noted rather than faked.\n")
	return b.String()
}

// Sovereignty renders the sovereignty-tiers page. The conceptual prose is static,
// but the provider catalogue tables are generated from the SAME `provider.Registry`
// the CLI uses, so the published list can never drift from what `flareover
// providers` actually offers, and a hyperscaler can never be silently retiered.
func Sovereignty() string {
	var b strings.Builder
	b.WriteString("---\n")
	b.WriteString("title: Sovereignty tiers\n")
	b.WriteString("description: \"flareover moves you toward EU-sovereign infrastructure, not merely EU residency, and refuses to let a US-operated region pass as sovereign. The catalogue is generated from the tool's own provider registry.\"\n")
	b.WriteString("---\n\n")
	b.WriteString("flareover exists to move you toward EU-**sovereign** infrastructure, not merely EU *residency*. Those are different things, and the tool is deliberate about the difference. Every provider it offers is tagged, and it will never let a US-operated option pass as sovereign.\n\n")
	b.WriteString("```bash\nflareover providers   # lists every edge provider with its tier\n```\n\n")
	b.WriteString(":::note[Generated from the code]\nThe catalogue below is generated from flareover's own `provider.Registry`: the same list `flareover providers` prints and `--edge-provider` validates against. A test fails if this page drifts from it, so the tiers can't be quietly rewritten.\n:::\n\n")

	b.WriteString("## The two tiers\n\n")
	b.WriteString("| Tier | What it means |\n|------|---------------|\n")
	b.WriteString("| **EU-owned (sovereign)** | An EU-headquartered operator with **no non-EU parent** that could be compelled to hand over data. EU jurisdiction only. |\n")
	b.WriteString("| **US-operator · EU-region** | A US company's EU datacenter. Your data *resides* in the EU, but the operator is under **US CLOUD Act / FISA** reach. Offered as a pragmatic bridge, **never** labelled sovereign, always with a nudge to the EU-owned options. |\n\n")
	b.WriteString("The distinction matters because CLOUD Act reach follows the *operator's* nationality, not the datacenter's location. \"It's in Frankfurt\" does not make it sovereign if the company holding the keys answers to a foreign subpoena.\n\n")

	b.WriteString("## Edge provider catalogue\n\n")
	b.WriteString("Use a key with `flareover prepare --edge-provider <key>` to emit a cloud-init that boots a Caddy edge on that provider.\n\n")

	b.WriteString("### EU-owned (sovereign)\n\n")
	b.WriteString("| Key | Provider | Where it sits | Jurisdiction |\n|-----|----------|---------------|--------------|\n")
	for _, p := range provider.Sovereign() {
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", p.Key, p.Name, p.Residency, p.Exposure)
	}

	b.WriteString("\n### US-operator · EU-region (residency only, **not** sovereign)\n\n")
	b.WriteString("| Key | Provider | Where it sits | The honest catch |\n|-----|----------|---------------|------------------|\n")
	for _, p := range provider.ResidencyOnly() {
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", p.Key, p.Name, p.Residency, p.Exposure)
	}

	b.WriteString("\n## How tiering shows up across the tool\n\n")
	b.WriteString("The same honesty applies wherever a US-operated option appears:\n\n")
	b.WriteString("- **[DNS targets](/docs/dns-targets/):** `route53`, `clouddns`, and `azure` are labelled US-operated; provisioning against them prints a nudge to the EU-owned options.\n")
	b.WriteString("- **[Object storage](/docs/object-storage/):** the managed destinations are all EU-owned and EU-region-scoped.\n")
	b.WriteString("- **Edge:** `flareover providers` groups the two tiers explicitly.\n\n")
	b.WriteString("> This is corporate-jurisdiction information to inform a choice, **not legal advice**. Your obligations depend on your data and your regulators; confirm the exact region and terms with the provider at deploy time.\n\n")
	b.WriteString("## Why sovereignty at all\n\n")
	b.WriteString("The whole point of leaving a large managed edge is usually some mix of cost, lock-in, and control. If you're doing the work anyway, flareover makes it easy to land somewhere genuinely under EU jurisdiction, and refuses to let \"EU region\" quietly stand in for \"EU sovereign\", which is exactly the kind of silent substitution the [contract](/docs/the-contract/) is built to prevent.\n")
	return b.String()
}

// cliTokenRe matches a long flag like --edge-provider in the usage text.
var cliTokenRe = regexp.MustCompile(`--[a-z][a-z0-9-]+`)

// CLIRefGaps returns every phase name and flag present in the CLI `usage` text
// that is NOT mentioned anywhere in the CLI-reference markdown `md`. An empty
// result means the reference documents the whole surface. This is the moat for
// the (rich, hand-written) CLI reference: the docs can't silently omit a command
// or flag the binary actually ships. A test fails until it's documented.
func CLIRefGaps(usage, md string) []string {
	var want []string

	// Phase names: entries in the PHASES block. A phase line is indented two
	// spaces with a non-space third char; wrapped description lines indent deeper.
	inPhases := false
	for _, ln := range strings.Split(usage, "\n") {
		if strings.HasPrefix(ln, "PHASES") {
			inPhases = true
			continue
		}
		if !inPhases {
			continue
		}
		if ln == "" {
			continue
		}
		if !strings.HasPrefix(ln, " ") { // a new top-level header ends the block
			break
		}
		if len(ln) > 2 && ln[2] != ' ' { // a phase entry, not a wrapped line
			fields := strings.Fields(ln)
			if len(fields) > 0 && !strings.HasPrefix(fields[0], "--") {
				want = append(want, fields[0])
			}
		}
	}
	// Flags anywhere in the usage text.
	want = append(want, cliTokenRe.FindAllString(usage, -1)...)

	seen := map[string]bool{}
	var missing []string
	for _, w := range want {
		if seen[w] {
			continue
		}
		seen[w] = true
		if !strings.Contains(md, w) {
			missing = append(missing, w)
		}
	}
	sort.Strings(missing)
	return missing
}
