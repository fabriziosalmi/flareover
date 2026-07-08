package report

import (
	"fmt"
	"html"
	"strings"
)

// HTML renders the coverage report as a single self-contained HTML document —
// the "Presentation that leaves no doubt", shareable with a stakeholder. It is
// pure rendering of already-decided verdicts: it invents nothing, so it cannot
// affect the 0% FP contract. No external assets (CSP-safe), theme-aware.
func (r Report) HTML() string {
	c := r.Counts()
	deterministic := c[Manual] == 0 && c[Ask] == 0

	var rows strings.Builder
	for _, f := range r.Sorted() {
		tgt := f.Target
		if tgt == "" {
			tgt = "—"
		}
		rat := html.EscapeString(f.Rationale)
		if f.Question != nil {
			rat += fmt.Sprintf(` <span class="ask">ASK: %s — options %s, default <b>%s</b></span>`,
				html.EscapeString(f.Question.Prompt),
				html.EscapeString(strings.Join(f.Question.Options, "/")),
				html.EscapeString(f.Question.Default))
		}
		fmt.Fprintf(&rows,
			`<tr class="v-%s"><td><span class="badge b-%s">%s</span></td><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td></tr>`+"\n",
			strings.ToLower(string(f.Verdict)), strings.ToLower(string(f.Verdict)), f.Verdict,
			html.EscapeString(f.Kind), html.EscapeString(f.Name), html.EscapeString(tgt), rat)
	}

	banner := ""
	if deterministic {
		banner = `<p class="det">✓ Fully deterministic — every element maps AUTO. No decisions required.</p>`
	} else {
		banner = fmt.Sprintf(`<p class="att">%d item(s) need attention: answer the ASK questions, handle the MANUAL items. Nothing is guessed.</p>`,
			c[Ask]+c[Manual])
	}

	return fmt.Sprintf(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>flareover assessment — %s</title>
<style>
 :root{--bg:#fff;--fg:#1a1d24;--mut:#5b6470;--line:#e4e7ec;--card:#f7f8fa;
   --auto:#12805c;--ask:#a8700a;--manual:#c0392b;--code:#f0f2f5}
 @media (prefers-color-scheme:dark){:root{--bg:#0b0e14;--fg:#e6e6e6;--mut:#8a93a2;
   --line:#232a36;--card:#121722;--auto:#5fd39a;--ask:#e5b567;--manual:#f07a6b;--code:#161b26}}
 :root[data-theme=light]{--bg:#fff;--fg:#1a1d24;--mut:#5b6470;--line:#e4e7ec;--card:#f7f8fa;
   --auto:#12805c;--ask:#a8700a;--manual:#c0392b;--code:#f0f2f5}
 :root[data-theme=dark]{--bg:#0b0e14;--fg:#e6e6e6;--mut:#8a93a2;--line:#232a36;
   --card:#121722;--auto:#5fd39a;--ask:#e5b567;--manual:#f07a6b;--code:#161b26}
 *{box-sizing:border-box}
 body{margin:0;background:var(--bg);color:var(--fg);
   font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:2rem 1rem}
 .wrap{max-width:960px;margin:0 auto}
 h1{font-size:1.5rem;margin:.2rem 0}
 h1 .flare{color:#f38020}
 .zone{color:var(--mut);font-size:.95rem;margin-bottom:1.2rem}
 .pills{display:flex;gap:.6rem;flex-wrap:wrap;margin:.8rem 0 1rem}
 .pill{border:1px solid var(--line);border-radius:999px;padding:.3rem .9rem;font-weight:600;font-size:.9rem}
 .pill b{font-size:1.05rem}
 .pill.auto{color:var(--auto)} .pill.ask{color:var(--ask)} .pill.manual{color:var(--manual)}
 .det{color:var(--auto);font-weight:600} .att{color:var(--ask);font-weight:600}
 .scroll{overflow-x:auto;border:1px solid var(--line);border-radius:10px}
 table{width:100%%;border-collapse:collapse;font-size:.9rem;min-width:640px}
 th,td{text-align:left;padding:.55rem .7rem;border-bottom:1px solid var(--line);vertical-align:top}
 th{color:var(--mut);font-weight:600;font-size:.78rem;text-transform:uppercase;letter-spacing:.04em}
 tr:last-child td{border-bottom:0}
 tbody tr:hover{background:var(--card)}
 .badge{display:inline-block;border-radius:6px;padding:.1rem .5rem;font-size:.78rem;font-weight:700;color:#fff}
 .b-auto{background:var(--auto)} .b-ask{background:var(--ask)} .b-manual{background:var(--manual)}
 code{background:var(--code);padding:.1rem .35rem;border-radius:5px;font-size:.85em}
 .ask{color:var(--ask);font-style:italic}
 .foot{color:var(--mut);font-size:.82rem;margin-top:1.6rem;border-top:1px solid var(--line);padding-top:1rem}
</style></head><body><div class="wrap">
<h1><span class="flare">flare</span>over — assessment</h1>
<div class="zone">%s</div>
<div class="pills">
 <span class="pill">%d elements</span>
 <span class="pill auto">AUTO <b>%d</b></span>
 <span class="pill ask">ASK <b>%d</b></span>
 <span class="pill manual">MANUAL <b>%d</b></span>
</div>
%s
<div class="scroll"><table>
<thead><tr><th>Verdict</th><th>Kind</th><th>Element</th><th>Target</th><th>Rationale</th></tr></thead>
<tbody>
%s</tbody></table></div>
<p class="foot">0%% false-positive contract: behavior-changing config is generated only for AUTO and
answered-ASK items. MANUAL items are surfaced, never guessed. Classification is a pure function of
the snapshot and decisions — re-running yields identical output.</p>
</div></body></html>
`, html.EscapeString(r.Zone), html.EscapeString(r.Zone),
		len(r.Findings), c[Auto], c[Ask], c[Manual], banner, rows.String())
}
