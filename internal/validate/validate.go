// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

// Package validate proves that generated artifacts actually parse, turning
// "faithful by construction" into "faithful and checked". It only ever runs
// read-only checkers (a syntax linter, `caddy validate`/`caddy fmt`), so it can
// report a problem but can never introduce one: it is incapable of affecting the
// 0% FP contract. Validation that cannot run (no `caddy` on PATH, or a stock
// build missing the caddy-waf/souin modules) is reported as skipped, never as a
// silent pass and never as a false failure.
package validate

import (
	"os"
	"os/exec"
	"strings"
)

// CaddyResult describes what Caddy validation ran and how it went.
type CaddyResult struct {
	Ran    string // "validate" (module-aware) | "fmt" (syntax only) | "" (nothing ran)
	OK     bool   // meaningful only when Ran != ""
	Detail string // human note, or the checker's error output on failure
}

// Skipped reports whether no check ran (caddy absent). A skipped check must not
// gate a pipeline as a failure.
func (r CaddyResult) Skipped() bool { return r.Ran == "" }

// Caddyfile validates a generated Caddyfile. If the caddy binary carries the
// caddy-waf and souin modules the generated config assumes, it runs the
// authoritative `caddy validate`. Otherwise it falls back to `caddy fmt`, which
// checks structure (braces/tokens) without resolving directives to modules, so
// a stock caddy never false-fails on the caddy-waf/souin directives it lacks.
func Caddyfile(content []byte) CaddyResult {
	caddy, err := exec.LookPath("caddy")
	if err != nil {
		return CaddyResult{Detail: "caddy not on PATH: validation skipped (install the custom xcaddy build to validate fully)"}
	}

	tmp, err := os.CreateTemp("", "flareover-*.Caddyfile")
	if err != nil {
		return CaddyResult{Detail: "could not stage Caddyfile for validation: " + err.Error()}
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(content); err != nil {
		return CaddyResult{Detail: "could not write staged Caddyfile: " + err.Error()}
	}
	tmp.Close()

	if hasCaddyModules(caddy) {
		out, err := exec.Command(caddy, "validate", "--adapter", "caddyfile", "--config", tmp.Name()).CombinedOutput() // #nosec G204: caddy resolved via LookPath, temp path we own
		if err != nil {
			return CaddyResult{Ran: "validate", OK: false, Detail: strings.TrimSpace(string(out))}
		}
		return CaddyResult{Ran: "validate", OK: true, Detail: "caddy validate passed (module-aware)"}
	}

	// Stock caddy: fmt checks syntax/structure without needing the WAF/cache modules.
	out, err := exec.Command(caddy, "fmt", tmp.Name()).CombinedOutput() // #nosec G204: caddy resolved via LookPath, temp path we own
	if err != nil {
		return CaddyResult{Ran: "fmt", OK: false, Detail: strings.TrimSpace(string(out))}
	}
	return CaddyResult{Ran: "fmt", OK: true,
		Detail: "syntax OK (caddy fmt); full validate needs the custom build (caddy-waf + souin)"}
}

// hasCaddyModules reports whether the caddy binary carries the WAF and cache
// modules the generated Caddyfile relies on.
func hasCaddyModules(caddy string) bool {
	out, err := exec.Command(caddy, "list-modules").CombinedOutput() // #nosec G204: caddy resolved via LookPath
	if err != nil {
		return false
	}
	mods := string(out)
	hasWAF := strings.Contains(mods, "waf")
	hasCache := strings.Contains(mods, "cache") || strings.Contains(mods, "souin")
	return hasWAF && hasCache
}

// Zone is a pure-Go structural lint of a generated BIND-style zone file: it
// verifies multi-line record parentheses balance and that every record line
// carries enough fields to be a record. It is deliberately lenient: it flags
// structural breakage, never style, so it cannot produce a false failure on
// valid output.
func Zone(content []byte) (ok bool, problems []string) {
	paren := 0
	for i, raw := range strings.Split(string(content), "\n") {
		line := raw
		if idx := strings.IndexByte(line, ';'); idx >= 0 { // strip comments
			line = line[:idx]
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		opens := strings.Count(trimmed, "(")
		closes := strings.Count(trimmed, ")")

		// Only lint standalone record lines: skip $ORIGIN/$TTL directives and any
		// line that is part of a parenthesised (multi-line) record like the SOA.
		if paren == 0 && !strings.HasPrefix(trimmed, "$") {
			// A continuation-free record needs at least owner + type + rdata.
			if opens == 0 && len(strings.Fields(trimmed)) < 3 {
				problems = append(problems, lineRef(i+1, raw)+": too few fields for a record")
			}
		}

		paren += opens - closes
		if paren < 0 {
			problems = append(problems, lineRef(i+1, raw)+": unbalanced ')' (closes more than it opens)")
			paren = 0
		}
	}
	if paren != 0 {
		problems = append(problems, "unterminated '(': a multi-line record (e.g. SOA) never closes")
	}
	return len(problems) == 0, problems
}

func lineRef(n int, raw string) string {
	s := strings.TrimSpace(raw)
	if len(s) > 48 {
		s = s[:48] + "…"
	}
	return "line " + itoa(n) + " " + strings.TrimSpace(s)
}

// itoa avoids pulling strconv for one small use.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
