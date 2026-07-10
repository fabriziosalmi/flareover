// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

// Package parity is the Failguards muscle: it proves the new edge behaves like
// Cloudflare before any cutover is allowed. It probes both edges with the same
// requests and diffs the responses, but only on what represents *behavior*
// (status code, redirect target, a small set of significant headers, body),
// deliberately ignoring provider-specific noise (Date, Server, CF-Ray, …). The
// gate passes only when every probe matches on the HARD signals (status +
// redirect Location); cosmetic differences are surfaced as SOFT, never silent,
// but do not by themselves block the cutover.
package parity

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/fabriziosalmi/flareover/internal/ir"
)

// Probe is a single request to replay against both edges.
type Probe struct {
	Name    string            // human description
	Host    string            // Host header (and SNI when https)
	Path    string            // request path, e.g. "/" or "/old/x"
	Method  string            // default GET
	Headers map[string]string // extra request headers (e.g. a malicious UA for a WAF probe)
}

// Divergence is one observed difference. Hard=true means it changes behavior.
type Divergence struct {
	Field  string `json:"field"` // "status" | "redirect" | "header:Name" | "body"
	Before string `json:"before"`
	After  string `json:"after"`
	Hard   bool   `json:"hard"`
}

// Result is the comparison for one probe.
type Result struct {
	Probe       Probe        `json:"probe"`
	Divergences []Divergence `json:"divergences,omitempty"`
}

// Match reports whether the probe matched on every signal.
func (r Result) Match() bool { return len(r.Divergences) == 0 }

// HardFail reports whether any behavior-changing divergence was seen.
func (r Result) HardFail() bool {
	for _, d := range r.Divergences {
		if d.Hard {
			return true
		}
	}
	return false
}

// Report is the full parity comparison and the cutover gate.
type Report struct {
	Before  string   `json:"before"`
	After   string   `json:"after"`
	Results []Result `json:"results"`
}

// Gate reports whether cutover is allowed: no probe may have a hard divergence.
func (r Report) Gate() bool {
	for _, res := range r.Results {
		if res.HardFail() {
			return false
		}
	}
	return true
}

// Text renders a terminal-friendly parity report ending in the gate verdict.
func (r Report) Text() string {
	var b strings.Builder
	hard, soft, matched := 0, 0, 0
	for _, res := range r.Results {
		if res.Match() {
			matched++
		}
		for _, d := range res.Divergences {
			if d.Hard {
				hard++
			} else {
				soft++
			}
		}
	}
	fmt.Fprintf(&b, "flareover parity: %s  vs  %s\n", r.Before, r.After)
	fmt.Fprintf(&b, "%d probes: %d match, %d hard divergence(s), %d soft\n\n", len(r.Results), matched, hard, soft)
	for _, res := range r.Results {
		if res.Match() {
			fmt.Fprintf(&b, "  ✓ %s\n", res.Probe.Name)
			continue
		}
		mark := "~"
		if res.HardFail() {
			mark = "✗"
		}
		fmt.Fprintf(&b, "  %s %s\n", mark, res.Probe.Name)
		for _, d := range res.Divergences {
			tag := "soft"
			if d.Hard {
				tag = "HARD"
			}
			fmt.Fprintf(&b, "      [%s] %s: %q → %q\n", tag, d.Field, d.Before, d.After)
		}
	}
	if r.Gate() {
		b.WriteString("\nGATE: PASS. No behavior-changing divergence. Cutover permitted.\n")
	} else {
		b.WriteString("\nGATE: FAIL. Hard divergence(s) present. Cutover blocked.\n")
	}
	return b.String()
}

// significantHeaders are compared; everything else is treated as provider noise.
// Location is handled separately (as the redirect signal).
var significantHeaders = []string{
	"Content-Type", "Cache-Control", "Content-Encoding", "Vary", "WWW-Authenticate",
}

// Endpoint describes one side of the comparison. The probe's Host always drives
// the URL, Host header, and TLS SNI (so the edge routes correctly); DialOverride
// forces the actual TCP connection to a fixed address: the way to compare a
// live domain (real DNS) against a staged edge reached by IP, with SNI intact
// (like `curl --resolve`).
type Endpoint struct {
	Scheme       string // "https" (default) | "http"
	DialOverride string // "" = resolve via DNS; else "host:port" to dial
	Insecure     bool   // skip TLS verification (staged internal-CA edge)
}

func (e Endpoint) scheme() string {
	if e.Scheme == "" {
		return "https"
	}
	return e.Scheme
}

func (e Endpoint) label() string {
	if e.DialOverride != "" {
		return e.scheme() + "://→" + e.DialOverride
	}
	return e.scheme() + "://(dns)"
}

func (e Endpoint) client() *http.Client {
	tr := &http.Transport{}
	if e.Insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	if e.DialOverride != "" {
		d := &net.Dialer{Timeout: 10 * time.Second}
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, e.DialOverride)
		}
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Comparer probes and diffs two edges.
type Comparer struct{}

// NewComparer builds a Comparer.
func NewComparer() *Comparer { return &Comparer{} }

// Compare replays every probe against both endpoints and returns the report.
// The probe's Host drives URL/Host/SNI on both sides; each endpoint decides
// scheme, dial target, and TLS strictness.
func (c *Comparer) Compare(ctx context.Context, before, after Endpoint, probes []Probe) (Report, error) {
	rep := Report{Before: before.label(), After: after.label()}
	bc, ac := before.client(), after.client()
	for _, p := range probes {
		bResp, errB := fetch(ctx, bc, before.scheme(), p)
		aResp, errA := fetch(ctx, ac, after.scheme(), p)
		res := Result{Probe: p}
		switch {
		case errB != nil && errA != nil:
			res.Divergences = append(res.Divergences, Divergence{Field: "error", Before: errB.Error(), After: errA.Error(), Hard: false})
		case errB != nil:
			res.Divergences = append(res.Divergences, Divergence{Field: "error", Before: errB.Error(), After: "ok", Hard: true})
		case errA != nil:
			res.Divergences = append(res.Divergences, Divergence{Field: "error", Before: "ok", After: errA.Error(), Hard: true})
		default:
			res.Divergences = diff(bResp, aResp)
		}
		rep.Results = append(rep.Results, res)
	}
	return rep, nil
}

// response is the normalized, comparable view of an HTTP response.
type response struct {
	status   int
	location string
	headers  map[string]string
	bodyHash string
}

func fetch(ctx context.Context, client *http.Client, scheme string, p Probe) (response, error) {
	method := p.Method
	if method == "" {
		method = http.MethodGet
	}
	url := scheme + "://" + p.Host + p.Path
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return response{}, err
	}
	req.Host = p.Host
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return response{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	h := map[string]string{}
	for _, name := range significantHeaders {
		if v := resp.Header.Get(name); v != "" {
			h[name] = v
		}
	}
	sum := sha256.Sum256(body)
	return response{
		status:   resp.StatusCode,
		location: normalizeLocation(resp.Header.Get("Location")),
		headers:  h,
		bodyHash: hex.EncodeToString(sum[:]),
	}, nil
}

// diff compares two normalized responses. Status and redirect Location are HARD
// (behavior); header and body differences are SOFT (surfaced, not gating).
func diff(b, a response) []Divergence {
	var out []Divergence
	if b.status != a.status {
		out = append(out, Divergence{Field: "status", Before: fmt.Sprint(b.status), After: fmt.Sprint(a.status), Hard: true})
	}
	if b.location != a.location {
		out = append(out, Divergence{Field: "redirect", Before: b.location, After: a.location, Hard: true})
	}
	for _, name := range significantHeaders {
		if b.headers[name] != a.headers[name] {
			out = append(out, Divergence{Field: "header:" + name, Before: b.headers[name], After: a.headers[name], Hard: false})
		}
	}
	// Body is only meaningful for non-redirect responses.
	if b.status < 300 || b.status >= 400 {
		if b.bodyHash != a.bodyHash {
			out = append(out, Divergence{Field: "body", Before: "sha256:" + short(b.bodyHash), After: "sha256:" + short(a.bodyHash), Hard: false})
		}
	}
	return out
}

// ProbesFromPlan derives a probe set from the migration plan: each site's root,
// plus every redirect's match path (to verify the redirect reproduces). This is
// what makes the gate specific to the actual configuration being migrated.
func ProbesFromPlan(p ir.Plan) []Probe {
	var probes []Probe
	seen := map[string]bool{}
	add := func(pr Probe) {
		// Include the headers in the dedup key: a WAF probe shares host+path with
		// the site root but differs by a triggering header, and must survive.
		key := pr.Host + " " + pr.Path + " " + fmt.Sprint(pr.Headers)
		if !seen[key] {
			seen[key] = true
			probes = append(probes, pr)
		}
	}
	for _, s := range p.Sites {
		// A wildcard site (*.host) can't be probed with a literal "*" Host:
		// concretizeHost substitutes a concrete label so the request is meaningful.
		host := concretizeHost(s.Host)
		add(Probe{Name: "root " + s.Host, Host: host, Path: "/"})
		for _, r := range s.Redirects {
			path := redirectProbePath(r.Match)
			add(Probe{Name: "redirect " + s.Host + path, Host: host, Path: path})
		}
	}
	// Security probes: send a request that a custom WAF rule should block, so the
	// gate verifies both edges block it identically. Only header-target rules
	// with a known trigger value are exercised here.
	if len(p.Sites) > 0 {
		host := concretizeHost(p.Sites[0].Host)
		for _, rule := range p.WAF.CustomRules {
			if rule.Action != "block" || rule.Sample == "" {
				continue
			}
			hdr := wafProbeHeader(rule.Targets)
			if hdr == "" {
				continue
			}
			add(Probe{
				Name: "waf-block " + rule.Description, Host: host, Path: "/",
				Headers: map[string]string{hdr: rule.Sample},
			})
		}
	}
	sort.SliceStable(probes, func(i, j int) bool {
		if probes[i].Name != probes[j].Name {
			return probes[i].Name < probes[j].Name
		}
		return probes[i].Path < probes[j].Path
	})
	return probes
}

func concretizeHost(h string) string {
	if strings.HasPrefix(h, "*.") {
		return "wildcard-probe." + strings.TrimPrefix(h, "*.")
	}
	return h
}

// wafProbeHeader maps a caddy-waf target token to the request header that
// triggers it, or "" if the rule is not exercisable via a simple header.
func wafProbeHeader(targets []string) string {
	for _, t := range targets {
		switch {
		case t == "USER_AGENT", strings.EqualFold(t, "HEADERS:User-Agent"):
			return "User-Agent"
		case strings.HasPrefix(t, "HEADERS:"):
			return strings.TrimPrefix(t, "HEADERS:")
		}
	}
	return ""
}

func redirectProbePath(match string) string {
	if match == "" || match == "*" {
		return "/"
	}
	// Turn a glob like "/old/*" into a concrete probe path.
	return strings.ReplaceAll(match, "*", "probe")
}

func normalizeLocation(loc string) string {
	// Trailing slashes and case in scheme/host are not behavior; the path is.
	return strings.TrimRight(loc, "/")
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
