// SPDX-License-Identifier: AGPL-3.0-only

// Package doctor is the pre-flight: before you provision, it checks — read-only —
// that every target service is reachable, authorized, and configured the way the
// provisioning step will need it. It writes nothing and changes nothing, so it
// cannot affect the 0% FP contract; it only turns the failures we learned the
// hard way (a missing certbot, a too-short token, an unconfigured DNS provider,
// an unreachable API) into an explicit GO / NO-GO before anything is applied.
package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// Status is a single check's outcome.
type Status int

const (
	OK   Status = iota // ready
	Warn               // works, but attention advised
	Fail               // will break provisioning
)

func (s Status) String() string {
	switch s {
	case OK:
		return "OK"
	case Warn:
		return "WARN"
	default:
		return "FAIL"
	}
}

// Check is one pre-flight probe.
type Check struct {
	Name   string
	Status Status
	Detail string
}

// Options selects which services to probe; an empty field means "skip that one".
type Options struct {
	PDNSURL       string
	PDNSKey       string
	CertMateURL   string
	CertMateToken string
	MinIOEndpoint string
	SPMURL        string
	CheckCaddy    bool
	HTTP          *http.Client
}

// weakTokenPatterns mirror the substrings CertMate/SPM reject in a bearer token.
var weakTokenPatterns = []string{"demo", "test", "changeme", "password", "admin", "secret", "12345678", "qwerty", "example"}

// Run executes every configured probe and returns the checks in a stable order.
func Run(ctx context.Context, o Options) []Check {
	if o.HTTP == nil {
		o.HTTP = &http.Client{Timeout: 8 * time.Second}
	}
	var checks []Check

	if o.PDNSURL != "" {
		checks = append(checks, checkPowerDNS(ctx, o))
	}
	if o.CertMateToken != "" {
		checks = append(checks, checkTokenStrength("CertMate API token", o.CertMateToken))
	}
	if o.CertMateURL != "" {
		checks = append(checks, checkCertMate(ctx, o))
	}
	if o.MinIOEndpoint != "" {
		checks = append(checks, checkReachable(ctx, o, "MinIO", o.MinIOEndpoint))
	}
	if o.SPMURL != "" {
		checks = append(checks, checkSPM(ctx, o))
	}
	if o.CheckCaddy {
		checks = append(checks, checkCaddyBuild())
	}
	return checks
}

// GoNoGo is true when no check FAILED (warnings are allowed through).
func GoNoGo(checks []Check) bool {
	for _, c := range checks {
		if c.Status == Fail {
			return false
		}
	}
	return true
}

func (o Options) get(ctx context.Context, url string, hdr map[string]string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := o.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func checkPowerDNS(ctx context.Context, o Options) Check {
	code, body, err := o.get(ctx, strings.TrimRight(o.PDNSURL, "/")+"/api/v1/servers", map[string]string{"X-API-Key": o.PDNSKey})
	switch {
	case err != nil:
		return Check{"PowerDNS API", Fail, "unreachable: " + err.Error()}
	case code == 401 || code == 403:
		return Check{"PowerDNS API", Fail, "API key rejected (set --pdns-key)"}
	case code >= 300:
		return Check{"PowerDNS API", Fail, fmt.Sprintf("HTTP %d", code)}
	default:
		var servers []struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(body, &servers)
		return Check{"PowerDNS API", OK, fmt.Sprintf("reachable, %d server(s)", len(servers))}
	}
}

func checkCertMate(ctx context.Context, o Options) Check {
	code, body, err := o.get(ctx, strings.TrimRight(o.CertMateURL, "/")+"/api/health", nil)
	if err != nil {
		return Check{"CertMate API", Fail, "unreachable: " + err.Error()}
	}
	if code >= 300 {
		return Check{"CertMate API", Fail, fmt.Sprintf("HTTP %d on /api/health", code)}
	}
	healthy := strings.Contains(string(body), "healthy") || strings.Contains(string(body), "\"ok\"")

	// If a token is supplied, confirm a DNS provider is actually configured —
	// issuance fails silently later otherwise.
	if o.CertMateToken != "" {
		sc, sbody, serr := o.get(ctx, strings.TrimRight(o.CertMateURL, "/")+"/api/settings",
			map[string]string{"Authorization": "Bearer " + o.CertMateToken})
		if serr == nil && sc < 300 {
			if !hasDNSProvider(sbody) {
				return Check{"CertMate API", Warn, "reachable but no DNS provider token configured (DNS-01 will fail)"}
			}
			return Check{"CertMate API", OK, "healthy, DNS provider configured"}
		}
	}
	if healthy {
		return Check{"CertMate API", OK, "healthy (token not supplied → DNS-provider config unchecked)"}
	}
	return Check{"CertMate API", Warn, "reachable but health not confirmed"}
}

func hasDNSProvider(settings []byte) bool {
	var s map[string]any
	if err := json.Unmarshal(settings, &s); err != nil {
		return false
	}
	if t, _ := s["cloudflare_token"].(string); t != "" {
		return true
	}
	dp, _ := s["dns_providers"].(map[string]any)
	for _, v := range dp {
		if m, ok := v.(map[string]any); ok {
			if tok, _ := m["api_token"].(string); tok != "" {
				return true
			}
		}
	}
	return false
}

func checkSPM(ctx context.Context, o Options) Check {
	code, body, err := o.get(ctx, strings.TrimRight(o.SPMURL, "/")+"/readyz", nil)
	if err != nil {
		return Check{"secure-proxy-manager", Fail, "unreachable: " + err.Error()}
	}
	if code >= 300 {
		return Check{"secure-proxy-manager", Fail, fmt.Sprintf("HTTP %d on /readyz", code)}
	}
	if strings.Contains(string(body), "ready") {
		return Check{"secure-proxy-manager", OK, "ready"}
	}
	return Check{"secure-proxy-manager", Warn, "reachable but not reporting ready"}
}

func checkReachable(ctx context.Context, o Options, name, endpoint string) Check {
	// An unauthenticated GET to an S3 endpoint returns 400/403 — which still
	// proves the service is up and speaking HTTP. Only a transport error is a fail.
	code, _, err := o.get(ctx, endpoint, nil)
	if err != nil {
		return Check{name, Fail, "unreachable: " + err.Error()}
	}
	return Check{name, OK, fmt.Sprintf("reachable (HTTP %d)", code)}
}

func checkTokenStrength(name, token string) Check {
	if n := len(token); n < 32 {
		return Check{name, Fail, fmt.Sprintf("%d chars — must be 32-512 (CertMate rejects shorter and falls back to UNAUTHENTICATED admin)", n)}
	} else if n > 512 {
		return Check{name, Fail, fmt.Sprintf("%d chars — exceeds the 512 limit", n)}
	}
	low := strings.ToLower(token)
	for _, w := range weakTokenPatterns {
		if strings.Contains(low, w) {
			return Check{name, Fail, fmt.Sprintf("contains weak pattern %q — CertMate rejects it on save", w)}
		}
	}
	return Check{name, OK, "length and content acceptable"}
}

func checkCaddyBuild() Check {
	caddy, err := exec.LookPath("caddy")
	if err != nil {
		return Check{"Caddy build", Warn, "caddy not on PATH — needed on the edge host"}
	}
	out, err := exec.Command(caddy, "list-modules").CombinedOutput() // #nosec G204 — resolved via LookPath
	if err != nil {
		return Check{"Caddy build", Warn, "caddy present but `list-modules` failed"}
	}
	mods := string(out)
	waf := strings.Contains(mods, "waf")
	cache := strings.Contains(mods, "cache") || strings.Contains(mods, "souin")
	switch {
	case waf && cache:
		return Check{"Caddy build", OK, "custom build carries caddy-waf + souin"}
	case waf || cache:
		return Check{"Caddy build", Warn, "custom build missing one module (need both caddy-waf and souin)"}
	default:
		return Check{"Caddy build", Warn, "stock caddy — rebuild with caddy-waf + souin via xcaddy"}
	}
}
