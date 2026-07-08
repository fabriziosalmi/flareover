// Package certmate is the certificate adapter: it drives a CertMate instance to
// issue certs via DNS-01, which is what unlocks the two things Caddy's built-in
// HTTP-01 cannot do — wildcard certificates and an EU certificate authority
// (Actalis). flareover asks CertMate to issue through PowerDNS DNS-01, then
// pulls the material for the edge to consume. This closes the wildcard gap the
// real cutover exposed.
package certmate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fabriziosalmi/flareover/internal/ir"
)

// apiError carries the HTTP status so callers can make idempotency decisions
// (e.g. treat 409 "already exists" as success) instead of string-matching.
type apiError struct {
	Method, Path, Body string
	Status             int
}

func (e *apiError) Error() string {
	return fmt.Sprintf("certmate %s %s: HTTP %d: %s", e.Method, e.Path, e.Status, e.Body)
}

// Client talks to a CertMate REST API.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// NewClient builds a CertMate client. The HTTP timeout is deliberately generous
// (5 min): CertMate runs certbot DNS-01 issuance SYNCHRONOUSLY inside the
// create request — the POST does not return until the challenge has propagated
// and Let's Encrypt has validated and signed, which routinely exceeds 30s. A
// tight timeout makes flareover report failure on a cert that in fact issues.
// Download/health calls return in milliseconds, so the high ceiling never
// costs them anything; per-call deadlines still come from the caller's context.
func NewClient(baseURL, token string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), Token: token, HTTP: &http.Client{Timeout: 5 * time.Minute}}
}

func (c *Client) req(ctx context.Context, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 300 {
		return &apiError{Method: method, Path: path, Status: resp.StatusCode, Body: strings.TrimSpace(string(raw))}
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// IssueRequest describes a certificate to obtain.
type IssueRequest struct {
	Domain      string   // primary domain (may be a wildcard, e.g. *.example.com)
	SANs        []string // additional names
	DNSProvider string   // "powerdns" (DNS-01 → wildcard-capable)
	CA          string   // "letsencrypt" | "actalis" (EU CA)
	AccountID   string   // CertMate DNS-provider account id
}

// Material is the issued certificate, ready for the edge to install.
type Material struct {
	FullchainPEM  string `json:"fullchain_pem"`
	PrivateKeyPEM string `json:"private_key_pem"`
	ChainPEM      string `json:"chain_pem"`
	CertPEM       string `json:"cert_pem"`
}

// Issue requests a certificate via DNS-01, which makes wildcard and EU-CA
// issuance possible. It is idempotent: CertMate's create endpoint rejects an
// existing domain with 409 CERTIFICATE_ALREADY_EXISTS rather than renewing, so
// a re-run on an already-issued cert is the desired state already met — treated
// here as success. (To force a refresh, use the renew/reissue endpoints.)
func (c *Client) Issue(ctx context.Context, r IssueRequest) error {
	if r.DNSProvider == "" {
		r.DNSProvider = "powerdns"
	}
	if r.CA == "" {
		r.CA = "letsencrypt"
	}
	body := map[string]any{
		"domain":       r.Domain,
		"san_domains":  r.SANs,
		"dns_provider": r.DNSProvider,
		"ca_provider":  r.CA,
	}
	if r.AccountID != "" {
		body["account_id"] = r.AccountID
	}
	err := c.req(ctx, http.MethodPost, "/api/certificates/create", body, nil)
	var ae *apiError
	if errors.As(err, &ae) && ae.Status == http.StatusConflict &&
		strings.Contains(ae.Body, "ALREADY_EXISTS") {
		return nil // cert already present → idempotent no-op
	}
	return err
}

// Download fetches the issued material for a domain (operator token required for
// the private key).
func (c *Client) Download(ctx context.Context, domain string) (Material, error) {
	var m Material
	err := c.req(ctx, http.MethodGet, "/api/certificates/"+url.PathEscape(domain)+"/download?format=json", nil, &m)
	return m, err
}

// EnsureReady polls until the domain's material is downloadable or the deadline
// passes — DNS-01 issuance is asynchronous (the challenge must propagate).
func (c *Client) EnsureReady(ctx context.Context, domain string, timeout time.Duration) (Material, error) {
	deadline := time.Now().Add(timeout)
	var last error
	for {
		m, err := c.Download(ctx, domain)
		if err == nil && m.FullchainPEM != "" && m.PrivateKeyPEM != "" {
			return m, nil
		}
		last = err
		if time.Now().After(deadline) {
			return Material{}, fmt.Errorf("certmate: %s not ready before deadline: %v", domain, last)
		}
		select {
		case <-ctx.Done():
			return Material{}, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

// PlanCerts decides which certificates to request for a migration plan. It
// prefers ONE wildcard cert per apex when the plan needs it (covering all
// subdomains via DNS-01), plus the apex; otherwise a cert per site host. This is
// exactly the split HTTP-01 gets wrong — wildcards must go through DNS-01.
//
// dnsProvider selects which authoritative DNS the DNS-01 challenge is written
// to. It defaults to "powerdns" (the target), but during migration — before the
// NS have been cut over — the zone still resolves at the SOURCE, so the
// bootstrap cert must be issued through the source's DNS provider (e.g.
// "cloudflare"). After the NS move to PowerDNS, re-issue with "powerdns".
func PlanCerts(p ir.Plan, ca, accountID, dnsProvider string) []IssueRequest {
	if dnsProvider == "" {
		dnsProvider = "powerdns"
	}
	apex := p.Zone
	wildcard := false
	hosts := map[string]bool{}
	for _, s := range p.Sites {
		if strings.HasPrefix(s.Host, "*.") {
			wildcard = true
		} else {
			hosts[s.Host] = true
		}
		if s.TLS.Wildcard {
			wildcard = true
		}
	}
	var out []IssueRequest
	if wildcard {
		// One DNS-01 wildcard cert covering the apex and every subdomain.
		out = append(out, IssueRequest{
			Domain: "*." + apex, SANs: []string{apex},
			DNSProvider: dnsProvider, CA: ca, AccountID: accountID,
		})
		return out
	}
	for h := range hosts {
		out = append(out, IssueRequest{Domain: h, DNSProvider: dnsProvider, CA: ca, AccountID: accountID})
	}
	return out
}
