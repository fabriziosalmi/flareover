// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package clouddns

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fabriziosalmi/flareover/internal/ir"
	"github.com/fabriziosalmi/flareover/internal/target/zonefile"
)

const (
	defaultBaseURL = "https://dns.googleapis.com/dns/v1"
	// scope grants read/write on Cloud DNS resource record sets.
	scope = "https://www.googleapis.com/auth/ndev.clouddns.readwrite"
)

// Provisioner reconciles the zone on Google Cloud DNS. It authenticates as a
// service account (a self-signed JWT exchanged for an OAuth2 access token) and
// is idempotent: it creates each (name,type) rrset and PATCHes it on conflict,
// so re-running converges. The managed zone must already exist. Cloud DNS owns
// SOA/NS; the registrar NS cutover stays a human step.
type Provisioner struct {
	BaseURL  string
	Project  string
	TokenURI string
	HTTP     *http.Client

	clientEmail string
	key         *rsa.PrivateKey

	tok    string
	tokExp time.Time
}

// serviceAccount is the subset of a GCP service-account key JSON we use.
type serviceAccount struct {
	ProjectID   string `json:"project_id"`
	PrivateKey  string `json:"private_key"`
	ClientEmail string `json:"client_email"`
	TokenURI    string `json:"token_uri"`
}

// NewProvisioner parses a service-account key JSON (the content of the file
// GOOGLE_APPLICATION_CREDENTIALS points at) and builds a provisioner. The
// project defaults to the key's project_id; pass a non-empty project to override.
func NewProvisioner(saJSON []byte, project string) (*Provisioner, error) {
	var sa serviceAccount
	if err := json.Unmarshal(saJSON, &sa); err != nil {
		return nil, fmt.Errorf("clouddns: parse service-account JSON: %w", err)
	}
	if sa.ClientEmail == "" || sa.PrivateKey == "" {
		return nil, fmt.Errorf("clouddns: service-account JSON missing client_email/private_key")
	}
	key, err := parsePrivateKey(sa.PrivateKey)
	if err != nil {
		return nil, err
	}
	if project == "" {
		project = sa.ProjectID
	}
	if project == "" {
		return nil, fmt.Errorf("clouddns: no project id (set GOOGLE_CLOUD_PROJECT or use a key with project_id)")
	}
	tokenURI := sa.TokenURI
	if tokenURI == "" {
		tokenURI = "https://oauth2.googleapis.com/token"
	}
	return &Provisioner{
		BaseURL: defaultBaseURL, Project: project, TokenURI: tokenURI,
		clientEmail: sa.ClientEmail, key: key,
		HTTP: &http.Client{Timeout: 20 * time.Second},
	}, nil
}

func parsePrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("clouddns: private_key is not valid PEM")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("clouddns: private key is not RSA")
		}
		return rk, nil
	}
	// Fall back to PKCS#1 for older key encodings.
	rk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("clouddns: parse private key: %w", err)
	}
	return rk, nil
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// token returns a cached access token, minting a fresh one via the JWT-bearer
// grant when needed.
func (p *Provisioner) token(ctx context.Context) (string, error) {
	if p.tok != "" && time.Now().Before(p.tokExp) {
		return p.tok, nil
	}
	now := time.Now()
	header := b64url([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims := fmt.Sprintf(`{"iss":%q,"scope":%q,"aud":%q,"iat":%d,"exp":%d}`,
		p.clientEmail, scope, p.TokenURI, now.Unix(), now.Add(time.Hour).Unix())
	signingInput := header + "." + b64url([]byte(claims))
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("clouddns: sign JWT: %w", err)
	}
	assertion := signingInput + "." + b64url(sig)

	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("clouddns: token exchange: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("clouddns: parse token: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("clouddns: empty access token")
	}
	p.tok = out.AccessToken
	ttl := out.ExpiresIn
	if ttl <= 0 {
		ttl = 3600
	}
	p.tokExp = now.Add(time.Duration(ttl-60) * time.Second)
	return p.tok, nil
}

// do issues an authenticated JSON request and returns (status, body).
func (p *Provisioner) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	tok, err := p.token(ctx)
	if err != nil {
		return 0, nil, err
	}
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(p.BaseURL, "/")+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, raw, nil
}

// managedZone resolves the Cloud DNS managed-zone id (+ its nameservers) for a
// DNS zone by its dnsName.
func (p *Provisioner) managedZone(ctx context.Context, zone string) (name string, ns []string, err error) {
	q := url.Values{"dnsName": {zonefile.FQDN(zone)}}.Encode()
	status, raw, err := p.do(ctx, http.MethodGet, "/projects/"+p.Project+"/managedZones?"+q, nil)
	if err != nil {
		return "", nil, err
	}
	if status >= 300 {
		return "", nil, fmt.Errorf("clouddns: list managed zones: HTTP %d: %s", status, strings.TrimSpace(string(raw)))
	}
	var out struct {
		ManagedZones []struct {
			Name        string   `json:"name"`
			NameServers []string `json:"nameServers"`
		} `json:"managedZones"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", nil, fmt.Errorf("clouddns: parse managed zones: %w", err)
	}
	if len(out.ManagedZones) == 0 {
		return "", nil, fmt.Errorf("clouddns: no managed zone found for %q (create it first)", zone)
	}
	return out.ManagedZones[0].Name, out.ManagedZones[0].NameServers, nil
}

type rrset struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	RRDatas []string `json:"rrdatas"`
}

// Provision reconciles every rrset (create, then patch on conflict), so
// re-running converges with no duplicates.
func (p *Provisioner) Provision(ctx context.Context, z ir.DNSZone) error {
	zoneName, _, err := p.managedZone(ctx, z.Name)
	if err != nil {
		return err
	}

	type key struct{ name, typ string }
	values := map[key][]string{}
	ttls := map[key]int{}
	order := []key{}
	for _, r := range z.Records {
		name := zonefile.FQDN(r.Name) // Cloud DNS uses the fully-qualified, dotted name
		typ := strings.ToUpper(r.Type)
		k := key{name, typ}
		if _, ok := values[k]; !ok {
			order = append(order, k)
			ttls[k] = zonefile.TTLOrDefault(r.TTL)
		}
		values[k] = append(values[k], zonefile.RData(r)) // BIND rdata; Cloud DNS wants TXT quoted
	}

	base := "/projects/" + p.Project + "/managedZones/" + zoneName + "/rrsets"
	for _, k := range order {
		rs := rrset{Name: k.name, Type: k.typ, TTL: ttls[k], RRDatas: values[k]}
		status, raw, err := p.do(ctx, http.MethodPost, base, rs)
		if err != nil {
			return err
		}
		switch {
		case status < 300:
			// created
		case status == http.StatusConflict: // already exists → replace it
			patch := base + "/" + url.PathEscape(k.name) + "/" + k.typ
			st, praw, perr := p.do(ctx, http.MethodPatch, patch, rs)
			if perr != nil {
				return perr
			}
			if st >= 300 {
				return fmt.Errorf("clouddns: patch %s/%s: HTTP %d: %s", k.name, k.typ, st, strings.TrimSpace(string(praw)))
			}
		default:
			return fmt.Errorf("clouddns: create %s/%s: HTTP %d: %s", k.name, k.typ, status, strings.TrimSpace(string(raw)))
		}
	}
	return nil
}

// Nameservers returns the managed zone's delegation set: the NS to publish at
// the registrar.
func (p *Provisioner) Nameservers(ctx context.Context, zone string) ([]string, error) {
	_, ns, err := p.managedZone(ctx, zone)
	return ns, err
}
