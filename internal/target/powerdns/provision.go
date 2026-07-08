// SPDX-License-Identifier: AGPL-3.0-only

package powerdns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/fabriziosalmi/flareover/internal/ir"
)

// Provisioner stands the zone up on a live PowerDNS via its Authoritative HTTP
// API — the step beyond emitting a zone file. It is idempotent: it creates the
// zone if absent, then REPLACEs every rrset, so re-running converges. DNSSEC is
// opt-in and returns the DS records the operator must publish at the registrar
// (flareover never touches the registrar — that stays an explicit human step).
type Provisioner struct {
	BaseURL string // e.g. http://127.0.0.1:8081
	APIKey  string
	Server  string // usually "localhost"
	HTTP    *http.Client
}

// NewProvisioner builds a provisioner with sane defaults.
func NewProvisioner(baseURL, apiKey string) *Provisioner {
	return &Provisioner{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		Server:  "localhost",
		HTTP:    &http.Client{Timeout: 20 * time.Second},
	}
}

func (p *Provisioner) do(ctx context.Context, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", p.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("powerdns %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// rrset is the PowerDNS rrset shape.
type rrset struct {
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	TTL        int       `json:"ttl"`
	ChangeType string    `json:"changetype,omitempty"`
	Records    []pdnsRec `json:"records"`
}

type pdnsRec struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

// Provision creates (if needed) and fully reconciles the zone. nameservers are
// the authoritative NS the zone should carry (the target PowerDNS servers).
func (p *Provisioner) Provision(ctx context.Context, z ir.DNSZone, nameservers []string) error {
	zoneID := fqdn(z.Name)
	rrsets := buildRRSets(z, nameservers)

	// Does the zone already exist?
	err := p.do(ctx, http.MethodGet, "/api/v1/servers/"+p.Server+"/zones/"+zoneID, nil, nil)
	if err != nil {
		// Create it with the full rrset payload. The apex NS records are already
		// in rrsets (buildRRSets), so the "nameservers" field must be omitted —
		// PowerDNS rejects mixing the two.
		create := map[string]any{
			"name":   zoneID,
			"kind":   "Native",
			"rrsets": rrsets,
		}
		if err := p.do(ctx, http.MethodPost, "/api/v1/servers/"+p.Server+"/zones", create, nil); err != nil {
			return fmt.Errorf("create zone: %w", err)
		}
		return nil
	}

	// Exists → REPLACE all rrsets idempotently.
	for i := range rrsets {
		rrsets[i].ChangeType = "REPLACE"
	}
	patch := map[string]any{"rrsets": rrsets}
	if err := p.do(ctx, http.MethodPatch, "/api/v1/servers/"+p.Server+"/zones/"+zoneID, patch, nil); err != nil {
		return fmt.Errorf("patch rrsets: %w", err)
	}
	return nil
}

// EnableDNSSEC activates zone signing and returns the DS records to publish at
// the registrar. Publishing the DS is deliberately left to the human.
func (p *Provisioner) EnableDNSSEC(ctx context.Context, zone string) ([]string, error) {
	zoneID := fqdn(zone)
	key := map[string]any{"keytype": "csk", "active": true}
	if err := p.do(ctx, http.MethodPost, "/api/v1/servers/"+p.Server+"/zones/"+zoneID+"/cryptokeys", key, nil); err != nil {
		return nil, fmt.Errorf("create signing key: %w", err)
	}
	var keys []struct {
		Active bool     `json:"active"`
		DS     []string `json:"ds"`
	}
	if err := p.do(ctx, http.MethodGet, "/api/v1/servers/"+p.Server+"/zones/"+zoneID+"/cryptokeys", nil, &keys); err != nil {
		return nil, err
	}
	var ds []string
	for _, k := range keys {
		if k.Active {
			ds = append(ds, k.DS...)
		}
	}
	return ds, nil
}

// buildRRSets turns the IR zone into PowerDNS rrsets, grouping records by
// (name,type) and adding the apex SOA/NS.
func buildRRSets(z ir.DNSZone, nameservers []string) []rrset {
	origin := fqdn(z.Name)
	type key struct{ name, typ string }
	groups := map[key][]pdnsRec{}
	ttls := map[key]int{}
	order := []key{}

	add := func(name, typ, content string, ttl int) {
		k := key{fqdn(name), strings.ToUpper(typ)}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
			ttls[k] = ttl
		}
		groups[k] = append(groups[k], pdnsRec{Content: content})
	}

	// SOA + NS at the apex.
	if len(nameservers) > 0 {
		add(z.Name, "SOA", fmt.Sprintf("%s hostmaster.%s 1 3600 600 1209600 300", fqdn(nameservers[0]), origin), 300)
		for _, ns := range nameservers {
			add(z.Name, "NS", fqdn(ns), 300)
		}
	}

	for _, r := range z.Records {
		ttl := r.TTL
		if ttl <= 0 {
			ttl = 300
		}
		switch strings.ToUpper(r.Type) {
		case "MX":
			prio := 0
			if r.Priority != nil {
				prio = *r.Priority
			}
			add(r.Name, "MX", fmt.Sprintf("%d %s", prio, fqdn(r.Content)), ttl)
		case "SRV":
			// SRV rdata is "priority weight port target."; Cloudflare keeps the
			// priority in a separate field (prepend it) and the target needs a
			// trailing dot (weight/port/target are already in Content).
			prio := 0
			if r.Priority != nil {
				prio = *r.Priority
			}
			add(r.Name, "SRV", fmt.Sprintf("%d %s", prio, srvTargetFQDN(r.Content)), ttl)
		case "CNAME":
			add(r.Name, "CNAME", fqdn(r.Content), ttl)
		case "TXT":
			add(r.Name, "TXT", fmt.Sprintf("%q", r.Content), ttl)
		default:
			add(r.Name, r.Type, r.Content, ttl)
		}
	}

	out := make([]rrset, 0, len(order))
	for _, k := range order {
		out = append(out, rrset{Name: k.name, Type: k.typ, TTL: ttls[k], Records: groups[k]})
	}
	return out
}

// srvTargetFQDN ensures the SRV target (last field of "weight port target")
// carries a trailing dot, which PowerDNS requires.
func srvTargetFQDN(content string) string {
	fields := strings.Fields(content)
	if len(fields) == 0 {
		return content
	}
	fields[len(fields)-1] = fqdn(fields[len(fields)-1])
	return strings.Join(fields, " ")
}
