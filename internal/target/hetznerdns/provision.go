// SPDX-License-Identifier: AGPL-3.0-only

package hetznerdns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fabriziosalmi/flareover/internal/ir"
	"github.com/fabriziosalmi/flareover/internal/target/zonefile"
)

// defaultBaseURL is the Hetzner DNS public API.
const defaultBaseURL = "https://dns.hetzner.com/api/v1"

// Provisioner reconciles the zone on Hetzner DNS. Hetzner has no per-rrset
// replace, so it is idempotent by creating only records it does not already find
// (keyed on name/type/value), which means re-running converges without
// duplicates and never touches records it did not create. The zone must already
// exist. Hetzner owns SOA/NS; the registrar NS cutover stays a human step.
type Provisioner struct {
	BaseURL string
	Token   string // HETZNER_DNS_TOKEN — sent as "Auth-API-Token: <token>"
	HTTP    *http.Client
}

// NewProvisioner builds a provisioner with sane defaults.
func NewProvisioner(token string) *Provisioner {
	return &Provisioner{BaseURL: defaultBaseURL, Token: token, HTTP: &http.Client{Timeout: 20 * time.Second}}
}

func (p *Provisioner) do(ctx context.Context, method, path string, body, out any) (int, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(p.BaseURL, "/")+path, rdr)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Auth-API-Token", p.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("hetzner %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil && len(raw) > 0 {
		return resp.StatusCode, json.Unmarshal(raw, out)
	}
	return resp.StatusCode, nil
}

// zone resolves a domain to its Hetzner zone id and delegation nameservers.
func (p *Provisioner) zone(ctx context.Context, name string) (id string, ns []string, err error) {
	q := url.Values{"name": {name}}.Encode()
	var out struct {
		Zones []struct {
			ID   string   `json:"id"`
			Name string   `json:"name"`
			NS   []string `json:"ns"`
		} `json:"zones"`
	}
	if _, err := p.do(ctx, http.MethodGet, "/zones?"+q, nil, &out); err != nil {
		return "", nil, err
	}
	for _, z := range out.Zones {
		if z.Name == name {
			return z.ID, z.NS, nil
		}
	}
	return "", nil, fmt.Errorf("hetzner: no zone found for %q (create it first)", name)
}

// recKey normalizes a record identity so trailing-dot / TXT-quote differences in
// what Hetzner echoes back do not cause a spurious duplicate on re-run.
func recKey(name, typ, value string) string {
	v := strings.TrimSuffix(strings.Trim(value, `"`), ".")
	return name + "\x00" + strings.ToUpper(typ) + "\x00" + v
}

type hetznerRecord struct {
	ID     string `json:"id"`
	ZoneID string `json:"zone_id"`
	Type   string `json:"type"`
	Name   string `json:"name"`
	Value  string `json:"value"`
	TTL    int    `json:"ttl,omitempty"`
}

// Provision creates every record not already present, so re-running converges.
func (p *Provisioner) Provision(ctx context.Context, z ir.DNSZone) error {
	zoneID, _, err := p.zone(ctx, z.Name)
	if err != nil {
		return err
	}

	// Existing records → a set of identities we must not re-create.
	var existing struct {
		Records []hetznerRecord `json:"records"`
	}
	if _, err := p.do(ctx, http.MethodGet, "/records?"+url.Values{"zone_id": {zoneID}}.Encode(), nil, &existing); err != nil {
		return err
	}
	have := map[string]bool{}
	for _, r := range existing.Records {
		have[recKey(r.Name, r.Type, r.Value)] = true
	}

	origin := zonefile.FQDN(z.Name)
	for _, r := range z.Records {
		name := zonefile.RecordName(origin, r.Name) // "@" for the apex
		typ := strings.ToUpper(r.Type)
		value := zonefile.RData(r) // BIND rdata; Hetzner wants TXT quoted, MX priority embedded
		if have[recKey(name, typ, value)] {
			continue // already present → idempotent
		}
		body := hetznerRecord{ZoneID: zoneID, Type: typ, Name: name, Value: value, TTL: zonefile.TTLOrDefault(r.TTL)}
		if _, err := p.do(ctx, http.MethodPost, "/records", body, nil); err != nil {
			return fmt.Errorf("create %s/%s: %w", name, typ, err)
		}
		have[recKey(name, typ, value)] = true
	}
	return nil
}

// Nameservers returns the zone's delegation targets to publish at the registrar.
func (p *Provisioner) Nameservers(ctx context.Context, zone string) ([]string, error) {
	_, ns, err := p.zone(ctx, zone)
	return ns, err
}
