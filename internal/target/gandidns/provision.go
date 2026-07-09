// SPDX-License-Identifier: AGPL-3.0-only

package gandidns

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
	"github.com/fabriziosalmi/flareover/internal/target/zonefile"
)

// defaultBaseURL is Gandi's EU LiveDNS endpoint.
const defaultBaseURL = "https://api.gandi.net/v5/livedns"

// Provisioner reconciles the zone on Gandi LiveDNS. It is idempotent: it PUTs
// each (name,type) rrset, which REPLACEs it wholesale, so re-running converges.
// The domain must already be attached to LiveDNS. Gandi owns SOA/NS; the
// registrar NS cutover stays a human step.
type Provisioner struct {
	BaseURL string
	PAT     string // GANDI_PAT — sent as "Authorization: Bearer <pat>"
	HTTP    *http.Client
}

// NewProvisioner builds a provisioner with sane defaults.
func NewProvisioner(pat string) *Provisioner {
	return &Provisioner{BaseURL: defaultBaseURL, PAT: pat, HTTP: &http.Client{Timeout: 20 * time.Second}}
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
	req.Header.Set("Authorization", "Bearer "+p.PAT)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("gandi %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil && len(raw) > 0 {
		return resp.StatusCode, json.Unmarshal(raw, out)
	}
	return resp.StatusCode, nil
}

// Provision PUTs one rrset per (name,type), each an idempotent REPLACE.
func (p *Provisioner) Provision(ctx context.Context, z ir.DNSZone) error {
	origin := zonefile.FQDN(z.Name)
	type key struct{ name, typ string }
	values := map[key][]string{}
	ttls := map[key]int{}
	order := []key{}
	for _, r := range z.Records {
		name := zonefile.RecordName(origin, r.Name) // "@" for the apex
		typ := strings.ToUpper(r.Type)
		k := key{name, typ}
		if _, ok := values[k]; !ok {
			order = append(order, k)
			ttls[k] = gandiTTL(r.TTL)
		}
		values[k] = append(values[k], zonefile.RData(r)) // BIND rdata; Gandi wants TXT quoted
	}

	for _, k := range order {
		body := map[string]any{"rrset_ttl": ttls[k], "rrset_values": values[k]}
		// DNS names are URL-path-safe (labels, "@", "*"), so no escaping is needed.
		path := "/domains/" + z.Name + "/records/" + k.name + "/" + k.typ
		if _, err := p.do(ctx, http.MethodPut, path, body, nil); err != nil {
			return fmt.Errorf("put %s/%s: %w", k.name, k.typ, err)
		}
	}
	return nil
}

// Nameservers returns the delegation targets to publish at the registrar.
func (p *Provisioner) Nameservers(ctx context.Context, zone string) ([]string, error) {
	var ns []string
	if _, err := p.do(ctx, http.MethodGet, "/domains/"+zone+"/nameservers", nil, &ns); err != nil {
		return nil, err
	}
	return ns, nil
}

// gandiTTL clamps to Gandi's minimum rrset_ttl of 300 seconds.
func gandiTTL(ttl int) int {
	t := zonefile.TTLOrDefault(ttl)
	if t < 300 {
		t = 300
	}
	return t
}
