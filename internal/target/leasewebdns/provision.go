// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package leasewebdns

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

// defaultBaseURL is the Leaseweb Domains API root.
const defaultBaseURL = "https://api.leaseweb.com/hosting/v2/domains"

// Provisioner reconciles the zone on Leaseweb DNS. It is idempotent: per
// (name,type) it deletes the existing resource record set (a missing one is
// fine) and recreates it, so re-running converges. The Leaseweb DNS domain must
// already exist. Leaseweb owns SOA/NS; the registrar NS cutover stays a human
// step.
type Provisioner struct {
	BaseURL string
	APIKey  string // LEASEWEB_API_KEY: sent as the "X-Lsw-Auth" header
	HTTP    *http.Client
}

// NewProvisioner builds a provisioner with sane defaults.
func NewProvisioner(apiKey string) *Provisioner {
	return &Provisioner{BaseURL: defaultBaseURL, APIKey: apiKey, HTTP: &http.Client{Timeout: 20 * time.Second}}
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
	req.Header.Set("X-Lsw-Auth", p.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("leaseweb %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil && len(raw) > 0 {
		return resp.StatusCode, json.Unmarshal(raw, out)
	}
	return resp.StatusCode, nil
}

type lswRecordSet struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Content []string `json:"content"`
	TTL     int      `json:"ttl"`
}

// Provision reconciles each (name,type) rrset: delete-then-create (REPLACE).
func (p *Provisioner) Provision(ctx context.Context, z ir.DNSZone) error {
	type key struct{ name, typ string }
	sets := map[key]*lswRecordSet{}
	order := []key{}
	for _, r := range z.Records {
		typ := strings.ToUpper(r.Type)
		name := zonefile.FQDN(r.Name) // Leaseweb's create body uses the fully-qualified, dotted name
		k := key{name, typ}
		if sets[k] == nil {
			sets[k] = &lswRecordSet{Name: name, Type: typ, TTL: zonefile.TTLOrDefault(r.TTL)}
			order = append(order, k)
		}
		sets[k].Content = append(sets[k].Content, zonefile.APIValue(r))
	}

	base := "/" + z.Name + "/resourceRecordSets"
	for _, k := range order {
		// Delete the existing set first (a 404 just means there was none), then
		// create the desired one. The delete path uses the undotted name.
		delName := strings.TrimSuffix(k.name, ".")
		if status, err := p.do(ctx, http.MethodDelete, base+"/"+delName+"/"+k.typ, nil, nil); err != nil && status != http.StatusNotFound {
			return fmt.Errorf("delete %s/%s: %w", delName, k.typ, err)
		}
		if _, err := p.do(ctx, http.MethodPost, base, sets[k], nil); err != nil {
			return fmt.Errorf("create %s/%s: %w", k.name, k.typ, err)
		}
	}
	return nil
}
