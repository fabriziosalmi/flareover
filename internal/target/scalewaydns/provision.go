// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package scalewaydns

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

const defaultBaseURL = "https://api.scaleway.com"

// Provisioner stands the zone up on Scaleway's managed DNS via the Domains API
// (v2beta1). It is idempotent: it creates the zone if absent (an already-existing
// zone is not an error), then issues one `set` change per (name,type), which
// REPLACEs that rrset, so re-running converges, with no duplicate records.
// Scaleway owns SOA/NS; the registrar NS cutover stays an explicit human step
// (Nameservers returns the delegation targets to publish).
type Provisioner struct {
	BaseURL   string // default https://api.scaleway.com
	SecretKey string // X-Auth-Token: SCW_SECRET_KEY
	ProjectID string // SCW_DEFAULT_PROJECT_ID (needed to create the zone)
	HTTP      *http.Client
}

// NewProvisioner builds a provisioner with sane defaults.
func NewProvisioner(secretKey, projectID string) *Provisioner {
	return &Provisioner{
		BaseURL:   defaultBaseURL,
		SecretKey: secretKey,
		ProjectID: projectID,
		HTTP:      &http.Client{Timeout: 20 * time.Second},
	}
}

// do issues one request and returns the HTTP status alongside any error, so the
// caller can treat an already-exists conflict on create as success.
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
	req.Header.Set("X-Auth-Token", p.SecretKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("scaleway %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil && len(raw) > 0 {
		return resp.StatusCode, json.Unmarshal(raw, out)
	}
	return resp.StatusCode, nil
}

// Provision creates (if needed) and fully reconciles the zone.
func (p *Provisioner) Provision(ctx context.Context, z ir.DNSZone) error {
	// 1) Create the zone. An already-existing zone is not an error. Scaleway
	// signals that with 409, and some paths word it in the body, so tolerate both.
	create := map[string]any{"domain": z.Name, "subdomain": "", "project_id": p.ProjectID}
	if status, err := p.do(ctx, http.MethodPost, "/domain/v2beta1/dns-zones", create, nil); err != nil {
		if status != http.StatusConflict && !alreadyExists(err) {
			return fmt.Errorf("create dns zone: %w", err)
		}
	}

	// 2) Set every rrset idempotently. disallow_new_zone_creation is true here
	// because step 1 already guaranteed the zone exists.
	patch := map[string]any{
		"changes":                    buildChanges(z),
		"disallow_new_zone_creation": true,
	}
	if _, err := p.do(ctx, http.MethodPatch, "/domain/v2beta1/dns-zones/"+z.Name+"/records", patch, nil); err != nil {
		return fmt.Errorf("set records: %w", err)
	}
	return nil
}

// Nameservers returns the delegation targets to publish at the registrar.
func (p *Provisioner) Nameservers(ctx context.Context, zone string) ([]string, error) {
	var out struct {
		Ns []struct {
			Name string `json:"name"`
		} `json:"ns"`
	}
	if _, err := p.do(ctx, http.MethodGet, "/domain/v2beta1/dns-zones/"+zone+"/nameservers", nil, &out); err != nil {
		return nil, err
	}
	ns := make([]string, 0, len(out.Ns))
	for _, n := range out.Ns {
		ns = append(ns, n.Name)
	}
	return ns, nil
}

func alreadyExists(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "already exists") || strings.Contains(s, "already have")
}

// scwRecord mirrors the Scaleway Domains API record: priority is a first-class
// field, so (unlike BIND) it never lives inside the rdata string.
type scwRecord struct {
	Data     string `json:"data"`
	Name     string `json:"name"`
	Priority uint32 `json:"priority"`
	TTL      uint32 `json:"ttl"`
	Type     string `json:"type"`
}

type scwIDFields struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type scwChange struct {
	Set struct {
		IDFields scwIDFields `json:"id_fields"`
		Records  []scwRecord `json:"records"`
	} `json:"set"`
}

// buildChanges groups the IR records by (name,type) and emits one idempotent
// `set` change per group, so each rrset is REPLACEd wholesale.
func buildChanges(z ir.DNSZone) []scwChange {
	origin := zonefile.FQDN(z.Name)
	type key struct{ name, typ string }
	groups := map[key][]scwRecord{}
	order := []key{}

	for _, r := range z.Records {
		typ := strings.ToUpper(r.Type)
		name := scwName(origin, r.Name)
		k := key{name, typ}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], scwRecord{
			Data:     scwData(r),
			Name:     name,
			Priority: uint32(zonefile.Priority(r)),
			TTL:      ttlOrDefault(r.TTL),
			Type:     typ,
		})
	}

	out := make([]scwChange, 0, len(order))
	for _, k := range order {
		var ch scwChange
		ch.Set.IDFields = scwIDFields{Name: k.name, Type: k.typ}
		ch.Set.Records = groups[k]
		out = append(out, ch)
	}
	return out
}

// scwData renders the record value the way the Scaleway API wants it: a bare
// value (no BIND quoting), FQDNs dotted, priority carried on the field not here.
func scwData(r ir.DNSRecord) string {
	switch strings.ToUpper(r.Type) {
	case "CNAME", "MX", "NS":
		return zonefile.FQDN(r.Content)
	case "SRV":
		return zonefile.SRVTargetFQDN(r.Content) // "weight port target." (priority is a separate field)
	default: // A, AAAA, TXT, CAA, ... take the raw value
		return r.Content
	}
}

// scwName renders a record name relative to the zone; Scaleway uses the empty
// string for the apex (not "@").
func scwName(origin, name string) string {
	n := zonefile.FQDN(name)
	if n == origin {
		return ""
	}
	return strings.TrimSuffix(n, "."+origin)
}

func ttlOrDefault(ttl int) uint32 {
	if ttl <= 0 {
		return 300
	}
	return uint32(ttl)
}
