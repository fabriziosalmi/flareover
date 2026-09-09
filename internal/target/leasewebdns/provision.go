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
		delName := strings.TrimSuffix(k.name, ".")

		// Leaseweb has no upsert: an rrset is replaced by deleting it and
		// creating the new one, which leaves a window in which the record does
		// not exist. Interrupt the run there — Ctrl-C cancels the in-flight
		// request through rootCtx, or the 20s timeout fires — and the rrset is
		// simply gone, with nothing to put it back. On the apex A record of a
		// live zone that is an outage, not a partial application.
		//
		// So: read the existing set first, and if the create fails, put back
		// exactly what was there. It cannot cover a SIGKILL, but it covers
		// every failure the process survives, which is all of the likely ones.
		var previous []lswRecordSet
		var prior *lswRecordSet
		if status, err := p.do(ctx, http.MethodGet, base+"/"+delName+"/"+k.typ, nil, &prior); err == nil && status < 300 && prior != nil {
			previous = append(previous, *prior)
		}

		if status, err := p.do(ctx, http.MethodDelete, base+"/"+delName+"/"+k.typ, nil, nil); err != nil && status != http.StatusNotFound {
			return fmt.Errorf("delete %s/%s: %w", delName, k.typ, err)
		}
		if _, err := p.do(ctx, http.MethodPost, base, sets[k], nil); err != nil {
			return fmt.Errorf("create %s/%s: %w%s", k.name, k.typ, err, p.restore(ctx, base, previous))
		}
	}
	return nil
}

// restore puts back an rrset that was deleted for a replacement that then
// failed, and reports what happened as a suffix to the caller's error. It uses
// context.WithoutCancel deliberately: the most likely reason the create failed
// is that the context was cancelled, and that is exactly when the record most
// needs putting back.
func (p *Provisioner) restore(ctx context.Context, base string, previous []lswRecordSet) string {
	if len(previous) == 0 {
		return " (no previous rrset to restore)"
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer cancel()
	if _, rerr := p.do(rctx, http.MethodPost, base, previous[0], nil); rerr != nil {
		return fmt.Sprintf(" — AND THE PREVIOUS RECORD COULD NOT BE RESTORED (%v): %s/%s is now absent from the zone, restore it by hand",
			rerr, previous[0].Name, previous[0].Type)
	}
	return " (the previous record was restored)"
}
