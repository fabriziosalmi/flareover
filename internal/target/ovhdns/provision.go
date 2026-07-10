// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package ovhdns

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fabriziosalmi/flareover/internal/ir"
	"github.com/fabriziosalmi/flareover/internal/target/zonefile"
)

// defaultBaseURL is OVH's EU API endpoint: the sovereign choice (ca/us endpoints
// would put the control plane under a non-EU jurisdiction).
const defaultBaseURL = "https://eu.api.ovh.com/1.0"

// Provisioner reconciles the zone on OVHcloud's managed DNS via the OVH API. It
// is idempotent: per (subDomain,fieldType) it deletes the existing records and
// recreates the desired set (a REPLACE), then triggers a zone refresh so the
// change goes live. The OVH DNS zone must already exist. OVH owns SOA/NS; the
// registrar NS cutover stays a human step.
//
// Auth is OVH's signed-request scheme (application key/secret + consumer key);
// implemented here in stdlib so flareover keeps its zero-dependency build.
type Provisioner struct {
	BaseURL     string
	AppKey      string // OVH_APPLICATION_KEY
	AppSecret   string // OVH_APPLICATION_SECRET
	ConsumerKey string // OVH_CONSUMER_KEY
	HTTP        *http.Client
	delta       *int64 // localUnix - serverUnix, fetched once from /auth/time
}

// NewProvisioner builds a provisioner with sane defaults.
func NewProvisioner(appKey, appSecret, consumerKey string) *Provisioner {
	return &Provisioner{
		BaseURL:     defaultBaseURL,
		AppKey:      appKey,
		AppSecret:   appSecret,
		ConsumerKey: consumerKey,
		HTTP:        &http.Client{Timeout: 20 * time.Second},
	}
}

func (p *Provisioner) base() string { return strings.TrimRight(p.BaseURL, "/") }

// sign builds the OVH request signature: "$1$" + sha1(secret+consumer+METHOD+
// fullURL+body+timestamp), fields joined by '+'. Pure, so it can be pinned.
func sign(secret, consumer, method, fullURL, body string, ts int64) string {
	h := sha1.New()
	fmt.Fprintf(h, "%s+%s+%s+%s+%s+%d", secret, consumer, method, fullURL, body, ts)
	return fmt.Sprintf("$1$%x", h.Sum(nil))
}

// serverTime reads OVH server time (unauthenticated) to sign against its clock.
func (p *Provisioner) serverTime(ctx context.Context) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.base()+"/auth/time", nil)
	if err != nil {
		return 0, err
	}
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
	if resp.StatusCode >= 300 {
		return 0, fmt.Errorf("ovh /auth/time: HTTP %d", resp.StatusCode)
	}
	var t int64
	if err := json.Unmarshal(bytes.TrimSpace(raw), &t); err != nil {
		return 0, fmt.Errorf("ovh /auth/time: %w", err)
	}
	return t, nil
}

func (p *Provisioner) timestamp(ctx context.Context) (int64, error) {
	if p.delta == nil {
		st, err := p.serverTime(ctx)
		if err != nil {
			return 0, err
		}
		d := time.Now().Unix() - st
		p.delta = &d
	}
	return time.Now().Unix() - *p.delta, nil
}

// signedDo issues one authenticated request. path is relative to the API root
// (e.g. "/domain/zone/example.com/record"); it may already carry a query string.
func (p *Provisioner) signedDo(ctx context.Context, method, path string, body, out any) (int, error) {
	var bodyBytes []byte
	if body != nil {
		var err error
		if bodyBytes, err = json.Marshal(body); err != nil {
			return 0, err
		}
	}
	fullURL := p.base() + path
	ts, err := p.timestamp(ctx)
	if err != nil {
		return 0, err
	}
	var rdr io.Reader
	if bodyBytes != nil {
		rdr = bytes.NewReader(bodyBytes)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return 0, err
	}
	req.Header.Set("X-Ovh-Application", p.AppKey)
	req.Header.Set("X-Ovh-Consumer", p.ConsumerKey)
	req.Header.Set("X-Ovh-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Ovh-Signature", sign(p.AppSecret, p.ConsumerKey, method, fullURL, string(bodyBytes), ts))
	req.Header.Set("Accept", "application/json")
	if bodyBytes != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("ovh %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil && len(raw) > 0 {
		return resp.StatusCode, json.Unmarshal(raw, out)
	}
	return resp.StatusCode, nil
}

type ovhRecordBody struct {
	FieldType string `json:"fieldType"`
	SubDomain string `json:"subDomain"`
	Target    string `json:"target"`
	TTL       int    `json:"ttl"`
}

// Provision reconciles the zone: REPLACE each rrset, then refresh.
func (p *Provisioner) Provision(ctx context.Context, z ir.DNSZone) error {
	origin := zonefile.FQDN(z.Name)
	type key struct{ sub, typ string }
	groups := map[key][]ovhRecordBody{}
	order := []key{}
	for _, r := range z.Records {
		typ := strings.ToUpper(r.Type)
		sub := ovhSubDomain(origin, r.Name)
		k := key{sub, typ}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], ovhRecordBody{FieldType: typ, SubDomain: sub, Target: zonefile.APIValue(r), TTL: zonefile.TTLOrDefault(r.TTL)})
	}

	base := "/domain/zone/" + z.Name
	for _, k := range order {
		// Existing records for this (subDomain,fieldType) → delete, so the POSTs
		// below leave exactly the desired set (idempotent REPLACE).
		q := base + "/record?fieldType=" + url.QueryEscape(k.typ) + "&subDomain=" + url.QueryEscape(k.sub)
		var ids []int64
		if _, err := p.signedDo(ctx, http.MethodGet, q, nil, &ids); err != nil {
			return fmt.Errorf("list %q/%s: %w", k.sub, k.typ, err)
		}
		for _, id := range ids {
			if _, err := p.signedDo(ctx, http.MethodDelete, base+"/record/"+strconv.FormatInt(id, 10), nil, nil); err != nil {
				return fmt.Errorf("delete record %d: %w", id, err)
			}
		}
		for _, body := range groups[k] {
			if _, err := p.signedDo(ctx, http.MethodPost, base+"/record", body, nil); err != nil {
				return fmt.Errorf("create %q/%s: %w", k.sub, k.typ, err)
			}
		}
	}

	// OVH stages record changes; the refresh publishes them.
	if _, err := p.signedDo(ctx, http.MethodPost, base+"/refresh", nil, nil); err != nil {
		return fmt.Errorf("refresh zone: %w", err)
	}
	return nil
}

// Nameservers returns the delegation targets to publish at the registrar.
func (p *Provisioner) Nameservers(ctx context.Context, zone string) ([]string, error) {
	var out struct {
		NameServers []string `json:"nameServers"`
	}
	if _, err := p.signedDo(ctx, http.MethodGet, "/domain/zone/"+zone, nil, &out); err != nil {
		return nil, err
	}
	return out.NameServers, nil
}

// ovhSubDomain renders a record name relative to the zone; OVH uses the empty
// string for the apex.
func ovhSubDomain(origin, name string) string {
	n := zonefile.FQDN(name)
	if n == origin {
		return ""
	}
	return strings.TrimSuffix(n, "."+origin)
}
