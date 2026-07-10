// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package azuredns

import (
	"bytes"
	"context"
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

const (
	defaultBaseURL  = "https://management.azure.com"
	defaultAuthHost = "https://login.microsoftonline.com"
	apiVersion      = "2018-05-01"
	scope           = "https://management.azure.com/.default"
)

// Provisioner reconciles the zone on Azure DNS via the Resource Manager API. It
// authenticates with an AAD client-credentials grant and is idempotent: it PUTs
// each (name,type) recordset (create-or-replace), so re-running converges. The
// DNS zone must already exist in the resource group. Azure owns SOA/NS; the
// registrar NS cutover stays a human step.
type Provisioner struct {
	BaseURL       string
	AuthHost      string
	Tenant        string
	ClientID      string
	ClientSecret  string
	Subscription  string
	ResourceGroup string
	HTTP          *http.Client

	tok    string
	tokExp time.Time
}

// NewProvisioner builds a provisioner. All credentials come from the environment.
func NewProvisioner(tenant, clientID, clientSecret, subscription, resourceGroup string) *Provisioner {
	return &Provisioner{
		BaseURL: defaultBaseURL, AuthHost: defaultAuthHost,
		Tenant: tenant, ClientID: clientID, ClientSecret: clientSecret,
		Subscription: subscription, ResourceGroup: resourceGroup,
		HTTP: &http.Client{Timeout: 20 * time.Second},
	}
}

// token returns a cached AAD access token, minting a fresh one via the
// client-credentials grant when needed.
func (p *Provisioner) token(ctx context.Context) (string, error) {
	if p.tok != "" && time.Now().Before(p.tokExp) {
		return p.tok, nil
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {p.ClientID},
		"client_secret": {p.ClientSecret},
		"scope":         {scope},
	}
	u := strings.TrimRight(p.AuthHost, "/") + "/" + p.Tenant + "/oauth2/v2.0/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
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
		return "", fmt.Errorf("azuredns: token exchange: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("azuredns: parse token: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("azuredns: empty access token")
	}
	p.tok = out.AccessToken
	ttl := out.ExpiresIn
	if ttl <= 0 {
		ttl = 3600
	}
	p.tokExp = time.Now().Add(time.Duration(ttl-60) * time.Second)
	return p.tok, nil
}

// do issues an authenticated JSON request (api-version appended) and returns
// (status, body).
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
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	u := strings.TrimRight(p.BaseURL, "/") + path + sep + "api-version=" + apiVersion
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
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

func (p *Provisioner) zoneBase() string {
	return "/subscriptions/" + p.Subscription + "/resourceGroups/" + p.ResourceGroup +
		"/providers/Microsoft.Network/dnsZones/"
}

// recordProps builds the Azure type-specific recordset properties for one
// (name,type) group. Unknown types are rejected rather than silently dropped:
// a record we cannot map faithfully must surface, never vanish.
func recordProps(typ string, ttl int, recs []ir.DNSRecord) (map[string]any, error) {
	props := map[string]any{"TTL": ttl}
	switch typ {
	case "A":
		arr := make([]map[string]any, 0, len(recs))
		for _, r := range recs {
			arr = append(arr, map[string]any{"ipv4Address": r.Content})
		}
		props["ARecords"] = arr
	case "AAAA":
		arr := make([]map[string]any, 0, len(recs))
		for _, r := range recs {
			arr = append(arr, map[string]any{"ipv6Address": r.Content})
		}
		props["AAAARecords"] = arr
	case "CNAME": // Azure CNAME is single-valued
		props["CNAMERecord"] = map[string]any{"cname": strings.TrimSuffix(recs[0].Content, ".")}
	case "MX":
		arr := make([]map[string]any, 0, len(recs))
		for _, r := range recs {
			arr = append(arr, map[string]any{"preference": zonefile.Priority(r), "exchange": strings.TrimSuffix(r.Content, ".")})
		}
		props["MXRecords"] = arr
	case "TXT":
		arr := make([]map[string]any, 0, len(recs))
		for _, r := range recs {
			arr = append(arr, map[string]any{"value": []string{r.Content}})
		}
		props["TXTRecords"] = arr
	case "NS":
		arr := make([]map[string]any, 0, len(recs))
		for _, r := range recs {
			arr = append(arr, map[string]any{"nsdname": zonefile.FQDN(r.Content)})
		}
		props["NSRecords"] = arr
	case "PTR":
		arr := make([]map[string]any, 0, len(recs))
		for _, r := range recs {
			arr = append(arr, map[string]any{"ptrdname": zonefile.FQDN(r.Content)})
		}
		props["PTRRecords"] = arr
	case "SRV":
		arr := make([]map[string]any, 0, len(recs))
		for _, r := range recs {
			f := strings.Fields(r.Content) // "weight port target"
			if len(f) != 3 {
				return nil, fmt.Errorf("azuredns: SRV content %q is not \"weight port target\"", r.Content)
			}
			weight, _ := strconv.Atoi(f[0])
			port, _ := strconv.Atoi(f[1])
			arr = append(arr, map[string]any{
				"priority": zonefile.Priority(r), "weight": weight, "port": port,
				"target": strings.TrimSuffix(f[2], "."),
			})
		}
		props["SRVRecords"] = arr
	case "CAA":
		arr := make([]map[string]any, 0, len(recs))
		for _, r := range recs {
			f := strings.SplitN(r.Content, " ", 3) // `0 issue "letsencrypt.org"`
			if len(f) != 3 {
				return nil, fmt.Errorf("azuredns: CAA content %q is not \"flags tag value\"", r.Content)
			}
			flags, _ := strconv.Atoi(f[0])
			arr = append(arr, map[string]any{"flags": flags, "tag": f[1], "value": strings.Trim(f[2], `"`)})
		}
		props["caaRecords"] = arr
	default:
		return nil, fmt.Errorf("azuredns: unsupported record type %q for %d record(s): map it by hand in the Azure portal", typ, len(recs))
	}
	return props, nil
}

// Provision PUTs one recordset per (name,type), each an idempotent create-or-replace.
func (p *Provisioner) Provision(ctx context.Context, z ir.DNSZone) error {
	origin := zonefile.FQDN(z.Name)
	type key struct{ name, typ string }
	groups := map[key][]ir.DNSRecord{}
	ttls := map[key]int{}
	order := []key{}
	for _, r := range z.Records {
		name := zonefile.RecordName(origin, r.Name) // "@" for the apex
		typ := strings.ToUpper(r.Type)
		k := key{name, typ}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
			ttls[k] = zonefile.TTLOrDefault(r.TTL)
		}
		groups[k] = append(groups[k], r)
	}

	zb := p.zoneBase() + z.Name + "/"
	for _, k := range order {
		props, err := recordProps(k.typ, ttls[k], groups[k])
		if err != nil {
			return err
		}
		body := map[string]any{"properties": props}
		// DNS relative names are path-safe (labels, "@", "*"); no escaping needed.
		path := zb + k.typ + "/" + k.name
		status, raw, err := p.do(ctx, http.MethodPut, path, body)
		if err != nil {
			return err
		}
		if status >= 300 {
			return fmt.Errorf("azuredns: put %s/%s: HTTP %d: %s", k.name, k.typ, status, strings.TrimSpace(string(raw)))
		}
	}
	return nil
}

// Nameservers returns the zone's delegation set: the NS to publish at the registrar.
func (p *Provisioner) Nameservers(ctx context.Context, zone string) ([]string, error) {
	status, raw, err := p.do(ctx, http.MethodGet, p.zoneBase()+zone, nil)
	if err != nil {
		return nil, err
	}
	if status >= 300 {
		return nil, fmt.Errorf("azuredns: get zone: HTTP %d: %s", status, strings.TrimSpace(string(raw)))
	}
	var out struct {
		Properties struct {
			NameServers []string `json:"nameServers"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out.Properties.NameServers, nil
}
