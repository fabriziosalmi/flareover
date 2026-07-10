// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package route53

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
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
	defaultEndpoint = "https://route53.amazonaws.com"
	apiVersion      = "/2013-04-01"
	// Route 53 is a global service; SigV4 is always signed against us-east-1.
	signRegion = "us-east-1"
	service    = "route53"
	xmlns      = "https://route53.amazonaws.com/doc/2013-04-01/"
)

// Provisioner reconciles the zone on AWS Route 53 via SigV4-signed API calls. It
// is idempotent: it UPSERTs each (name,type) rrset (create-or-replace), so
// re-running converges. The hosted zone must already exist. Route 53 owns SOA/NS;
// the registrar NS cutover stays a human step.
type Provisioner struct {
	Endpoint     string
	AccessKey    string // AWS_ACCESS_KEY_ID
	SecretKey    string // AWS_SECRET_ACCESS_KEY
	SessionToken string // AWS_SESSION_TOKEN (optional, for temporary creds)
	HTTP         *http.Client
}

// NewProvisioner builds a provisioner with sane defaults.
func NewProvisioner(access, secret, session string) *Provisioner {
	return &Provisioner{
		Endpoint: defaultEndpoint, AccessKey: access, SecretKey: secret, SessionToken: session,
		HTTP: &http.Client{Timeout: 20 * time.Second},
	}
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// do issues a SigV4-signed request and returns (status, body). It never follows
// the AWS control plane beyond the configured endpoint.
func (p *Provisioner) do(ctx context.Context, method, path, rawQuery string, body []byte) (int, []byte, error) {
	u := strings.TrimRight(p.Endpoint, "/") + path
	if rawQuery != "" {
		u += "?" + rawQuery
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	payloadHash := sha256Hex(body)
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if p.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", p.SessionToken)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/xml")
	}

	host := req.URL.Host
	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n", host, payloadHash, amzDate)
	canonicalRequest := strings.Join([]string{method, canonicalURI, rawQuery, canonicalHeaders, signedHeaders, payloadHash}, "\n")
	scope := dateStamp + "/" + signRegion + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, sha256Hex([]byte(canonicalRequest))}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+p.SecretKey), dateStamp)
	kRegion := hmacSHA256(kDate, signRegion)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))
	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", p.AccessKey, scope, signedHeaders, sig))

	resp, err := p.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return resp.StatusCode, raw, fmt.Errorf("route53 %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return resp.StatusCode, raw, nil
}

// hostedZoneID resolves the zone name to its Route 53 hosted-zone id.
func (p *Provisioner) hostedZoneID(ctx context.Context, name string) (string, error) {
	q := url.Values{"dnsname": {zonefile.FQDN(name)}}.Encode()
	_, raw, err := p.do(ctx, http.MethodGet, apiVersion+"/hostedzonesbyname", q, nil)
	if err != nil {
		return "", err
	}
	var out struct {
		Zones []struct {
			ID   string `xml:"Id"`
			Name string `xml:"Name"`
		} `xml:"HostedZones>HostedZone"`
	}
	if err := xml.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("route53: parse hosted zones: %w", err)
	}
	want := zonefile.FQDN(name)
	for _, z := range out.Zones {
		if z.Name == want {
			return strings.TrimPrefix(z.ID, "/hostedzone/"), nil
		}
	}
	return "", fmt.Errorf("route53: no hosted zone found for %q (create it first)", name)
}

// XML shapes for ChangeResourceRecordSets.
type r53RR struct {
	Value string `xml:"Value"`
}
type r53RRSet struct {
	Name    string  `xml:"Name"`
	Type    string  `xml:"Type"`
	TTL     int     `xml:"TTL"`
	Records []r53RR `xml:"ResourceRecords>ResourceRecord"`
}
type r53Change struct {
	Action string   `xml:"Action"`
	RRSet  r53RRSet `xml:"ResourceRecordSet"`
}
type changeRequest struct {
	XMLName xml.Name    `xml:"ChangeResourceRecordSetsRequest"`
	XMLNS   string      `xml:"xmlns,attr"`
	Changes []r53Change `xml:"ChangeBatch>Changes>Change"`
}

// Provision UPSERTs every rrset, so re-running converges with no duplicates.
func (p *Provisioner) Provision(ctx context.Context, z ir.DNSZone) error {
	zoneID, err := p.hostedZoneID(ctx, z.Name)
	if err != nil {
		return err
	}

	type key struct{ name, typ string }
	groups := map[key][]string{}
	ttls := map[key]int{}
	order := []key{}
	for _, r := range z.Records {
		name := zonefile.FQDN(r.Name) // Route 53 uses the fully-qualified, dotted name
		typ := strings.ToUpper(r.Type)
		k := key{name, typ}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
			ttls[k] = zonefile.TTLOrDefault(r.TTL)
		}
		groups[k] = append(groups[k], zonefile.RData(r)) // BIND rdata; Route 53 wants TXT quoted
	}

	req := changeRequest{XMLNS: xmlns}
	for _, k := range order {
		recs := make([]r53RR, 0, len(groups[k]))
		for _, v := range groups[k] {
			recs = append(recs, r53RR{Value: v})
		}
		req.Changes = append(req.Changes, r53Change{
			Action: "UPSERT",
			RRSet:  r53RRSet{Name: k.name, Type: k.typ, TTL: ttls[k], Records: recs},
		})
	}
	body, err := xml.Marshal(req)
	if err != nil {
		return err
	}
	if _, _, err := p.do(ctx, http.MethodPost, apiVersion+"/hostedzone/"+zoneID+"/rrset", "", body); err != nil {
		return fmt.Errorf("change record sets: %w", err)
	}
	return nil
}

// Nameservers returns the zone's delegation set: the NS to publish at the registrar.
func (p *Provisioner) Nameservers(ctx context.Context, zone string) ([]string, error) {
	id, err := p.hostedZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	_, raw, err := p.do(ctx, http.MethodGet, apiVersion+"/hostedzone/"+id, "", nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		NS []string `xml:"DelegationSet>NameServers>NameServer"`
	}
	if err := xml.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out.NS, nil
}
