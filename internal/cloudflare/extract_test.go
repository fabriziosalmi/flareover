// SPDX-License-Identifier: AGPL-3.0-only

package cloudflare

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testZoneID = "0123456789abcdef0123456789abcdef"

// env wraps a result in the standard Cloudflare success envelope.
func env(result string) string { return `{"success":true,"result":` + result + `}` }

// envPaged wraps a paged result with result_info.
func envPaged(result string, page, total int) string {
	return fmt.Sprintf(`{"success":true,"result":%s,"result_info":{"page":%d,"total_pages":%d}}`, result, page, total)
}

type resp struct {
	status int // 0 → 200
	body   string
}

// mockCF serves the routed paths; any unrouted path returns result:null, which
// decodes cleanly into an empty slice or a zero struct — so optional surfaces
// simply come back empty (no warning), and each test routes only what it cares
// about.
func mockCF(t *testing.T, routes map[string]resp) (*Client, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if rr, ok := routes[r.URL.Path]; ok {
			if rr.status != 0 {
				w.WriteHeader(rr.status)
			}
			_, _ = w.Write([]byte(rr.body))
			return
		}
		_, _ = w.Write([]byte(env("null")))
	}))
	c := NewClient("tok")
	c.BaseURL = srv.URL
	return c, srv.Close
}

func base(id string) string { return "/zones/" + id }

// happyRoutes is a realistic zone: DNS + a WAF ruleset + a transform ruleset +
// a page rule + settings (SSL, HSTS, DNSSEC).
func happyRoutes(id string) map[string]resp {
	return map[string]resp{
		base(id): {body: env(fmt.Sprintf(`{"id":%q,"name":"example.com","status":"active","name_servers":["a.ns.cloudflare.com"]}`, id))},
		base(id) + "/settings": {body: env(`[
			{"id":"ssl","value":"flexible"},
			{"id":"always_use_https","value":"on"},
			{"id":"security_header","value":{"strict_transport_security":{"enabled":true,"max_age":31536000,"include_subdomains":true}}}
		]`)},
		base(id) + "/dnssec":      {body: env(`{"status":"active"}`)},
		base(id) + "/dns_records": {body: envPaged(`[{"type":"A","name":"example.com","content":"192.0.2.1","ttl":1,"proxied":true},{"type":"MX","name":"example.com","content":"mail.example.com","ttl":300,"priority":10}]`, 1, 1)},
		base(id) + "/pagerules":   {body: env(`[{"targets":[{"target":"url","constraint":{"value":"example.com/old/*"}}],"actions":[{"id":"forwarding_url","value":{"url":"https://example.com/new","status_code":301}}],"priority":1,"status":"active"}]`)},
		base(id) + "/rulesets": {body: env(`[
			{"id":"rs_fw","name":"default","phase":"http_request_firewall_custom","kind":"zone"},
			{"id":"rs_tf","name":"transform","phase":"http_response_headers_transform","kind":"zone"},
			{"id":"rs_managed_catalog","name":"CF catalog","phase":"http_request_firewall_custom","kind":"managed"}
		]`)},
		base(id) + "/rulesets/rs_fw": {body: env(`{"rules":[{"description":"block bad UA","expression":"http.user_agent eq \"badbot\"","action":"block","enabled":true}]}`)},
		base(id) + "/rulesets/rs_tf": {body: env(`{"rules":[{"description":"sec headers","expression":"true","action":"rewrite","action_parameters":{"headers":{"X-Frame-Options":{"operation":"set","value":"DENY"}}},"enabled":true}]}`)},
	}
}

func TestExtractHappyPath(t *testing.T) {
	c, done := mockCF(t, happyRoutes(testZoneID))
	defer done()

	s, err := c.Extract(context.Background(), testZoneID)
	if err != nil {
		t.Fatal(err)
	}
	if s.Zone.Name != "example.com" || s.Zone.ID != testZoneID {
		t.Errorf("zone = %+v", s.Zone)
	}
	if len(s.DNSRecords) != 2 {
		t.Errorf("dns records = %d, want 2", len(s.DNSRecords))
	}
	if s.Settings.SSL != "flexible" || s.Settings.DNSSEC != "active" || s.Settings.HSTS == nil {
		t.Errorf("settings = %+v", s.Settings)
	}
	if len(s.Rulesets) != 2 { // the managed catalog entry is skipped, empty rulesets dropped
		t.Errorf("rulesets = %d, want 2", len(s.Rulesets))
	}
	if len(s.PageRules) != 1 {
		t.Errorf("page rules = %d, want 1", len(s.PageRules))
	}
	// Only the R2/Access skip (no AccountID) should warn — nothing silently lost.
	for _, w := range c.Warnings {
		if !strings.Contains(w, "R2") && !strings.Contains(w, "Access") {
			t.Errorf("unexpected warning: %q", w)
		}
	}
}

// TestExtractParseFailuresWarned is the 0%FP guard: an item flareover can't
// decode must be surfaced as a warning, never silently dropped.
func TestExtractParseFailuresWarned(t *testing.T) {
	routes := happyRoutes(testZoneID)
	// ssl as a number (not a string) → the value is unreadable.
	routes[base(testZoneID)+"/settings"] = resp{body: env(`[{"id":"ssl","value":123}]`)}
	// action_parameters as a string (not an object) → unreadable.
	routes[base(testZoneID)+"/rulesets/rs_fw"] = resp{body: env(`{"rules":[{"description":"broken","expression":"true","action":"block","action_parameters":"oops","enabled":true}]}`)}

	c, done := mockCF(t, routes)
	defer done()
	if _, err := c.Extract(context.Background(), testZoneID); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(c.Warnings, "\n")
	if !strings.Contains(joined, `setting "ssl": unreadable value`) {
		t.Errorf("missing settings parse-failure warning:\n%s", joined)
	}
	if !strings.Contains(joined, "unreadable action params") {
		t.Errorf("missing ruleset parse-failure warning:\n%s", joined)
	}
}

// TestExtractDegradesNotAborts: an optional surface that 403s becomes a warning
// (extraction continues), but a DNS failure is fatal.
func TestExtractDegradesNotAborts(t *testing.T) {
	routes := happyRoutes(testZoneID)
	routes[base(testZoneID)+"/workers/routes"] = resp{status: http.StatusForbidden, body: ""}

	c, done := mockCF(t, routes)
	defer done()
	if _, err := c.Extract(context.Background(), testZoneID); err != nil {
		t.Fatalf("a 403 on an optional surface must not abort: %v", err)
	}
	if !strings.Contains(strings.Join(c.Warnings, "\n"), "workers") {
		t.Error("the workers 403 was not surfaced as a warning")
	}

	// DNS is the one non-optional surface: its failure aborts.
	routes[base(testZoneID)+"/dns_records"] = resp{body: `{"success":false,"errors":[{"message":"nope"}]}`}
	c2, done2 := mockCF(t, routes)
	defer done2()
	if _, err := c2.Extract(context.Background(), testZoneID); err == nil {
		t.Error("a dns_records failure must abort extraction")
	}
}

func TestListZonesPaged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("page") {
		case "1":
			_, _ = w.Write([]byte(envPaged(`[{"id":"z1","name":"a.example"}]`, 1, 2)))
		default: // page 2
			_, _ = w.Write([]byte(envPaged(`[{"id":"z2","name":"b.example"}]`, 2, 2)))
		}
	}))
	defer srv.Close()
	c := NewClient("tok")
	c.BaseURL = srv.URL

	zs, err := c.ListZones(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(zs) != 2 || zs[0].Name != "a.example" || zs[1].Name != "b.example" {
		t.Errorf("zones = %+v, want both pages", zs)
	}
}
