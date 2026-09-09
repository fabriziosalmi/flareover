// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package leasewebdns

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fabriziosalmi/flareover/internal/ir"
)

// Leaseweb has no upsert: an rrset is replaced by deleting it and creating the
// new one. Interrupt the run in that window and the record is simply gone, with
// nothing to put it back — on the apex A record of a live zone that is an
// outage rather than a partial application.
func TestAFailedCreateRestoresTheRecordItDeleted(t *testing.T) {
	var deleted, restored bool
	var posts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"name":"www.example.com.","type":"A","content":["198.51.100.1"],"ttl":300}`))
		case http.MethodDelete:
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		case http.MethodPost:
			posts++
			if posts == 1 { // the replacement fails
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"errorMessage":"boom"}`))
				return
			}
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), "198.51.100.1") {
				restored = true
			}
			w.WriteHeader(http.StatusCreated)
		}
	}))
	defer srv.Close()

	p := NewProvisioner("key")
	p.BaseURL = srv.URL
	err := p.Provision(context.Background(), ir.DNSZone{
		Name:    "example.com",
		Records: []ir.DNSRecord{{Type: "A", Name: "www.example.com", Content: "203.0.113.10", TTL: 300}},
	})
	if err == nil {
		t.Fatal("a failed create returned no error")
	}
	if !deleted {
		t.Fatal("the test did not reach the delete-then-create window")
	}
	if !restored {
		t.Errorf("the previous record was not restored; error was: %v", err)
	}
	if !strings.Contains(err.Error(), "restored") {
		t.Errorf("the error does not say what happened to the previous record: %v", err)
	}
}
