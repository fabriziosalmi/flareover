// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package objstore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExtractR2(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			return
		}
		wrap := func(result string) { w.Write([]byte(`{"success":true,"result":` + result + `}`)) }
		switch {
		case strings.HasSuffix(r.URL.Path, "/r2/buckets"):
			wrap(`{"buckets":[{"name":"assets","location":"weur"},{"name":"cold","location":"weur"}]}`)
		case strings.HasSuffix(r.URL.Path, "/assets/cors"):
			wrap(`{"rules":[{"allowed":{"origins":["https://x"],"methods":["GET"]},"maxAgeSeconds":600}]}`)
		case strings.HasSuffix(r.URL.Path, "/assets/lifecycle"):
			wrap(`{"rules":[{"id":"exp","conditions":{"prefix":"tmp/"},"deleteObjectsTransition":{"condition":{"maxAge":2592000}}}]}`)
		case strings.HasSuffix(r.URL.Path, "/cold/lifecycle"):
			wrap(`{"rules":[{"id":"tier","storageClassTransitions":[{"x":1}]}]}`)
		default:
			wrap(`{}`) // empty cors/lifecycle
		}
	}))
	defer srv.Close()

	old := r2Base
	r2Base = srv.URL
	defer func() { r2Base = old }()

	s, err := ExtractR2(context.Background(), "tok", "acct1")
	if err != nil {
		t.Fatal(err)
	}
	if s.Source != "r2" || len(s.Buckets) != 2 {
		t.Fatalf("snapshot = %+v", s)
	}
	assets := s.Buckets[0]
	if len(assets.CORS) != 1 || assets.CORS[0].MaxAgeSeconds != 600 {
		t.Errorf("assets CORS = %+v", assets.CORS)
	}
	if len(assets.Lifecycle) != 1 || assets.Lifecycle[0].ExpireDays != 30 {
		t.Errorf("assets lifecycle = %+v (want 30d expiry)", assets.Lifecycle)
	}
	// The cold bucket's tiering transition must be flagged (→ MANUAL later).
	cold := s.Buckets[1]
	if len(cold.Lifecycle) != 1 || !cold.Lifecycle[0].Transition {
		t.Errorf("cold lifecycle should flag a tiering transition: %+v", cold.Lifecycle)
	}

	// End-to-end: the extracted snapshot classifies cleanly.
	rep := Classify(s)
	if len(rep.Findings) == 0 {
		t.Error("classify produced no findings from the extracted snapshot")
	}
}
