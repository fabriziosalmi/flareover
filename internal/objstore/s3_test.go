// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package objstore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestExtractS3(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every request must be SigV4-signed.
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIA/") {
			w.WriteHeader(403)
			return
		}
		q := r.URL.RawQuery
		switch {
		case r.URL.Path == "/" && q == "":
			w.Write([]byte(`<ListAllMyBucketsResult><Buckets><Bucket><Name>media</Name></Bucket></Buckets></ListAllMyBucketsResult>`))
		case strings.HasPrefix(q, "versioning"):
			w.Write([]byte(`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`))
		case strings.HasPrefix(q, "cors"):
			w.Write([]byte(`<CORSConfiguration><CORSRule><AllowedOrigin>https://x</AllowedOrigin><AllowedMethod>GET</AllowedMethod><MaxAgeSeconds>300</MaxAgeSeconds></CORSRule></CORSConfiguration>`))
		case strings.HasPrefix(q, "lifecycle"):
			w.Write([]byte(`<LifecycleConfiguration><Rule><ID>expire</ID><Filter><Prefix>tmp/</Prefix></Filter><Expiration><Days>7</Days></Expiration></Rule><Rule><ID>tier</ID><Transition><StorageClass>GLACIER</StorageClass></Transition></Rule></LifecycleConfiguration>`))
		case strings.HasPrefix(q, "policy"):
			w.Write([]byte(`{"Version":"2012-10-17","Statement":[]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	fixed := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	cfg := S3Config{
		Endpoint: srv.URL, Region: "eu-central-1", AccessKey: "AKIA", SecretKey: "secret",
		now: func() time.Time { return fixed },
	}
	s, err := ExtractS3(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.Source != "s3" || len(s.Buckets) != 1 {
		t.Fatalf("snapshot = %+v", s)
	}
	b := s.Buckets[0]
	if !b.Versioning {
		t.Error("versioning not detected")
	}
	if len(b.CORS) != 1 || b.CORS[0].MaxAgeSeconds != 300 {
		t.Errorf("CORS = %+v", b.CORS)
	}
	if len(b.Lifecycle) != 2 {
		t.Fatalf("lifecycle rules = %d, want 2", len(b.Lifecycle))
	}
	if b.Lifecycle[0].ExpireDays != 7 {
		t.Errorf("expiry = %d, want 7", b.Lifecycle[0].ExpireDays)
	}
	if !b.Lifecycle[1].Transition {
		t.Error("GLACIER transition should be flagged (→ MANUAL)")
	}
	if b.PolicyJSON == "" {
		t.Error("bucket policy should be captured (→ MANUAL)")
	}

	// The extracted snapshot classifies with the same 0% FP discipline.
	rep := Classify(s)
	if len(rep.Findings) == 0 {
		t.Error("classify produced no findings")
	}
}

func TestSigV4Deterministic(t *testing.T) {
	fixed := time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
	mk := func() *http.Request {
		req, _ := http.NewRequest("GET", "https://s3.example.com/media?cors", nil)
		return req
	}
	cfg := S3Config{Region: "eu-central-1", AccessKey: "AKIA", SecretKey: "s", now: func() time.Time { return fixed }}
	r1, r2 := mk(), mk()
	cfg.sign(r1)
	cfg.sign(r2)
	a1, a2 := r1.Header.Get("Authorization"), r2.Header.Get("Authorization")
	if a1 == "" || a1 != a2 {
		t.Fatalf("SigV4 not deterministic:\n%s\n%s", a1, a2)
	}
	if !strings.Contains(a1, "Credential=AKIA/20260707/eu-central-1/s3/aws4_request") {
		t.Errorf("scope wrong: %s", a1)
	}
	if !strings.Contains(a1, "SignedHeaders=host;x-amz-content-sha256;x-amz-date") {
		t.Errorf("signed headers wrong: %s", a1)
	}
}

// The fan-out across buckets was exercised with a single bucket, so the
// goroutine body ran once and the race detector never saw two of them at the
// same time. Several buckets make the concurrency real, and asserting the
// output order pins the property the index-writing exists to guarantee: the
// snapshot must not depend on which goroutine finished first.
func TestExtractS3IsDeterministicUnderContention(t *testing.T) {
	names := []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot",
		"golf", "hotel", "india", "juliet", "kilo", "lima"}
	var list strings.Builder
	list.WriteString(`<ListAllMyBucketsResult><Buckets>`)
	for _, n := range names {
		list.WriteString("<Bucket><Name>" + n + "</Name></Bucket>")
	}
	list.WriteString(`</Buckets></ListAllMyBucketsResult>`)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.RawQuery
		switch {
		case r.URL.Path == "/" && q == "":
			_, _ = w.Write([]byte(list.String()))
		case strings.HasPrefix(q, "versioning"):
			_, _ = w.Write([]byte(`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`))
		default:
			// Absent, not unreadable: must not become a gap.
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`<Error><Code>NoSuchCORSConfiguration</Code></Error>`))
		}
	}))
	defer srv.Close()

	cfg := S3Config{Endpoint: srv.URL, Region: "eu-west-1", AccessKey: "AKIA", SecretKey: "s3cret"}
	first, err := ExtractS3(context.Background(), cfg)
	if err != nil {
		t.Fatalf("ExtractS3: %v", err)
	}
	if len(first.Buckets) != len(names) {
		t.Fatalf("got %d buckets, want %d", len(first.Buckets), len(names))
	}
	for i, n := range names {
		if first.Buckets[i].Name != n {
			t.Fatalf("bucket %d = %q, want %q: the fan-out did not preserve listing order", i, first.Buckets[i].Name, n)
		}
		if !first.Buckets[i].Versioning {
			t.Errorf("bucket %q lost its versioning under contention", n)
		}
	}
	if len(first.ExtractionGaps) != 0 {
		t.Errorf("a 404 (genuinely absent) was recorded as a gap: %+v", first.ExtractionGaps)
	}

	// Same inputs, same output — the contract the whole pipeline rests on.
	second, err := ExtractS3(context.Background(), cfg)
	if err != nil {
		t.Fatalf("ExtractS3 (second run): %v", err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if string(a) != string(b) {
		t.Error("two extractions of the same account differ: the fan-out leaked ordering into the snapshot")
	}
}

// An unreadable facet under contention must land on the right bucket.
func TestExtractS3AttributesGapsToTheRightBucket(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.RawQuery
		switch {
		case r.URL.Path == "/" && q == "":
			_, _ = w.Write([]byte(`<ListAllMyBucketsResult><Buckets><Bucket><Name>one</Name></Bucket><Bucket><Name>two</Name></Bucket></Buckets></ListAllMyBucketsResult>`))
		case r.URL.Path == "/two" && strings.HasPrefix(q, "versioning"):
			w.WriteHeader(403) // this key cannot read two's configuration
		case strings.HasPrefix(q, "versioning"):
			_, _ = w.Write([]byte(`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`))
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`<Error><Code>NoSuchCORSConfiguration</Code></Error>`))
		}
	}))
	defer srv.Close()

	snap, err := ExtractS3(context.Background(), S3Config{
		Endpoint: srv.URL, Region: "eu-west-1", AccessKey: "AKIA", SecretKey: "s3cret",
	})
	if err != nil {
		t.Fatalf("ExtractS3: %v", err)
	}
	if len(snap.ExtractionGaps) != 1 {
		t.Fatalf("got %d gaps, want 1: %+v", len(snap.ExtractionGaps), snap.ExtractionGaps)
	}
	g := snap.ExtractionGaps[0]
	if g.Bucket != "two" || g.Facet != "versioning" {
		t.Errorf("gap = %+v, want bucket \"two\" facet \"versioning\"", g)
	}
	// The bucket that could be read keeps its value.
	for _, b := range snap.Buckets {
		if b.Name == "one" && !b.Versioning {
			t.Error("a readable bucket lost its versioning because another bucket failed")
		}
	}
}
