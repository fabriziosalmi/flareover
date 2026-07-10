// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package objstore

import (
	"context"
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
