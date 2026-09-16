// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package objstore

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// S3Config points the extractor at any S3-compatible endpoint (AWS S3, R2's S3
// endpoint, MinIO, …). Path-style addressing keeps one endpoint working for all.
type S3Config struct {
	Endpoint  string // e.g. https://s3.eu-central-1.amazonaws.com
	Region    string // e.g. eu-central-1
	AccessKey string
	SecretKey string
	HTTP      *http.Client
	// now is injected for testability; defaults to time.Now.
	now func() time.Time
}

// ExtractS3 reads an S3-compatible account's buckets and config (versioning,
// CORS, lifecycle, policy presence) into a Snapshot via SigV4-signed GETs.
// Read-only. This is the "leave AWS S3 (or any S3) for sovereign MinIO" source,
// the counterpart to ExtractR2.
func ExtractS3(ctx context.Context, cfg S3Config) (Snapshot, error) {
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	s := Snapshot{SchemaVersion: CurrentSchemaVersion, Source: "s3"}

	// ListBuckets.
	var lb struct {
		Buckets struct {
			Bucket []struct {
				Name string `xml:"Name"`
			} `xml:"Bucket"`
		} `xml:"Buckets"`
	}
	if err := cfg.getXML(ctx, "/", &lb); err != nil {
		return s, fmt.Errorf("list buckets: %w", err)
	}

	// One bucket's four metadata reads are independent of every other bucket's,
	// and they used to run strictly one after another: an account with two
	// hundred buckets made eight hundred serial round trips, minutes of wall
	// time for work that overlaps perfectly, with nothing printed while it
	// happened. Bounded fan-out, results written by index so the snapshot stays
	// byte-stable — determinism is the contract here, so the output order must
	// not depend on which goroutine finished first.
	buckets := make([]Bucket, len(lb.Buckets.Bucket))
	// Gaps are collected per bucket and flattened in listing order afterwards,
	// for the same reason the buckets are: the snapshot must not depend on
	// which goroutine finished first.
	gaps := make([][]Gap, len(lb.Buckets.Bucket))
	sem := make(chan struct{}, s3Concurrency)
	var wg sync.WaitGroup
	for i, b := range lb.Buckets.Bucket {
		// Acquire before spawning, not inside the goroutine: otherwise the
		// bound limits requests in flight while the task count still grows with
		// the input, and the loop applies no backpressure of its own.
		sem <- struct{}{}
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			defer func() { <-sem }()
			buckets[i], gaps[i] = cfg.describeBucket(ctx, name)
		}(i, b.Name)
	}
	wg.Wait()
	s.Buckets = buckets
	for _, g := range gaps {
		s.ExtractionGaps = append(s.ExtractionGaps, g...)
	}
	return s, nil
}

// s3Concurrency bounds the fan-out. Small on purpose: the point is to stop
// paying full latency per bucket, not to spend an account's request budget as
// fast as possible — an S3 provider that starts refusing is worse than a slow
// extraction.
const s3Concurrency = 8

// describeBucket performs one bucket's four metadata reads. Each is best-effort
// by design: a 404 on ?cors means the bucket has none, and an error on any of
// them leaves that facet at its zero value rather than failing the extraction.
func (cfg S3Config) describeBucket(ctx context.Context, name string) (Bucket, []Gap) {
	bucket := Bucket{Name: name, Region: cfg.Region}
	var gaps []Gap

	// Each of the four reads below is best-effort, and that used to mean the
	// failure was indistinguishable from the absence: a 403 on ?versioning
	// recorded "versioning off", a 429 on ?policy recorded "no policy
	// attached". Both are the permissive answer, and both flow into the
	// generated MinIO script as a setting to reproduce — so the migration drops
	// the control and the report calls the bucket covered.
	//
	// A 404 (NoSuchCORSConfiguration, NoSuchLifecycleConfiguration,
	// NoSuchBucketPolicy) genuinely means absent and is the normal case.
	// Anything else is recorded as a gap, which Classify reports MANUAL.
	note := func(facet string, err error) {
		if err == nil || isAbsent(err) {
			return
		}
		gaps = append(gaps, Gap{Bucket: name, Facet: facet, Detail: oneLine(err.Error())})
	}

	// Versioning.
	var v struct {
		Status string `xml:"Status"`
	}
	err := cfg.getXML(ctx, "/"+name+"?versioning", &v)
	note("versioning", err)
	if err == nil {
		bucket.Versioning = v.Status == "Enabled"
	}

	// CORS.
	var cors struct {
		Rules []struct {
			Origins []string `xml:"AllowedOrigin"`
			Methods []string `xml:"AllowedMethod"`
			Headers []string `xml:"AllowedHeader"`
			MaxAge  int      `xml:"MaxAgeSeconds"`
		} `xml:"CORSRule"`
	}
	err = cfg.getXML(ctx, "/"+name+"?cors", &cors)
	note("cors", err)
	if err == nil {
		for _, r := range cors.Rules {
			bucket.CORS = append(bucket.CORS, CORSRule{
				AllowedOrigins: r.Origins, AllowedMethods: r.Methods,
				AllowedHeaders: r.Headers, MaxAgeSeconds: r.MaxAge,
			})
		}
	}

	// Lifecycle.
	var lc struct {
		Rules []struct {
			ID     string `xml:"ID"`
			Filter struct {
				Prefix string `xml:"Prefix"`
			} `xml:"Filter"`
			Prefix     string `xml:"Prefix"`
			Expiration *struct {
				Days int `xml:"Days"`
			} `xml:"Expiration"`
			Transition *struct {
				StorageClass string `xml:"StorageClass"`
			} `xml:"Transition"`
		} `xml:"Rule"`
	}
	err = cfg.getXML(ctx, "/"+name+"?lifecycle", &lc)
	note("lifecycle", err)
	if err == nil {
		for _, r := range lc.Rules {
			prefix := r.Prefix
			if prefix == "" {
				prefix = r.Filter.Prefix
			}
			rule := LifecycleRule{ID: r.ID, Prefix: prefix}
			if r.Expiration != nil {
				rule.ExpireDays = r.Expiration.Days
			}
			if r.Transition != nil {
				rule.Transition = true
			}
			bucket.Lifecycle = append(bucket.Lifecycle, rule)
		}
	}

	// Policy presence (JSON, not XML): record it so it surfaces as MANUAL.
	body, perr := cfg.get(ctx, "/"+name+"?policy")
	note("policy", perr)
	if perr == nil && len(strings.TrimSpace(string(body))) > 0 {
		bucket.PolicyJSON = string(body)
	}

	return bucket, gaps
}

// isAbsent reports whether the error means "this bucket has no such
// configuration" rather than "this could not be read". S3 answers the former
// with 404 and a NoSuch* code.
func isAbsent(err error) bool {
	m := err.Error()
	return strings.Contains(m, "HTTP 404") || strings.Contains(m, "NoSuch")
}

// oneLine collapses an error into a single bounded line, so a multi-line XML
// fault cannot break the snapshot's own validation or a rendered report row.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 512 {
		s = s[:509] + "..."
	}
	return s
}

// get performs a SigV4-signed GET and returns the body (non-2xx → error).
func (c S3Config) get(ctx context.Context, pathQuery string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.Endpoint, "/")+pathQuery, nil)
	if err != nil {
		return nil, err
	}
	c.sign(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("s3 %s: HTTP %d", pathQuery, resp.StatusCode)
	}
	return body, nil
}

func (c S3Config) getXML(ctx context.Context, pathQuery string, out any) error {
	body, err := c.get(ctx, pathQuery)
	if err != nil {
		return err
	}
	return xml.Unmarshal(body, out)
}

// sign adds an AWS Signature Version 4 Authorization header to req.
func (c S3Config) sign(req *http.Request) {
	const service = "s3"
	t := c.now().UTC()
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")

	payloadHash := sha256Hex(nil) // empty body for GETs
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	host := req.URL.Host
	req.Header.Set("Host", host)

	// Canonical request.
	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalQuery := canonicalQueryString(req.URL.RawQuery)
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n", host, payloadHash, amzDate)
	canonicalRequest := strings.Join([]string{"GET", canonicalURI, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash}, "\n")

	// String to sign.
	scope := strings.Join([]string{dateStamp, c.Region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, sha256Hex([]byte(canonicalRequest))}, "\n")

	// Signing key + signature.
	kDate := hmacSHA256([]byte("AWS4"+c.SecretKey), dateStamp)
	kRegion := hmacSHA256(kDate, c.Region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	auth := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.AccessKey, scope, signedHeaders, signature)
	req.Header.Set("Authorization", auth)
}

// canonicalQueryString sorts and encodes the query for SigV4. S3 subresource
// queries here are keys without values (e.g. "cors", "versioning").
func canonicalQueryString(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, "&")
	sort.Strings(parts)
	for i, p := range parts {
		if !strings.Contains(p, "=") {
			parts[i] = p + "=" // SigV4 requires key=value form
		}
	}
	return strings.Join(parts, "&")
}

func sha256Hex(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}
