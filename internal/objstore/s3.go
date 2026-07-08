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
	s := Snapshot{SchemaVersion: 1, Source: "s3"}

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

	for _, b := range lb.Buckets.Bucket {
		bucket := Bucket{Name: b.Name, Region: cfg.Region}

		// Versioning.
		var v struct {
			Status string `xml:"Status"`
		}
		if err := cfg.getXML(ctx, "/"+b.Name+"?versioning", &v); err == nil {
			bucket.Versioning = v.Status == "Enabled"
		}

		// CORS (404/NoSuchCORSConfiguration is normal).
		var cors struct {
			Rules []struct {
				Origins []string `xml:"AllowedOrigin"`
				Methods []string `xml:"AllowedMethod"`
				Headers []string `xml:"AllowedHeader"`
				MaxAge  int      `xml:"MaxAgeSeconds"`
			} `xml:"CORSRule"`
		}
		if err := cfg.getXML(ctx, "/"+b.Name+"?cors", &cors); err == nil {
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
		if err := cfg.getXML(ctx, "/"+b.Name+"?lifecycle", &lc); err == nil {
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

		// Policy presence (JSON, not XML) — record it so it surfaces as MANUAL.
		if body, err := cfg.get(ctx, "/"+b.Name+"?policy"); err == nil && len(strings.TrimSpace(string(body))) > 0 {
			bucket.PolicyJSON = string(body)
		}

		s.Buckets = append(s.Buckets, bucket)
	}
	return s, nil
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
