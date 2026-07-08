package objstore

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// R2 API base (overridable in tests).
var r2Base = "https://api.cloudflare.com/client/v4"

// ExtractR2 reads a Cloudflare R2 account's buckets and their configuration
// (CORS, lifecycle) into a source-agnostic Snapshot, ready for Classify/Generate.
// Read-only: it only issues GETs. Requires an API token with Workers R2
// Storage:Read and the account id.
func ExtractR2(ctx context.Context, token, accountID string) (Snapshot, error) {
	s := Snapshot{SchemaVersion: 1, Source: "r2", Account: accountID}
	c := &http.Client{Timeout: 30 * time.Second}

	get := func(path string, out any) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, r2Base+path, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := c.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		if resp.StatusCode >= 300 {
			return fmt.Errorf("r2 %s: HTTP %d: %s", path, resp.StatusCode, strings.TrimSpace(string(raw)))
		}
		var env struct {
			Success bool            `json:"success"`
			Result  json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			return fmt.Errorf("r2 %s: %w", path, err)
		}
		if !env.Success {
			return fmt.Errorf("r2 %s: API error: %s", path, string(raw))
		}
		if out != nil {
			return json.Unmarshal(env.Result, out)
		}
		return nil
	}

	var list struct {
		Buckets []struct {
			Name     string `json:"name"`
			Location string `json:"location"`
		} `json:"buckets"`
	}
	if err := get("/accounts/"+accountID+"/r2/buckets", &list); err != nil {
		return s, err
	}

	for _, b := range list.Buckets {
		bucket := Bucket{Name: b.Name, Region: b.Location}
		base := "/accounts/" + accountID + "/r2/buckets/" + b.Name

		// CORS (best-effort; absence is not an error).
		var cors struct {
			Rules []struct {
				Allowed struct {
					Origins []string `json:"origins"`
					Methods []string `json:"methods"`
					Headers []string `json:"headers"`
				} `json:"allowed"`
				MaxAgeSeconds int `json:"maxAgeSeconds"`
			} `json:"rules"`
		}
		if err := get(base+"/cors", &cors); err == nil {
			for _, r := range cors.Rules {
				bucket.CORS = append(bucket.CORS, CORSRule{
					AllowedOrigins: r.Allowed.Origins, AllowedMethods: r.Allowed.Methods,
					AllowedHeaders: r.Allowed.Headers, MaxAgeSeconds: r.MaxAgeSeconds,
				})
			}
		}

		// Lifecycle (best-effort).
		var lc struct {
			Rules []struct {
				ID         string `json:"id"`
				Enabled    bool   `json:"enabled"`
				Conditions struct {
					Prefix string `json:"prefix"`
				} `json:"conditions"`
				DeleteObjectsTransition *struct {
					Condition struct {
						MaxAge int `json:"maxAge"`
					} `json:"condition"`
				} `json:"deleteObjectsTransition"`
				StorageClassTransitions []json.RawMessage `json:"storageClassTransitions"`
			} `json:"rules"`
		}
		if err := get(base+"/lifecycle", &lc); err == nil {
			for _, r := range lc.Rules {
				rule := LifecycleRule{ID: r.ID, Prefix: r.Conditions.Prefix}
				if r.DeleteObjectsTransition != nil {
					rule.ExpireDays = r.DeleteObjectsTransition.Condition.MaxAge / 86400
				}
				if len(r.StorageClassTransitions) > 0 {
					rule.Transition = true
				}
				bucket.Lifecycle = append(bucket.Lifecycle, rule)
			}
		}

		s.Buckets = append(s.Buckets, bucket)
	}
	return s, nil
}
