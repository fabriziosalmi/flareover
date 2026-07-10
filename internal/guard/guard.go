// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

// Package guard is the Failguards muscle as a running loop. After a cutover it
// watches the migrated edge's health; when it degrades past a threshold it fires
// a trigger: a rollback (back to the source) or, in failover framing, a flip to
// a warm standby. The same watch is the failover primitive: monitor the primary,
// act on catastrophe. The trigger is a caller-supplied hook, so the dangerous
// outward action (a DNS write) stays explicit and testable in isolation.
package guard

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

// Check reports health: nil means healthy, an error describes the problem.
type Check func(context.Context) error

// Status is one observation, passed to the Report callback each tick.
type Status struct {
	At               time.Time
	Healthy          bool
	Reason           string
	ConsecutiveFails int
}

// Options configure the watch.
type Options struct {
	Interval      time.Duration
	FailThreshold int
	// OnUnhealthy fires once when consecutive failures reach the threshold
	// (e.g. run the rollback / flip to standby). Watch returns after it fires.
	OnUnhealthy func(reason string) error
	// Report is called every tick with the current status (for live output).
	Report func(Status)
	// Once runs a single check and returns (for CI / a one-shot health gate).
	Once bool
}

// Watch runs the health loop until the trigger fires, the context is cancelled,
// or (in Once mode) a single check completes. It returns whether the trigger
// fired.
func Watch(ctx context.Context, check Check, o Options) (triggered bool, err error) {
	if o.Interval <= 0 {
		o.Interval = 30 * time.Second
	}
	if o.FailThreshold <= 0 {
		o.FailThreshold = 3
	}
	fails := 0
	tick := func() (bool, error) {
		cerr := check(ctx)
		st := Status{At: nowOr(), Healthy: cerr == nil}
		if cerr != nil {
			fails++
			st.Reason = cerr.Error()
		} else {
			fails = 0
		}
		st.ConsecutiveFails = fails
		if o.Report != nil {
			o.Report(st)
		}
		if fails >= o.FailThreshold {
			reason := fmt.Sprintf("%d consecutive failures: %s", fails, st.Reason)
			if o.OnUnhealthy != nil {
				if herr := o.OnUnhealthy(reason); herr != nil {
					return true, fmt.Errorf("trigger failed: %w", herr)
				}
			}
			return true, nil
		}
		return false, nil
	}

	if o.Once {
		return tick()
	}

	t := time.NewTicker(o.Interval)
	defer t.Stop()
	for {
		fired, terr := tick()
		if fired || terr != nil {
			return fired, terr
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-t.C:
		}
	}
}

// HTTPCheck builds a health check that fetches url and verifies the status code
// (and, over HTTPS, a valid certificate: no InsecureSkipVerify). A non-match or
// a transport/TLS error is unhealthy.
func HTTPCheck(url string, expectStatus int) Check {
	client := &http.Client{
		Timeout:       10 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{}}, // strict verify
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if expectStatus == 0 {
		expectStatus = 200
	}
	return func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err // transport / TLS failure
		}
		defer resp.Body.Close()
		if resp.StatusCode != expectStatus {
			return fmt.Errorf("status %d (want %d)", resp.StatusCode, expectStatus)
		}
		return nil
	}
}

func nowOr() time.Time { return time.Now() }
