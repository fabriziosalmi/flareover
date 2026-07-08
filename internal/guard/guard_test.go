// SPDX-License-Identifier: AGPL-3.0-only

package guard

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestOnceHealthy(t *testing.T) {
	triggered, err := Watch(context.Background(), func(context.Context) error { return nil },
		Options{Once: true, FailThreshold: 3})
	if err != nil || triggered {
		t.Fatalf("healthy once: triggered=%v err=%v", triggered, err)
	}
}

func TestOnceBelowThresholdDoesNotTrigger(t *testing.T) {
	triggered, _ := Watch(context.Background(), func(context.Context) error { return errors.New("down") },
		Options{Once: true, FailThreshold: 3})
	if triggered {
		t.Fatal("a single failure must not trip a threshold of 3")
	}
}

func TestTriggersAtThreshold(t *testing.T) {
	var fired atomic.Bool
	var gotReason string
	triggered, err := Watch(context.Background(),
		func(context.Context) error { return errors.New("502") },
		Options{
			Interval:      time.Millisecond,
			FailThreshold: 2,
			OnUnhealthy: func(reason string) error {
				fired.Store(true)
				gotReason = reason
				return nil
			},
		})
	if err != nil {
		t.Fatal(err)
	}
	if !triggered || !fired.Load() {
		t.Fatalf("expected trigger; triggered=%v fired=%v", triggered, fired.Load())
	}
	if gotReason == "" {
		t.Error("trigger reason should describe the failures")
	}
}

func TestHealthyResetsCounter(t *testing.T) {
	var n int32
	// fails twice, then healthy forever → threshold 3 is never reached.
	check := func(context.Context) error {
		if atomic.AddInt32(&n, 1) <= 2 {
			return errors.New("warming up")
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	triggered, _ := Watch(ctx, check, Options{Interval: time.Millisecond, FailThreshold: 3})
	if triggered {
		t.Fatal("intermittent failures below threshold must not trigger a rollback")
	}
}

// TestTriggerFailureSurfaces: if the rollback hook itself errors, Watch reports it.
func TestTriggerFailureSurfaces(t *testing.T) {
	_, err := Watch(context.Background(),
		func(context.Context) error { return errors.New("down") },
		Options{Once: true, FailThreshold: 1, OnUnhealthy: func(string) error { return errors.New("rollback broke") }})
	if err == nil {
		t.Fatal("a failing trigger must surface an error")
	}
}
