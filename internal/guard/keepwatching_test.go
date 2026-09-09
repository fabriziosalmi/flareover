// SPDX-FileCopyrightText: © 2026 Fabrizio Salmi
// SPDX-License-Identifier: AGPL-3.0-only

package guard

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A watchdog that stops after the first rollback leaves the migration
// unguarded for everything that happens next — including a rollback that
// itself failed. KeepWatching is how an operator running this as a long-lived
// service asks for the other behaviour; fire-once stays the default because a
// CI gate and the documented exit code 20 expect it.
func TestKeepWatchingContinuesPastTheTriggerAndResetsTheCounter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var fires int
	var seen []int
	check := func(context.Context) error { return errors.New("down") }

	triggered, err := Watch(ctx, check, Options{
		Interval:      time.Millisecond,
		FailThreshold: 2,
		KeepWatching:  true,
		OnUnhealthy: func(string) error {
			fires++
			if fires >= 3 {
				cancel() // stop the test once we have seen it fire repeatedly
			}
			return nil
		},
		Report: func(s Status) { seen = append(seen, s.ConsecutiveFails) },
	})

	if triggered {
		t.Error("Watch returned triggered=true; with KeepWatching it should run until cancelled")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if fires < 3 {
		t.Errorf("trigger fired %d times, want at least 3: it stopped watching", fires)
	}
	// The counter must reset after firing, or the threshold would be crossed
	// again on the very next tick and the trigger would run every interval.
	var sawReset bool
	for i := 1; i < len(seen); i++ {
		if seen[i] < seen[i-1] {
			sawReset = true
			break
		}
	}
	if !sawReset {
		t.Errorf("the failure counter never reset after a trigger: %v", seen)
	}
}

// The default must not change: fire once, return, exit 20.
func TestWithoutKeepWatchingTheDefaultIsStillFireOnce(t *testing.T) {
	var fires int
	triggered, err := Watch(context.Background(), func(context.Context) error { return errors.New("down") }, Options{
		Interval:      time.Millisecond,
		FailThreshold: 1,
		OnUnhealthy:   func(string) error { fires++; return nil },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !triggered {
		t.Error("triggered = false, want true")
	}
	if fires != 1 {
		t.Errorf("trigger fired %d times, want exactly 1", fires)
	}
}

// A failing trigger stops the watch even with KeepWatching: continuing to
// hammer a rollback that does not work is amplification, not resilience.
func TestAFailingTriggerStopsEvenWhenKeepWatching(t *testing.T) {
	_, err := Watch(context.Background(), func(context.Context) error { return errors.New("down") }, Options{
		Interval:      time.Millisecond,
		FailThreshold: 1,
		KeepWatching:  true,
		OnUnhealthy:   func(string) error { return errors.New("rollback script exited 1") },
	})
	if err == nil {
		t.Fatal("a failing trigger was swallowed")
	}
}
