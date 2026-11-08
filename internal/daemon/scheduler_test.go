package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSchedulerRunsDueJobsAndBacksOff(t *testing.T) {
	now := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	var runs []string
	failing := true
	hasKey := false
	jobs := []*job{
		{name: "match", every: 6 * time.Hour, run: func(context.Context) error { runs = append(runs, "match"); return nil }},
		{name: "refresh", every: 12 * time.Hour, needsKey: true, run: func(context.Context) error { runs = append(runs, "refresh"); return nil }},
		{name: "feeds", every: 30 * time.Minute, run: func(context.Context) error {
			runs = append(runs, "feeds")
			if failing {
				return errors.New("offline")
			}
			return nil
		}},
	}
	path := filepath.Join(t.TempDir(), "schedule.json")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := newScheduler(jobs, path, clock, func() bool { return hasKey }, log)
	ctx := context.Background()

	s.runDue(ctx)
	if strings.Join(runs, ",") != "match,feeds" {
		t.Fatalf("first run: %v (refresh needs the key)", runs)
	}
	st := s.snapshot()
	if st["feeds"].Failures != 1 || !st["feeds"].Next.Equal(now.Add(2*time.Minute)) {
		t.Fatalf("failed job should retry in 2 minutes: %+v", st["feeds"])
	}

	runs, now = nil, now.Add(2*time.Minute)
	failing = false
	s.runDue(ctx)
	if strings.Join(runs, ",") != "feeds" {
		t.Fatalf("only the retry is due: %v", runs)
	}

	runs, hasKey = nil, true
	s.trigger("refresh")
	s.runDue(ctx)
	if strings.Join(runs, ",") != "refresh" {
		t.Fatalf("triggered job: %v", runs)
	}

	// After a restart (or waking up hours later) overdue jobs run at once.
	runs, now = nil, now.Add(7*time.Hour)
	s2 := newScheduler(jobs, path, clock, func() bool { return false }, log)
	s2.runDue(ctx)
	if strings.Join(runs, ",") != "match,feeds" || s2.lastOK("match").IsZero() {
		t.Fatalf("after restart: %v", runs)
	}
}

// The real clock carries a monotonic reading that stops while the computer
// sleeps. The scheduler must compare wall-clock times only, or jobs due
// during sleep wait for hours of awake time.
func TestSchedulerUsesWallClockTime(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	jobs := []*job{{name: "feeds", every: time.Minute, run: func(context.Context) error { return nil }}}
	s := newScheduler(jobs, filepath.Join(t.TempDir(), "schedule.json"), time.Now, func() bool { return false }, log)
	s.runDue(context.Background())
	for _, tm := range []time.Time{s.now(), s.snapshot()["feeds"].Next, s.snapshot()["feeds"].LastOK} {
		if strings.Contains(tm.String(), "m=") {
			t.Fatalf("%v carries a monotonic reading, which stops during sleep", tm)
		}
	}
}

// Intervals come from mis config; a shorter one applies right away.
func TestSchedulerFollowsTheConfiguredInterval(t *testing.T) {
	now := time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC)
	every := 6 * time.Hour
	runs := 0
	jobs := []*job{{name: "match", every: time.Hour, interval: func() time.Duration { return every },
		run: func(context.Context) error { runs++; return nil }}}
	s := newScheduler(jobs, filepath.Join(t.TempDir(), "schedule.json"), func() time.Time { return now }, func() bool { return false },
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	s.runDue(context.Background())
	if next := s.snapshot()["match"].Next; runs != 1 || !next.Equal(now.Add(6*time.Hour)) {
		t.Fatalf("runs %d, next %v: want the configured 6h, not the 1h default", runs, next)
	}

	now = now.Add(45 * time.Minute)
	every = 30 * time.Minute // shortened in mis config: overdue now
	s.runDue(context.Background())
	if runs != 2 {
		t.Fatalf("a shorter interval should apply at once; runs = %d", runs)
	}
}
