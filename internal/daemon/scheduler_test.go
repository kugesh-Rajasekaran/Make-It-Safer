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
