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
