package daemon

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
)

// JobState is a job's history, kept in state/schedule.json so overdue jobs
// run right after a restart or after the computer wakes up.
type JobState struct {
	LastRun   time.Time `json:"last_run,omitzero"`
	LastOK    time.Time `json:"last_ok,omitzero"`
	LastError string    `json:"last_error,omitempty"`
	Next      time.Time `json:"next"`
	Failures  int       `json:"failures,omitempty"`
}

type job struct {
	name     string
	every    time.Duration        // default interval
	interval func() time.Duration // the configured one (schedule in config.yaml); 0 = every
	needsKey bool                 // only runs while unlocked
	run      func(ctx context.Context) error
}

// period is how long the job waits between runs.
func (j *job) period() time.Duration {
	if j.interval != nil {
		if d := j.interval(); d > 0 {
			return d
		}
	}
	return j.every
}

// scheduler runs jobs one at a time when they are due.
type scheduler struct {
	jobs   []*job
	path   string
	now    func() time.Time
	hasKey func() bool
	log    *slog.Logger
	wake   chan struct{}

	mu    sync.Mutex
	state map[string]*JobState
}

func newScheduler(jobs []*job, path string, now func() time.Time, hasKey func() bool, log *slog.Logger) *scheduler {
	// Schedule by wall-clock time. Go's monotonic clock stops while the
	// computer sleeps, so a job due during the night would otherwise wait
	// for hours of awake time instead of running right after wake-up.
	wall := func() time.Time { return now().Round(0) }
	s := &scheduler{jobs: jobs, path: path, now: wall, hasKey: hasKey, log: log, wake: make(chan struct{}, 1), state: map[string]*JobState{}}
	if data, err := os.ReadFile(path); err == nil { //nolint:gosec // path is in our state dir
		_ = json.Unmarshal(data, &s.state)
	}
	for _, j := range jobs {
		if s.state[j.name] == nil {
			s.state[j.name] = &JobState{Next: now()} // never ran: run soon
		}
	}
	return s
}

// trigger makes a job run at the next opportunity.
func (s *scheduler) trigger(name string) {
	s.mu.Lock()
	if st := s.state[name]; st != nil {
		st.Next = s.now()
	}
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// loop runs due jobs every tick and whenever a job is triggered.
func (s *scheduler) loop(ctx context.Context, tick time.Duration) {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		s.runDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.wake:
		}
	}
}

// runDue runs every job whose time has come.
func (s *scheduler) runDue(ctx context.Context) {
	for _, j := range s.jobs {
		if ctx.Err() != nil {
			return
		}
		period := j.period()
		s.mu.Lock()
		st := s.state[j.name]
		// A shorter interval set in mis config applies now, not after the
		// old one ran out.
		if st.Failures == 0 && !st.LastRun.IsZero() && st.LastRun.Add(period).Before(st.Next) {
			st.Next = st.LastRun.Add(period)
		}
		due := !s.now().Before(st.Next)
		s.mu.Unlock()
		if !due || (j.needsKey && !s.hasKey()) {
			continue
		}

		s.log.Debug("job", "status", "start", "job", j.name)
		runCtx, cancel := context.WithTimeout(ctx, 20*time.Minute)
		err := j.run(runCtx)
		cancel()

		s.mu.Lock()
		now := s.now()
		st.LastRun = now
		if err != nil {
			st.Failures++
			st.LastError = apperr.MessageOf(err)
			st.Next = now.Add(min(period, time.Duration(1<<min(st.Failures, 4))*time.Minute))
			s.log.Warn("job", "status", "error", "job", j.name, "error", err, "retry", st.Next)
		} else {
			st.Failures, st.LastError, st.LastOK = 0, "", now
			st.Next = now.Add(period)
			s.log.Debug("job", "status", "success", "job", j.name)
		}
		s.mu.Unlock()
		s.save()
	}
}

func (s *scheduler) save() {
	s.mu.Lock()
	data, err := json.MarshalIndent(s.state, "", " ")
	s.mu.Unlock()
	if err == nil {
		if err := config.WriteFileAtomic(s.path, data); err != nil {
			s.log.Warn("schedule", "status", "error", "error", err)
		}
	}
}

// snapshot copies the job states, for status.
func (s *scheduler) snapshot() map[string]*JobState {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]*JobState{}
	for name, st := range s.state {
		c := *st
		out[name] = &c
	}
	return out
}

// lastOK returns when a job last succeeded.
func (s *scheduler) lastOK(name string) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.state[name]; st != nil {
		return st.LastOK
	}
	return time.Time{}
}
