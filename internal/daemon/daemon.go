package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/engine"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/keyring"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/notify"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/vault"
)

// Daemon is the background service.
type Daemon struct {
	paths     config.Paths
	version   string
	log       *slog.Logger
	notifier  notify.Notifier
	now       func() time.Time
	newEngine func(*config.Config) *engine.Engine
	feeds     *feeds.Client

	ctx           context.Context
	followUpEvery time.Duration

	mu        sync.Mutex
	key       *vault.Key                 // nil while locked
	locks     uint64                     // counts locks, so an unlock that started before one is dropped
	secrets   vault.SecretStore          // holds the auto-unlock key
	clicked   map[string]map[string]bool // notification group → servers whose fix button was used
	unlocking sync.Mutex                 // one passphrase unlock at a time
	limiter   vault.Limiter
	sched     *scheduler
	started   time.Time
}

// New returns a daemon for the given install.
func New(paths config.Paths, version string, log *slog.Logger, notifier notify.Notifier) *Daemon {
	d := &Daemon{paths: paths, version: version, log: log, notifier: notifier, now: time.Now, feeds: feeds.New(version),
		ctx: context.Background(), followUpEvery: followUpEvery, secrets: keyring.AutoUnlock(paths.Home), clicked: map[string]map[string]bool{}}
	d.newEngine = func(cfg *config.Config) *engine.Engine { return engine.New(paths, cfg, version, log) }
	return d
}

// Run serves the CLI and runs scheduled jobs until ctx ends. It starts
// locked; with auto-unlock on it unlocks itself, otherwise you unlock it
// once after each restart.
func (d *Daemon) Run(ctx context.Context) error {
	_ = vault.Harden()
	if err := d.paths.RequireInitialized(); err != nil {
		return err
	}
	l, err := listen(d.paths.Socket)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(d.paths.Socket) }()
	defer d.lock()

	d.ctx, d.started = ctx, d.now()
	d.sched = newScheduler(d.jobs(), filepath.Join(d.paths.State, "schedule.json"), d.now, d.unlocked, d.log)
	go d.serve(ctx, l)
	go d.handleClicks(ctx)
	d.unlockAtStart()
	d.log.Info("daemon", "status", "start", "version", d.version, "notifier", d.notifier.Describe())
	d.sched.loop(ctx, time.Minute)
	d.log.Info("daemon", "status", "stop")
	return nil
}

// jobs are the background service's timers. Four follow schedule in
// config.yaml (mis config › Checks); sending due notifications stays at 15 min.
func (d *Daemon) jobs() []*job {
	configured := func(pick func(config.Schedule) config.Duration) func() time.Duration {
		return func() time.Duration {
			cfg, err := config.Load(d.paths.Config)
			if err != nil {
				return 0 // the default
			}
			return time.Duration(pick(cfg.Schedule))
		}
	}
	return []*job{
		{name: "feeds", every: 30 * time.Minute, run: d.jobFeeds,
			interval: configured(func(s config.Schedule) config.Duration { return s.DataChanges })},
		{name: "refresh", every: 12 * time.Hour, needsKey: true, run: d.jobRefresh,
			interval: configured(func(s config.Schedule) config.Duration { return s.Servers })},
		{name: "match", every: 6 * time.Hour, run: d.jobMatch,
			interval: configured(func(s config.Schedule) config.Duration { return s.FullCheck })},
		{name: "early", every: 15 * time.Minute, run: d.jobEarly,
			interval: configured(func(s config.Schedule) config.Duration { return s.NewCVEs })},
		{name: "remind", every: 15 * time.Minute, run: func(context.Context) error { return d.remind() }},
	}
}

func (d *Daemon) dispatch(ctx context.Context, req Request) (any, error) {
	switch req.Op {
	case OpStatus:
		return d.status(), nil
	case OpUnlock:
		return nil, d.unlock(req.Passphrase)
	case OpAutoUnlock:
		return nil, d.autoUnlock()
	case OpLock:
		d.lock()
		d.showLockNotice()
		return nil, nil
	case OpCheck:
		return d.check(ctx, req)
	case OpFix:
		key := ""
		if req.CVE != "" {
			key = "cve:" + req.CVE
		}
		return nil, d.fix(req.Server, key)
	case OpNotify:
		return nil, d.notifyTest()
	}
	return nil, apperr.New(apperr.DaemonBadRequest, fmt.Sprintf("unknown operation %q", req.Op))
}

func (d *Daemon) status() Status {
	if r, ok := d.notifier.(notify.Rechecker); ok {
		r.Recheck(time.Second) // report today's System Settings, not what they were at start
	}
	return Status{Version: d.version, Locked: !d.unlocked(), AutoUnlock: vault.AutoUnlockEnabled(d.paths.AutoKey), Started: d.started,
		Notifier: d.notifier.Describe(), Ready: d.notifier.Ready(), Jobs: d.sched.snapshot()}
}

// check runs a check now for the CLI.
func (d *Daemon) check(ctx context.Context, req Request) (*engine.Result, error) {
	cfg, err := config.Load(d.paths.Config)
	if err != nil {
		return nil, err
	}
	servers := cfg.Checked()
	if len(req.Servers) > 0 {
		servers = nil
		for _, name := range req.Servers {
			s, ok := cfg.Server(name)
			if !ok {
				return nil, apperr.New(apperr.ServerNotFound, "no server named "+name)
			}
			servers = append(servers, s)
		}
	}
	eng := d.newEngine(cfg)
	if req.Refresh {
		var signer ssh.Signer // this computer is read without the key
		if slices.ContainsFunc(servers, func(s config.Server) bool { return !s.Local }) {
			key := d.currentKey()
			if key == nil {
				return nil, apperr.New(apperr.VaultLocked, "Make-It-Safer is locked; run: mis unlock (or check with --no-refresh)")
			}
			signer = key.Signer()
		}
		d.refreshFailed(eng.Refresh(ctx, signer, servers)) // failures also show up per server below
	}
	res, err := eng.Match(ctx, servers)
	if err != nil {
		return nil, err
	}
	d.alert(res)
	return res, nil
}

// jobFeeds checks cheaply whether Debian's or Ubuntu's data or CISA's
// catalog changed, and triggers a match when they did.
func (d *Daemon) jobFeeds(ctx context.Context) error {
	path := filepath.Join(d.paths.Cache, "feed-etags.json")
	known := map[string]string{}
	if data, err := os.ReadFile(path); err == nil { //nolint:gosec // our own cache file
		_ = json.Unmarshal(data, &known)
	}
	changed := false
	for _, u := range []string{
		"https://osv-vulnerabilities.storage.googleapis.com/Debian/modified_id.csv",
		"https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/modified_id.csv",
	} {
		etag, err := d.feeds.Head(ctx, u)
		if err != nil {
			return err
		}
		if etag == "" || etag != known[u] {
			changed = true
			known[u] = etag
		}
	}
	cfg, err := config.Load(d.paths.Config)
	if err != nil {
		return err
	}
	catalog := d.newEngine(cfg).KEV
	kevBefore, _ := catalog.Cached()
	kevAfter, err := catalog.Refresh(ctx)
	if err == nil && (kevBefore == nil || kevBefore.Version != kevAfter.Version) {
		changed = true
	}
	if data, err := json.Marshal(known); err == nil {
		_ = config.WriteFileAtomic(path, data)
	}
	if changed {
		d.sched.trigger("match")
	}
	return nil
}

func (d *Daemon) jobRefresh(ctx context.Context) error {
	key := d.currentKey()
	if key == nil {
		return nil
	}
	cfg, err := config.Load(d.paths.Config)
	if err != nil {
		return err
	}
	failed := d.newEngine(cfg).Refresh(ctx, key.Signer(), cfg.Servers)
	d.refreshFailed(failed)
	if len(failed) == len(cfg.Servers) && len(cfg.Servers) > 0 {
		return apperr.New(apperr.ServerUnreachable, "could not refresh any server")
	}
	d.sched.trigger("match")
	return nil
}

func (d *Daemon) jobMatch(ctx context.Context) error {
	cfg, err := config.Load(d.paths.Config)
	if err != nil {
		return err
	}
	servers := cfg.Checked()
	if len(servers) == 0 {
		return nil
	}
	// This computer needs no key, so it's read again on every match, even
	// while locked; servers are refreshed by the refresh job.
	eng := d.newEngine(cfg)
	d.refreshFailed(eng.Refresh(ctx, nil, servers))
	res, err := eng.Match(ctx, servers)
	if err != nil {
		return err
	}
	d.alert(res)
	return nil
}

// jobEarly looks for early warnings in the CVE List.
func (d *Daemon) jobEarly(ctx context.Context) error {
	cfg, err := config.Load(d.paths.Config)
	if err != nil {
		return err
	}
	if len(cfg.Checked()) == 0 || !cfg.Rules.EarlyWarning.Enabled {
		return nil
	}
	res, err := d.newEngine(cfg).EarlyWarnings(ctx, cfg.Checked())
	if err != nil {
		return err
	}
	d.alert(res)
	return nil
}
