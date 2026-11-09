package engine

import (
	"context"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/inventory"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/sshx"
)

// Refresh saves each server's package list: this computer's is read
// directly; servers are logged in to as "mis", which needs signer (without
// it they're skipped). It returns the servers that failed, with why.
func (e *Engine) Refresh(ctx context.Context, signer ssh.Signer, servers []config.Server) map[string]error {
	hk := sshx.HostKeys{Path: e.Paths.KnownHosts}
	failed := map[string]error{}
	for _, s := range servers {
		if !s.Local && signer == nil {
			continue
		}
		e.Log.Debug("refresh", "status", "start", "server", s.Name)
		var inv *inventory.Inventory
		var err error
		if s.Local {
			inv, err = e.Local(ctx, e.Now())
		} else {
			inv, err = collect(ctx, sshx.TargetOf(s), hk, signer, e.Now())
		}
		if err == nil {
			err = inventory.Save(e.Paths, s.Name, inv)
		}
		if err != nil {
			e.Log.Warn("refresh", "status", "error", "server", s.Name, "error", err)
			failed[s.Name] = err
			continue
		}
		e.Log.Debug("refresh", "status", "success", "server", s.Name, "packages", len(inv.Packages))
	}
	return failed
}

func collect(ctx context.Context, t sshx.Target, hk sshx.HostKeys, signer ssh.Signer, now time.Time) (*inventory.Inventory, error) {
	c, err := sshx.Dial(ctx, t, hk, signer)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	out, err := c.Collect(ctx)
	if err != nil {
		return nil, err
	}
	return inventory.Parse(out, now)
}

// Check refreshes package lists when refresh is set (servers only with a
// signer, see Refresh), then matches the saved lists.
func (e *Engine) Check(ctx context.Context, refresh bool, signer ssh.Signer, servers []config.Server) (*Result, error) {
	failed := map[string]error{}
	if refresh {
		failed = e.Refresh(ctx, signer, servers)
	}
	res, err := e.Match(ctx, servers)
	if err != nil {
		return nil, err
	}
	res.MarkNotRefreshed(failed)
	return res, nil
}

// MarkNotRefreshed flags the servers whose package list could not be
// refreshed (failed, as Refresh returns it). Their findings come from an
// older saved list, so the result says so instead of looking clean. A
// server that already has a problem keeps its own.
func (r *Result) MarkNotRefreshed(failed map[string]error) {
	for i, s := range r.Servers {
		if err, ok := failed[s.Server]; ok && s.Code == "" {
			r.Servers[i].Code, r.Servers[i].Error = apperr.CodeOf(err), "package list not refreshed: "+apperr.MessageOf(err)
		}
	}
}
