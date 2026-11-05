package setup

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/inventory"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/sshx"
)

// Check is one restriction, proven from the outside.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// Report is the result of verifying one server.
type Report struct {
	Server    string               `json:"server"`
	OK        bool                 `json:"ok"`
	OS        string               `json:"os,omitempty"`
	Kernel    string               `json:"kernel,omitempty"`
	Packages  int                  `json:"packages"`
	Checks    []Check              `json:"checks"`
	Inventory *inventory.Inventory `json:"-"`
}

// privilegedGroups would give "mis" more than read access.
var privilegedGroups = []string{"root", "sudo", "admin", "adm", "wheel", "docker", "lxd", "incus-admin", "libvirt", "disk", "shadow"}

// Verify logs in as "mis" and checks that it can only run the collector.
func Verify(ctx context.Context, t sshx.Target, hk sshx.HostKeys, signer ssh.Signer, now time.Time) (*Report, error) {
	c, err := sshx.Dial(ctx, t, hk, signer)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()

	r := &Report{Server: t.Name}
	add := func(name string, ok bool, detail string) {
		r.Checks = append(r.Checks, Check{Name: name, OK: ok, Detail: detail})
	}

	// Ask for a different command; a correctly set-up server ignores it.
	out, err := c.Run(ctx, "id; touch /tmp/mis-was-here")
	var inv *inventory.Inventory
	if err == nil {
		inv, err = inventory.Parse(out, now)
	}
	if err != nil {
		add("Only the collector can run", false, "asked to run `id`; the server did not answer with the collector: "+apperr.MessageOf(err))
	} else {
		add("Only the collector can run", true, "asked to run `id`; the server ran the collector instead")
	}
	add("No terminal", !c.PTYAllowed(), "")
	add("No port forwarding", !c.LocalForwardAllowed() && !c.RemoteForwardAllowed(), "")

	offered, err := sshx.PasswordOffered(ctx, t, hk)
	switch {
	case err != nil:
		add("No password login", false, apperr.MessageOf(err))
	default:
		add("No password login", !offered, "")
	}

	if inv != nil {
		r.Inventory, r.Packages, r.Kernel = inv, len(inv.Packages), inv.Kernel
		r.OS = inv.OSID + " " + inv.OSVersion
		bad := slices.DeleteFunc(slices.Clone(inv.Groups), func(g string) bool { return !slices.Contains(privilegedGroups, g) })
		detail := "groups: " + strings.Join(inv.Groups, " ")
		if len(bad) > 0 {
			detail = "member of " + strings.Join(bad, ", ")
		}
		add("No admin groups", len(bad) == 0 && len(inv.Groups) > 0, detail)
		add("Supported OS", inv.Supported(), fmt.Sprintf("%s %s", inv.OSID, inv.OSVersion))
	}

	r.OK = inv != nil && !slices.ContainsFunc(r.Checks, func(c Check) bool { return !c.OK })
	return r, nil
}
