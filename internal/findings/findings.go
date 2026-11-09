// Package findings holds what Make-It-Safer found on each server, how urgent
// each finding is, and its lifecycle from new to resolved.
package findings

import (
	"fmt"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/apperr"
)

// Kind is what a finding is about.
type Kind string

// Finding kinds.
const (
	KindVulnerability Kind = "vulnerability"
	KindReboot        Kind = "reboot"        // a patched kernel is installed but not running
	KindEndOfLife     Kind = "end-of-life"   // the OS release no longer gets (free) security fixes
	KindEarlyWarning  Kind = "early-warning" // unconfirmed: from the CVE List, before the distro assessed it
	KindUpdates       Kind = "updates"       // packages with newer versions but no CVE data (Homebrew on a Mac)
)

// How an early warning ended (Finding.Resolution).
const (
	ResolutionConfirmed   = "confirmed"    // the distro data confirmed it: a vulnerability finding took over
	ResolutionNotAffected = "not affected" // the distro assessed it and this server isn't affected
	ResolutionExpired     = "expired"      // no distro data after 30 days
)

// Priority decides whether and how often you're reminded.
type Priority int

// Priorities, lowest first.
const (
	Silent Priority = iota
	Normal
	High
	Urgent
)

func (p Priority) String() string {
	return [...]string{"silent", "normal", "high", "urgent"}[p]
}

// MarshalText writes priorities as words in JSON.
func (p Priority) MarshalText() ([]byte, error) { return []byte(p.String()), nil }

// UnmarshalText reads priorities written by MarshalText.
func (p *Priority) UnmarshalText(b []byte) error {
	for i, name := range []string{"silent", "normal", "high", "urgent"} {
		if string(b) == name {
			*p = Priority(i)
			return nil
		}
	}
	return fmt.Errorf("unknown priority %q", b)
}

// State is where a finding is in its lifecycle.
type State string

// Lifecycle states:
//
//	new ──► notified ──► snoozed / accepted ──► resolved
//	 ▲                                              │
//	 └────────────── reopened (reported again) ─────┘
const (
	StateNew      State = "new"
	StateNotified State = "notified"
	StateSnoozed  State = "snoozed"  // acknowledged until a date
	StateAccepted State = "accepted" // acknowledged as an accepted risk
	StateResolved State = "resolved"
)

var transitions = map[State][]State{
	StateNew:      {StateNotified, StateSnoozed, StateAccepted, StateResolved},
	StateNotified: {StateSnoozed, StateAccepted, StateResolved},
	StateSnoozed:  {StateNew, StateAccepted, StateResolved},
	StateAccepted: {StateNew, StateSnoozed, StateResolved},
	StateResolved: {StateNew},
}

// Finding is one thing to fix on one server.
type Finding struct {
	ID             string    `json:"id"` // server/kind/subject, stable across checks
	Server         string    `json:"server"`
	Kind           Kind      `json:"kind"`
	CVE            string    `json:"cve,omitempty"`
	VulnID         string    `json:"vuln_id,omitempty"` // distro record, e.g. UBUNTU-CVE-2024-6387
	Source         string    `json:"source,omitempty"`  // source package
	Installed      string    `json:"installed,omitempty"`
	Fixed          string    `json:"fixed,omitempty"` // "" while there's no fix
	ProOnly        bool      `json:"pro_only,omitempty"`
	Summary        string    `json:"summary,omitempty"`  // from the data source; display only
	Vector         string    `json:"vector,omitempty"`   // CVSS vector from the CVE record; display only
	Weakness       string    `json:"weakness,omitempty"` // e.g. "CWE-364: Signal Handler Race Condition"
	Impact         string    `json:"impact,omitempty"`   // what an attacker could do, in Apple's or CISA's words
	Details        string    `json:"details,omitempty"`  // the CVE record's description
	DistroPriority string    `json:"distro_priority,omitempty"`
	Score          float64   `json:"score,omitempty"` // CVSS base score, 0 = unknown
	EPSS           float64   `json:"epss,omitempty"`
	KEV            bool      `json:"kev,omitempty"`
	Priority       Priority  `json:"priority"`
	State          State     `json:"state"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	NotifiedAt     time.Time `json:"notified_at,omitzero"`
	ResolvedAt     time.Time `json:"resolved_at,omitzero"`
	SnoozedUntil   time.Time `json:"snoozed_until,omitzero"`
	AckReason      string    `json:"ack_reason,omitempty"`
	Resolution     string    `json:"resolution,omitempty"` // early warnings: how they ended
}

// MakeID builds a finding's stable ID.
func MakeID(server string, kind Kind, subject string) string {
	return server + "/" + string(kind) + "/" + subject
}

// Open reports whether the finding still needs attention.
func (f *Finding) Open() bool { return f.State != StateResolved }

// HasFix reports whether the distro has published a fix.
func (f *Finding) HasFix() bool { return f.Fixed != "" }

// Transition moves the finding to a new state, refusing invalid moves.
func (f *Finding) Transition(to State, now time.Time) error {
	allowed := false
	for _, s := range transitions[f.State] {
		allowed = allowed || s == to
	}
	if !allowed {
		return apperr.New(apperr.FindingsInvalidTransition, fmt.Sprintf("%s can't go from %s to %s", f.ID, f.State, to))
	}
	f.State = to
	switch to {
	case StateNotified:
		f.NotifiedAt = now
	case StateResolved:
		f.ResolvedAt = now
	case StateNew:
		f.ResolvedAt, f.NotifiedAt, f.SnoozedUntil, f.AckReason, f.Resolution = time.Time{}, time.Time{}, time.Time{}, "", ""
	}
	return nil
}
