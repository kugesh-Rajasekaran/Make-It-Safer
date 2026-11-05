package vault

import (
	"sync"
	"time"
)

// Limiter slows down repeated failed unlock attempts. After n failures the
// next attempt has to wait 2^(n-1) seconds, at most five minutes. It only
// guards the running daemon; offline attacks on key.enc are slowed by Argon2id.
type Limiter struct {
	mu       sync.Mutex
	failures int
	next     time.Time
	Now      func() time.Time // for tests; defaults to time.Now
}

const maxUnlockDelay = 5 * time.Minute

// Wait returns how long until the next attempt is allowed (zero if now).
func (l *Limiter) Wait() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if d := l.next.Sub(l.now()); d > 0 {
		return d
	}
	return 0
}

// Failure records a failed attempt.
func (l *Limiter) Failure() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failures++
	delay := maxUnlockDelay
	if l.failures <= 9 {
		delay = min(time.Duration(1<<(l.failures-1))*time.Second, maxUnlockDelay)
	}
	l.next = l.now().Add(delay)
}

// Success resets the limiter.
func (l *Limiter) Success() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failures = 0
	l.next = time.Time{}
}

func (l *Limiter) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}
