package server

import (
	"sync"
	"time"
)

// Failed-password limit (H3): maxFailures failures for one submitted actor
// label within one window block that label until the window ends. State is in
// memory only. Labels are tracked as submitted, whether or not they exist, so
// the limit reveals nothing about which labels are registered. The table is
// bounded; once full, untracked labels are refused until entries expire.
const (
	maxFailures    = 5
	failureWindow  = 15 * time.Minute
	maxTrackedKeys = 10000
)

type attempt struct {
	count int
	start time.Time
}

type limiter struct {
	mu  sync.Mutex
	now func() time.Time
	m   map[string]*attempt
}

func newLimiter(now func() time.Time) *limiter {
	return &limiter{now: now, m: map[string]*attempt{}}
}

func (l *limiter) expire(now time.Time) {
	for k, a := range l.m {
		if now.Sub(a.start) >= failureWindow {
			delete(l.m, k)
		}
	}
}

// blocked reports whether the label is currently locked out.
func (l *limiter) blocked(label string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if a, ok := l.m[label]; ok {
		if now.Sub(a.start) >= failureWindow {
			delete(l.m, label)
			return 0, false
		}
		if a.count >= maxFailures {
			return failureWindow - now.Sub(a.start), true
		}
		return 0, false
	}
	if len(l.m) >= maxTrackedKeys {
		l.expire(now)
		if len(l.m) >= maxTrackedKeys {
			return failureWindow, true
		}
	}
	return 0, false
}

func (l *limiter) fail(label string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	a, ok := l.m[label]
	if !ok || now.Sub(a.start) >= failureWindow {
		if !ok && len(l.m) >= maxTrackedKeys {
			return
		}
		a = &attempt{start: now}
		l.m[label] = a
	}
	a.count++
}

func (l *limiter) reset(label string) {
	l.mu.Lock()
	delete(l.m, label)
	l.mu.Unlock()
}
