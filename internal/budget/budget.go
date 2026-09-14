// Package budget enforces query budgets for the whole run: max queries, max
// QPS, bounded concurrency, per-server timeout, and recursion limit. The
// budget is the single guardrail that prevents ZoneLint from flooding a target.
package budget

import (
	"context"
	"sync"
	"time"
)

// Budget bounds outbound DNS activity.
type Budget struct {
	MaxQueries     int           // absolute cap on queries
	MaxQPS         int           // 0 == unlimited rate
	MaxConcurrency int           // in-flight query cap (0 == 1)
	PerTimeout     time.Duration // per-server response timeout
	RecursionLimit int           // max resolution hops (0 == default 8)
}

// Defaults returns a conservative, safe budget.
func Defaults() Budget {
	return Budget{
		MaxQueries:     400,
		MaxQPS:         50,
		MaxConcurrency: 16,
		PerTimeout:     3 * time.Second,
		RecursionLimit: 8,
	}
}

// Validated normalizes zero/negative values into safe defaults.
func (b Budget) Validated() Budget {
	if b.MaxQueries <= 0 {
		b.MaxQueries = 400
	}
	if b.MaxQPS <= 0 {
		b.MaxQPS = 50
	}
	if b.MaxConcurrency <= 0 {
		b.MaxConcurrency = 1
	}
	if b.PerTimeout <= 0 {
		b.PerTimeout = 3 * time.Second
	}
	if b.RecursionLimit <= 0 {
		b.RecursionLimit = 8
	}
	return b
}

// Counter tracks remaining queries and is safe for concurrent use.
type Counter struct {
	mu        sync.Mutex
	remaining int
}

// NewCounter returns a counter initialized to n.
func NewCounter(n int) *Counter {
	if n <= 0 {
		n = 400
	}
	return &Counter{remaining: n}
}

// Remaining returns the number of queries still permitted.
func (c *Counter) Remaining() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.remaining
}

// Consume decrements the budget by one; it reports whether the query may
// proceed. It never underflows below zero.
func (c *Counter) Consume() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.remaining <= 0 {
		return false
	}
	c.remaining--
	return true
}

// RateLimiter is a token bucket rate limiter.
type RateLimiter struct {
	mu     sync.Mutex
	tokens float64
	max    float64
	refill float64 // tokens per second
	last   time.Time
}

// NewRateLimiter builds a limiter for qps queries per second.
func NewRateLimiter(qps float64) *RateLimiter {
	if qps <= 0 {
		qps = 50
	}
	return &RateLimiter{
		tokens: qps,
		max:    qps,
		refill: qps,
		last:   time.Now(),
	}
}

// Wait blocks until a token is available or ctx is done. It returns an error
// only if ctx is cancelled.
func (r *RateLimiter) Wait(ctx context.Context) error {
	for {
		r.mu.Lock()
		now := time.Now()
		r.last = now
		r.tokens = r.max
		if r.tokens > r.max {
			r.tokens = r.max
		}
		if r.tokens >= 1 {
			r.tokens--
			r.mu.Unlock()
			return nil
		}
		wait := time.Duration((1 - r.tokens) / r.refill * float64(time.Second))
		r.mu.Unlock()
		if wait <= 0 {
			wait = time.Millisecond
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// Semaphore bounds in-flight queries.
type Semaphore struct {
	ch chan struct{}
}

// NewSemaphore returns a semaphore of width w.
func NewSemaphore(w int) *Semaphore {
	if w <= 0 {
		w = 1
	}
	return &Semaphore{ch: make(chan struct{}, w)}
}

// Acquire blocks until a slot is free or ctx is done.
func (s *Semaphore) Acquire(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case s.ch <- struct{}{}:
		return nil
	}
}

// Release frees a slot.
func (s *Semaphore) Release() {
	<-s.ch
}
