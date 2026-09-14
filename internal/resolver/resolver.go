// Package resolver defines the Resolver abstraction used throughout ZoneLint.
// A network resolver talks to real DNS servers over UDP/TCP; a fake resolver
// serves controlled zones from memory for tests.
package resolver

import (
	"context"
	"time"

	"github.com/miekg/dns"

	"github.com/example/ZoneLint/internal/budget"
)

// Result is the outcome of a single query.
type Result struct {
	Resp   *dns.Msg
	Server string // server that answered (may be empty for fakes)
	Err    error
}

// Resolver issues DNS queries subject to the query budget.
type Resolver interface {
	// Query sends a single request and returns the response. It enforces the
	// budget, timeout, retries, and context cancellation.
	Query(ctx context.Context, server string, req *dns.Msg) (*dns.Msg, error)
	// Transfer performs a bounded zone transfer (AXFR). It returns the
	// collected records and stops at budget/record limits.
	Transfer(ctx context.Context, server string, req *dns.Msg) ([]dns.RR, error)
}

// Config holds resolver tunables.
type Config struct {
	Timeout time.Duration
	Retries int
	EDNS    bool
	DNSSEC  bool
	Budget  budget.Budget
	UDPAddr string // "1.1.1.1:53"
}
