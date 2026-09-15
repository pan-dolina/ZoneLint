package resolver

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"

	"github.com/pan-dolina/ZoneLint/internal/budget"
)

// NetworkResolver is a production resolver over UDP/TCP with EDNS, DO bit,
// retries, and full budget enforcement.
type NetworkResolver struct {
	cli     *dns.Client
	cfg     Config
	bud     budget.Budget
	counter *budget.Counter
	rate    *budget.RateLimiter
	sem     *budget.Semaphore
}

// NewNetwork builds a NetworkResolver from Config.
func NewNetwork(cfg Config) *NetworkResolver {
	b := cfg.Budget.Validated()
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = b.PerTimeout
	}
	cli := &dns.Client{Timeout: timeout}
	return &NetworkResolver{
		cli:     cli,
		cfg:     cfg,
		bud:     b,
		counter: budget.NewCounter(b.MaxQueries),
		rate:    budget.NewRateLimiter(float64(b.MaxQPS)),
		sem:     budget.NewSemaphore(b.MaxConcurrency),
	}
}

func (r *NetworkResolver) spend(ctx context.Context) error {
	if !r.counter.Consume() {
		return context.DeadlineExceeded // budget exhausted
	}
	if err := r.rate.Wait(ctx); err != nil {
		return err
	}
	return r.sem.Acquire(ctx)
}

func (r *NetworkResolver) release() {
	r.sem.Release()
}

// Query issues a single query with UDP and TCP fallback.
func (r *NetworkResolver) Query(ctx context.Context, server string, req *dns.Msg) (*dns.Msg, error) {
	if err := r.spend(ctx); err != nil {
		return nil, err
	}
	defer r.release()

	if server == "" {
		server = r.cfg.UDPAddr
	}
	if server == "" {
		server = DefaultServer(nil)
	}

	retries := r.cfg.Retries
	if retries < 0 {
		retries = 0
	}
	for attempt := 0; attempt <= retries; attempt++ {
		per := r.perContext(ctx)
		resp, err := r.send(ctx, per, server, req, "udp")
		if err == nil && resp != nil {
			return resp, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// TCP fallback on UDP failure/timeout.
		if resp, err = r.send(ctx, per, server, req, "tcp"); err == nil {
			return resp, nil
		}
	}
	return nil, context.DeadlineExceeded
}

func (r *NetworkResolver) send(ctx context.Context, timeout time.Duration, server string, req *dns.Msg, netw string) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cli := &dns.Client{Net: netw, Timeout: timeout}
	done := make(chan struct{})
	var (
		resp *dns.Msg
		rtt  time.Duration
		err  error
	)
	go func() {
		resp, rtt, err = cli.ExchangeContext(ctx, req, server)
		close(done)
	}()
	select {
	case <-ctx.Done():
		<-done
		return nil, ctx.Err()
	case <-done:
		_ = rtt
		return resp, err
	}
}

// Transfer performs a bounded AXFR over TCP.
func (r *NetworkResolver) Transfer(ctx context.Context, server string, req *dns.Msg) ([]dns.RR, error) {
	if err := r.spend(ctx); err != nil {
		return nil, err
	}
	defer r.release()

	per := r.bud.PerTimeout
	ctx, cancel := context.WithTimeout(ctx, per)
	defer cancel()

	cli := &dns.Client{Net: "tcp", Timeout: per}
	resp, _, err := cli.ExchangeContext(ctx, req, server)
	if err != nil {
		return nil, err
	}
	return extractTransfer(resp), nil
}

// extractTransfer safely pulls records out of an AXFR response, bounding size.
func extractTransfer(resp *dns.Msg) []dns.RR {
	if resp == nil {
		return nil
	}
	const max = 100000
	var out []dns.RR
	for _, rr := range resp.Answer {
		if rr == nil {
			continue
		}
		out = append(out, rr)
		if len(out) >= max {
			break
		}
	}
	for _, rr := range resp.Ns {
		if rr == nil {
			continue
		}
		out = append(out, rr)
		if len(out) >= max {
			break
		}
	}
	return out
}

func (r *NetworkResolver) perContext(ctx context.Context) time.Duration {
	per := r.bud.PerTimeout
	deadline, ok := ctx.Deadline()
	if ok {
		if remaining := time.Until(deadline); remaining < per {
			per = remaining
		}
	}
	if per <= 0 {
		per = r.bud.PerTimeout
	}
	return per
}

// DefaultServer returns the first public resolver from a provided list, or the
// first resolver from the host's system resolver configuration, falling back to
// a sensible public default.
func DefaultServer(resolvers []string) string {
	if len(resolvers) > 0 {
		return joinPort(resolvers[0])
	}
	// Prefer the host's configured resolver so queries work on networks where
	// public resolvers (1.1.1.1, 8.8.8.8) are unreachable.
	if srv, ok := systemResolver(); ok {
		return joinPort(srv)
	}
	return "1.1.1.1:53"
}

// systemResolver returns the first nameserver from the host's resolver
// configuration (/etc/resolv.conf on Unix). It reports ok=false when no
// resolver can be determined.
func systemResolver() (string, bool) {
	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(conf.Servers) == 0 {
		return "", false
	}
	return conf.Servers[0], true
}

func joinPort(host string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return host + ":53"
}
