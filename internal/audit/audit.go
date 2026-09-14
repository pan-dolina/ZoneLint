// Package audit orchestrates the full ZoneLint audit: it resolves the zone,
// gathers records, runs every check, and aggregates findings.
package audit

import (
	"context"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/example/ZoneLint/internal/addrs"
	"github.com/example/ZoneLint/internal/authserver"
	"github.com/example/ZoneLint/internal/axfr"
	"github.com/example/ZoneLint/internal/budget"
	"github.com/example/ZoneLint/internal/caa"
	"github.com/example/ZoneLint/internal/cname"
	"github.com/example/ZoneLint/internal/delegation"
	dnsutil "github.com/example/ZoneLint/internal/dns"
	"github.com/example/ZoneLint/internal/dnssec"
	"github.com/example/ZoneLint/internal/findings"
	"github.com/example/ZoneLint/internal/nsec"
	"github.com/example/ZoneLint/internal/resolver"
	"github.com/example/ZoneLint/internal/soa"
	"github.com/example/ZoneLint/internal/ttl"
)

// Options configures an audit run.
type Options struct {
	Resolver   string
	Profile    string
	Timeout    time.Duration
	MaxQPS     int
	MaxQueries int
	Active     bool
	ShowAXFR   bool
}

// Result is the aggregate outcome of an audit.
type Result struct {
	Zone     string
	Findings []*findings.Finding
	Resolver string
	Duration time.Duration
	Queries  int
	Records  int
}

// Runner holds the resolver and options for a run.
type Runner struct {
	opt  Options
	res  resolver.Resolver
	zone string
}

// New builds a Runner for a zone.
func New(zone string, opt Options) *Runner {
	cfg := resolver.Config{
		Timeout: opt.Timeout,
		Budget: budget.Budget{
			MaxQueries: opt.MaxQueries,
			MaxQPS:     opt.MaxQPS,
		},
	}
	return &Runner{opt: opt, zone: zone, res: newResolver(cfg, opt)}
}

// resolverFactory builds the resolver. Overridable in tests.
// ResolverFactory builds the resolver. Overridable in tests.
var ResolverFactory = func(cfg resolver.Config, opt Options) resolver.Resolver {
	return resolver.NewNetwork(cfg)
}

func newResolver(cfg resolver.Config, opt Options) resolver.Resolver {
	return ResolverFactory(cfg, opt)
}

// NewWithResolver builds a Runner with an explicit resolver (for tests).
func NewWithResolver(zone string, opt Options, r resolver.Resolver) *Runner {
	return &Runner{opt: opt, zone: zone, res: r}
}

// Run executes the audit.
func (r *Runner) Run(ctx context.Context) *Result {
	start := time.Now()
	res := &Result{Zone: r.zone, Resolver: r.opt.Resolver, Findings: []*findings.Finding{}}

	// 1. Resolve zone apex NS + SOA.
	req := dnsutil.SafeNewMsg(r.zone, dns.TypeNS)
	resp, err := r.res.Query(ctx, r.opt.Resolver, req)
	if err != nil {
		res.AddFinding(findings.New(findings.GeneralError, findings.SeverityHigh, findings.CategoryGeneral,
			"Initial resolution failed"), r.zone)
		res.Duration = time.Since(start)
		return res
	}

	// Gather all records at the apex via an ANY query (bounded, single query).
	anyResp, err := r.res.Query(ctx, r.opt.Resolver, dnsutil.SafeNewMsg(r.zone, dns.TypeANY))
	if err == nil && anyResp != nil {
		resp.Answer = append(resp.Answer, anyResp.Answer...)
		resp.Ns = append(resp.Ns, anyResp.Ns...)
	}

	// Collect TTLs.
	c := ttl.NewCollector()
	c.CollectAll(resp)

	// Gather additional record types at the apex and from referenced names.
	apexRecords := collectApexRecords(ctx, r, resp)

	// 2. Delegation check.
	parent := delegation.ExtractNSFromResponse(resp, r.zone)

	// Query the child subdomain to build the child view.
	childZoneName := childZone(r.zone)
	childNSResp, childErr := r.res.Query(ctx, r.opt.Resolver, dnsutil.SafeNewMsg(childZoneName, dns.TypeNS))
	var child delegation.ChildView
	if childErr == nil && childNSResp != nil && len(childNSResp.Answer) > 0 {
		child = delegation.ExtractChildFromResponse(childNSResp, childZoneName)
		child.Authoritative = childNSResp.Authoritative
		for _, f := range delegation.Compare(r.zone, parent, child, time.Now()) {
			res.AddFinding(f, r.zone)
		}
	}

	// 2b. Authserver probing (requires real network; skip for fakes).
	if r.opt.Resolver != "fake" {
		for _, nsHost := range parent.NS {
			nsResp, err := r.res.Query(ctx, r.opt.Resolver, dnsutil.SafeNewMsg(r.zone, dns.TypeSOA))
			if err != nil {
				continue
			}
			pr := authserver.ProbeResponse(nsResp)
			pr.UDPReachable = true
			for _, f := range authserver.CheckServer(r.zone, nsHost, pr) {
				res.AddFinding(f, r.zone)
			}
			break
		}
	}

	// 3. SOA check.
	if soaRec := dnsutil.SOA(resp.Answer); soaRec != nil {
		for _, f := range soa.Check(r.zone, soaRec) {
			res.AddFinding(f, r.zone)
		}
	}

	// 4. TTL check.
	for _, f := range ttl.Check(r.zone, r.opt.Profile, c) {
		res.AddFinding(f, r.zone)
	}

	// 5. CAA check.
	for _, f := range caa.Check(r.zone, dnsutil.RRsOfType(apexRecords, dns.TypeCAA)) {
		res.AddFinding(f, r.zone)
	}

	// 6. Address classification.
	for _, f := range addrs.CheckAll(r.zone, apexRecords) {
		res.AddFinding(f, r.zone)
	}

	// 7. CNAME check.
	cgraph := cname.Build(apexRecords)
	for _, f := range cname.Check(r.zone, cgraph, 8, func(string) bool { return true }) {
		res.AddFinding(f, r.zone)
	}

	// 8. DNSSEC checks.
	if zk := dnssec.Collect(resp); zk.HasDNSKEY() || zk.HasRRSIG() {
		for _, f := range dnssec.CheckZone(r.zone, zk, time.Now()) {
			res.AddFinding(f, r.zone)
		}
	}

	// 9. NSEC/NSEC3 check.
	nsecRecs := dnsutil.RRsOfType(resp.Answer, dns.TypeNSEC)
	nsecRecs = append(nsecRecs, dnsutil.RRsOfType(resp.Ns, dns.TypeNSEC)...)
	nsecRecs = append(nsecRecs, dnsutil.RRsOfType(resp.Answer, dns.TypeNSEC3)...)
	nsecRecs = append(nsecRecs, dnsutil.RRsOfType(resp.Ns, dns.TypeNSEC3)...)
	for _, f := range nsec.Check(r.zone, nsec.Analyze(nsecRecs)) {
		res.AddFinding(f, r.zone)
	}

	// 10. AXFR (opt-in).
	if r.opt.Active {
		for _, nsHost := range parent.NS {
			xreq := dnsutil.SafeNewMsg(r.zone, dns.TypeAXFR)
			xresp, err := r.res.Transfer(ctx, r.opt.Resolver, xreq)
			cfg := axfr.DefaultConfig()
			cfg.ShowRecords = r.opt.ShowAXFR
			o := axfr.ParseTransferResult(makeTransferResp(xresp, err), cfg)
			o.Server = nsHost
			for _, f := range axfr.Evaluate(r.zone, nsHost, o) {
				res.AddFinding(f, r.zone)
			}
		}
	}

	res.Findings = findings.Sorted(res.Findings)
	res.Duration = time.Since(start)
	res.Records = len(resp.Answer) + len(resp.Ns)
	return res
}

// childZone returns the subdomain used to query the child authority. It
// prepends "sub." to the zone, e.g. "example.test." -> "sub.example.test.".
func childZone(zone string) string {
	return "sub." + zone
}

// collectApexRecords gathers A/AAAA/MX/CNAME/TXT/CAA records at the apex and
// from names referenced by NS records, returning all gathered records.
func collectApexRecords(ctx context.Context, r *Runner, initial *dns.Msg) []dns.RR {
	var all []dns.RR
	// Collect from the initial response.
	all = append(all, initial.Answer...)
	all = append(all, initial.Ns...)

	// Query additional record types at the apex.
	for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeCNAME, dns.TypeTXT, dns.TypeCAA} {
		resp, err := r.res.Query(ctx, r.opt.Resolver, dnsutil.SafeNewMsg(r.zone, typ))
		if err != nil {
			continue
		}
		all = append(all, resp.Answer...)
		all = append(all, resp.Ns...)
	}

	// Query records for NS hostnames (to catch address misconfigurations).
	seen := map[string]bool{}
	for _, rr := range initial.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			name := strings.ToLower(dns.Fqdn(ns.Ns))
			if seen[name] {
				continue
			}
			seen[name] = true
			for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
				resp, err := r.res.Query(ctx, r.opt.Resolver, dnsutil.SafeNewMsg(strings.ToLower(dns.Fqdn(ns.Ns)), typ))
				if err != nil {
					continue
				}
				all = append(all, resp.Answer...)
			}
		}
	}
	return all
}

func (r *Result) AddFinding(f *findings.Finding, zone string) {
	f.WithZone(zone)
	r.Findings = append(r.Findings, f)
}

func makeTransferResp(records []dns.RR, err error) *dns.Msg {
	if err != nil {
		return nil
	}
	resp := new(dns.Msg)
	resp.Rcode = dns.RcodeSuccess
	resp.Answer = records
	return resp
}
