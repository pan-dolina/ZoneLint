// Package audit orchestrates the full ZoneLint audit: it resolves the zone,
// gathers records, runs every check, and aggregates findings.
package audit

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/pan-dolina/ZoneLint/internal/active"
	"github.com/pan-dolina/ZoneLint/internal/addrs"
	"github.com/pan-dolina/ZoneLint/internal/authserver"
	"github.com/pan-dolina/ZoneLint/internal/axfr"
	"github.com/pan-dolina/ZoneLint/internal/budget"
	"github.com/pan-dolina/ZoneLint/internal/caa"
	"github.com/pan-dolina/ZoneLint/internal/cname"
	"github.com/pan-dolina/ZoneLint/internal/delegation"
	dnsutil "github.com/pan-dolina/ZoneLint/internal/dns"
	"github.com/pan-dolina/ZoneLint/internal/dnssec"
	"github.com/pan-dolina/ZoneLint/internal/findings"
	"github.com/pan-dolina/ZoneLint/internal/nsec"
	"github.com/pan-dolina/ZoneLint/internal/resolver"
	"github.com/pan-dolina/ZoneLint/internal/soa"
	"github.com/pan-dolina/ZoneLint/internal/ttl"
	"github.com/pan-dolina/ZoneLint/internal/wildcard"
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
	opt     Options
	res     resolver.Resolver
	zone    string
	queries int
}

// New builds a Runner for a zone.
func New(zone string, opt Options) *Runner {
	cfg := resolver.Config{
		Timeout: opt.Timeout,
		Budget: budget.Budget{
			MaxQueries: opt.MaxQueries,
			MaxQPS:     opt.MaxQPS,
		},
		UDPAddr: resolver.DefaultServer(splitResolvers(opt.Resolver)),
	}
	return &Runner{opt: opt, zone: zone, res: newResolver(cfg, opt)}
}

// splitResolvers parses a comma-separated resolver list.
func splitResolvers(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
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
	resp, err := r.query(ctx, req)
	if err != nil {
		f := findings.GeneralError.New(r.zone, "Initial resolution failed.")
		res.AddFinding(&f)
		res.Duration = time.Since(start)
		return res
	}

	// Gather all records at the apex via an ANY query (bounded, single query).
	anyResp, err := r.query(ctx, dnsutil.SafeNewMsg(r.zone, dns.TypeANY))
	if err == nil && anyResp != nil {
		resp.Answer = append(resp.Answer, anyResp.Answer...)
		resp.Ns = append(resp.Ns, anyResp.Ns...)
	}

	// Collect TTLs.
	c := ttl.NewCollector()
	c.CollectAll(resp)

	// Gather additional record types at the apex and from referenced names.
	apexRecords, apexUnits := collectApexRecords(ctx, r, resp)

	// 2. Delegation check.
	parent := delegation.ExtractNSFromResponse(resp, r.zone)

	// Query the child subdomain to build the child view.
	childZoneName := childZone(r.zone)
	childNSResp, childErr := r.query(ctx, dnsutil.SafeNewMsg(childZoneName, dns.TypeNS))
	var child delegation.ChildView
	if childErr == nil && childNSResp != nil && len(childNSResp.Answer) > 0 {
		child = delegation.ExtractChildFromResponse(childNSResp, childZoneName)
		child.Authoritative = childNSResp.Authoritative
		for _, f := range delegation.Compare(r.zone, parent, child, time.Now()) {
			res.AddFinding(f)
		}
	}

	// 2b. Authserver probing (requires real network; skip for fakes).
	// Only probe authoritative servers directly. When the resolver is a
	// recursive resolver the response is not authoritative, so the
	// AA/SOA/NS checks would be false positives.
	if r.opt.Resolver != "fake" && resp.Authoritative {
		for _, nsHost := range parent.NS {
			nsResp, err := r.query(ctx, dnsutil.SafeNewMsg(r.zone, dns.TypeSOA))
			if err != nil {
				continue
			}
			pr := authserver.ProbeResponse(nsResp)
			pr.UDPReachable = true
			for _, f := range authserver.CheckServer(r.zone, nsHost, pr) {
				res.AddFinding(f)
			}
			break
		}
	}

	// 3. SOA check.
	if soaRec := dnsutil.SOA(resp.Answer); soaRec != nil {
		for _, f := range soa.Check(r.zone, soaRec) {
			res.AddFinding(f)
		}
	}

	// 4. TTL check.
	for _, f := range ttl.Check(r.zone, r.opt.Profile, c) {
		res.AddFinding(f)
	}

	// 5. CAA check.
	for _, f := range caa.Check(r.zone, dnsutil.RRsOfType(apexRecords, dns.TypeCAA)) {
		res.AddFinding(f)
	}

	// 6. Address classification.
	for _, f := range addrs.CheckAll(r.zone, apexRecords) {
		res.AddFinding(f)
	}

	// 7. CNAME check.
	cgraph := cname.Build(apexRecords)
	resolveTarget := buildResolveTarget(apexRecords, r.zone)
	for _, f := range cname.Check(r.zone, cgraph, 8, resolveTarget) {
		res.AddFinding(f)
	}

	// 8. DNSSEC checks: collect DNSKEY/DS at the apex and probe a random
	// non-existent name to harvest NSEC/NSEC3 from the negative response,
	// then run presence, chain-of-trust, and cryptographic verification.
	dd := r.collectDNSSEC(ctx, resp, apexRecords, apexUnits)
	// Only RRSIGs signed by this zone count towards its DNSSEC state; negative
	// responses at the delegation also carry records signed by the parent.
	zk := dnssec.Collect(dd.combined).InZone(r.zone)
	anchor := dnssec.Collect(dd.ds)
	// A DS at the delegation also means DNSSEC is expected: a signed-looking
	// delegation whose zone data cannot be validated is a broken setup.
	signed := zk.HasDNSKEY() || zk.HasRRSIG() || anchor.HasDS()
	if signed {
		for _, f := range dnssec.CheckZone(r.zone, zk, time.Now()) {
			res.AddFinding(f)
		}
		sigFailures, verified := r.verifySignatures(dd)
		for _, f := range sigFailures {
			res.AddFinding(f)
		}
		if !anchor.HasDS() {
			f := findings.DNSSECNoDS.New(r.zone,
				"The zone is DNSSEC-signed but the parent publishes no DS record, so the chain of trust cannot be established.")
			res.AddFinding(&f)
		} else if cr := dnssec.ValidateChain(anchor, zk, time.Now()); !cr.Valid {
			reason := cr.Reason
			if reason == "" {
				reason = cr.BrokenAt
			}
			if reason == "" {
				reason = "validation failed"
			}
			f := findings.DNSSECBrokenChain.New(r.zone,
				"The DNSSEC chain of trust does not validate for this zone.",
				reason)
			res.AddFinding(&f)
		} else if verified > 0 && len(sigFailures) == 0 {
			f := findings.DNSSECValid.New(r.zone,
				"The DNSSEC chain of trust validates and all in-zone RRSIGs verify against the zone DNSKEY.",
				fmt.Sprintf("verified_rrsets=%d", verified))
			res.AddFinding(&f)
		}
	}

	// 9. NSEC/NSEC3 check (signed zones only; NSEC/NSEC3 appear in negative
	// responses, which is why they are harvested in step 8).
	if signed {
		nsecRecs := dnsutil.RRsOfType(dd.combined.Answer, dns.TypeNSEC)
		nsecRecs = append(nsecRecs, dnsutil.RRsOfType(dd.combined.Ns, dns.TypeNSEC)...)
		nsecRecs = append(nsecRecs, dnsutil.RRsOfType(dd.combined.Answer, dns.TypeNSEC3)...)
		nsecRecs = append(nsecRecs, dnsutil.RRsOfType(dd.combined.Ns, dns.TypeNSEC3)...)
		for _, f := range nsec.Check(r.zone, nsec.Analyze(nsecRecs)) {
			res.AddFinding(f)
		}
	}

	// 10. AXFR (opt-in).
	if r.opt.Active {
		for _, nsHost := range parent.NS {
			xreq := dnsutil.SafeNewMsg(r.zone, dns.TypeAXFR)
			xresp, err := r.transfer(ctx, xreq)
			cfg := axfr.DefaultConfig()
			cfg.ShowRecords = r.opt.ShowAXFR
			o := axfr.ParseTransferResult(makeTransferResp(xresp, err), cfg)
			o.Server = nsHost
			if err != nil && err == resolver.ErrZoneRefused {
				o.Status = "refused"
			}
			for _, f := range axfr.Evaluate(r.zone, nsHost, o) {
				res.AddFinding(f)
			}
		}
	}

	// 11. Wildcard probe (always on; single random query).
	if wcName, err := wildcard.ProbeName(r.zone); err == nil {
		if wcResp, err := r.query(ctx, dnsutil.SafeNewMsg(wcName, dns.TypeA)); err == nil && wcResp != nil {
			if wildcard.IsWildcardResponse(wcResp, wcName) {
				for _, f := range wildcard.Check(r.zone, wcName, true) {
					res.AddFinding(f)
				}
			}
		}
	}

	// 12. Active recursion (opt-in).
	if r.opt.Active {
		for _, nsHost := range parent.NS {
			recName, err := active.RandomName(r.zone)
			if err != nil {
				continue
			}
			recResp, err := r.query(ctx, dnsutil.SafeNewMsg(recName, dns.TypeA))
			if err != nil {
				continue
			}
			rp := active.CheckRecursion(nsHost, r.zone, recResp)
			for _, f := range active.Check(nsHost, r.zone, rp) {
				res.AddFinding(f)
			}
		}
	}

	sorted := make([]findings.Finding, len(res.Findings))
	for i, f := range res.Findings {
		sorted[i] = *f
	}
	findings.Sort(sorted)
	res.Findings = make([]*findings.Finding, len(sorted))
	for i, f := range sorted {
		res.Findings[i] = &f
	}
	res.Duration = time.Since(start)

	res.Records = len(resp.Answer) + len(resp.Ns) + len(apexRecords) + len(dd.combined.Answer) + len(dd.combined.Ns)
	res.Queries = r.queries
	return res
}

// query issues a single audited query and counts it. EDNS0 with the DO
// (DNSSEC OK) bit is set so resolvers return DNSSEC records.
func (r *Runner) query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if req.IsEdns0() == nil {
		req.SetEdns0(1232, true)
	}
	r.queries++
	return r.res.Query(ctx, r.opt.Resolver, req)
}

// transfer issues a bounded AXFR and counts it.
func (r *Runner) transfer(ctx context.Context, req *dns.Msg) ([]dns.RR, error) {
	r.queries++
	return r.res.Transfer(ctx, r.opt.Resolver, req)
}

// dnssecData holds the DNSSEC material collected for a zone.
type dnssecData struct {
	units    []*dns.Msg // individual responses, for per-response RRSIG verification
	keys     []dns.RR   // zone DNSKEY answer records, attached to each unit
	combined *dns.Msg   // deduplicated union of all records (presence/chain/NSEC)
	ds       *dns.Msg   // DS-only response (the chain-of-trust anchor)
}

// collectDNSSEC gathers DNSSEC material for the zone: it keeps each response as
// a unit (an RRSIG is verified against the RRset from the same response, since
// resolvers may synthesize per-query variants of negative-proof records), and
// additionally merges everything into a deduplicated union. It issues DNSKEY
// and DS queries at the apex and probes a random non-existent name to harvest
// NSEC/NSEC3 records from the negative response.
func (r *Runner) collectDNSSEC(ctx context.Context, initial *dns.Msg, apexRecords []dns.RR, apexUnits []*dns.Msg) *dnssecData {
	d := &dnssecData{combined: new(dns.Msg), ds: new(dns.Msg)}
	d.units = append(d.units, initial)
	d.units = append(d.units, apexUnits...)

	// Records merged from several responses repeat (e.g. the SOA appears in
	// every negative response); key by name, type, and RDATA so each unique
	// record is kept once.
	seen := map[string]bool{}
	add := func(section *[]dns.RR, rr dns.RR) {
		if rr == nil {
			return
		}
		key := dns.Fqdn(strings.ToLower(rr.Header().Name)) + "|" +
			strconv.Itoa(int(rr.Header().Rrtype)) + "|" + rrKey(rr)
		if seen[key] {
			return
		}
		seen[key] = true
		*section = append(*section, rr)
	}
	addAll := func(section *[]dns.RR, rrs []dns.RR) {
		for _, rr := range rrs {
			add(section, rr)
		}
	}

	addAll(&d.combined.Answer, initial.Answer)
	addAll(&d.combined.Ns, initial.Ns)
	addAll(&d.combined.Answer, apexRecords)

	for _, typ := range []uint16{dns.TypeDNSKEY, dns.TypeDS} {
		resp, err := r.query(ctx, dnsutil.SafeNewMsg(r.zone, typ))
		if err != nil || resp == nil {
			continue
		}
		d.units = append(d.units, resp)
		addAll(&d.combined.Answer, resp.Answer)
		addAll(&d.combined.Ns, resp.Ns)
		if typ == dns.TypeDNSKEY {
			d.keys = append(d.keys, resp.Answer...)
		} else {
			d.ds.Answer = append(d.ds.Answer, resp.Answer...)
			d.ds.Ns = append(d.ds.Ns, resp.Ns...)
		}
	}

	// Negative probe: a random non-existent name yields NSEC/NSEC3 (and the
	// SOA) in the authority section of a signed zone.
	if probeName, err := wildcard.ProbeName(r.zone); err == nil {
		if resp, err := r.query(ctx, dnsutil.SafeNewMsg(probeName, dns.TypeA)); err == nil && resp != nil {
			d.units = append(d.units, resp)
			addAll(&d.combined.Answer, resp.Answer)
			addAll(&d.combined.Ns, resp.Ns)
		}
	}
	return d
}

// rrKey returns a stable identity for a record's RDATA: the canonical wire
// RDATA when available, otherwise the presentation form.
func rrKey(rr dns.RR) string {
	if rd := dnsutil.RRData(rr); rd != nil {
		return string(rd)
	}
	return rr.String()
}

// verifySignatures cryptographically verifies every in-zone RRSIG whose key is
// present in the zone DNSKEY set. Each RRSIG is verified against the RRset as
// it appeared in the same response (resolvers may synthesize per-query variants
// of negative-proof records, so responses are kept as units and the zone
// DNSKEY set is attached to each). DS records are skipped: they are signed by
// the parent zone, whose keys are not available. A covered RRset is reported
// only when it fails verification in every response that carried it. The
// function returns the findings and the number of RRsets verified successfully.
func (r *Runner) verifySignatures(d *dnssecData) ([]*findings.Finding, int) {
	type pairStat struct {
		passes, fails int
		name          string
		rtype         uint16
		keyTag        uint16
	}
	stats := map[string]*pairStat{}
	apex := dns.Fqdn(strings.ToLower(r.zone))
	for _, unit := range d.units {
		msg := new(dns.Msg)
		msg.Answer = append(msg.Answer, unit.Answer...)
		msg.Ns = append(msg.Ns, unit.Ns...)
		msg.Answer = append(msg.Answer, d.keys...)
		zk := dnssec.Collect(msg)
		for name, sigs := range zk.RRSigs {
			lname := dns.Fqdn(strings.ToLower(name))
			if lname != apex && !strings.HasSuffix(lname, "."+apex) {
				continue // out-of-zone name (e.g. NS host addresses)
			}
			for _, sig := range sigs {
				rtype := sig.TypeCovered
				if rtype == dns.TypeDS {
					continue
				}
				if len(zk.ByType[lname][rtype]) == 0 {
					continue // no covered records in this response
				}
				if !zk.HasKeyForTag(sig.KeyTag) {
					continue // no matching DNSKEY: nothing to verify against
				}
				key := lname + "/" + strconv.Itoa(int(rtype))
				st := stats[key]
				if st == nil {
					st = &pairStat{name: lname, rtype: rtype, keyTag: sig.KeyTag}
					stats[key] = st
				}
				if idx := dnssec.VerifyRRSIGForType(zk, lname, rtype, time.Now()); idx >= 0 {
					st.fails++
				} else {
					st.passes++
				}
			}
		}
	}

	var out []*findings.Finding
	verified := 0
	for _, st := range stats {
		if st.passes > 0 {
			verified++
			continue
		}
		if st.fails > 0 {
			f := findings.DNSSECInvalidSig.New(r.zone,
				"An RRSIG does not verify against the zone DNSKEY, so the covered records fail validation.",
				fmt.Sprintf("name=%s type=%s keytag=%d", st.name, dns.TypeToString[st.rtype], st.keyTag))
			out = append(out, &f)
		}
	}
	return out, verified
}

// childZone returns the subdomain used to query the child authority. It
// prepends "sub." to the zone, e.g. "example.test." -> "sub.example.test.".
func childZone(zone string) string {
	return "sub." + zone
}

// buildResolveTarget returns a function that reports whether a name resolves to
// a record within the audited zone. Names outside the zone (or with no record)
// are treated as unresolved, enabling dangling-CNAME detection.
func buildResolveTarget(records []dns.RR, zone string) func(string) bool {
	inZone := map[string]bool{}
	for _, rr := range records {
		if rr == nil {
			continue
		}
		inZone[strings.ToLower(dns.Fqdn(rr.Header().Name))] = true
	}
	zone = strings.ToLower(dns.Fqdn(zone))
	return func(name string) bool {
		name = strings.ToLower(dns.Fqdn(name))
		if inZone[name] {
			return true
		}
		// A target that is a subdomain of the audited zone resolves if the
		// zone itself is present (delegation boundary).
		if strings.HasSuffix(name, "."+zone) {
			return inZone[zone]
		}
		return false
	}
}

// collectApexRecords gathers A/AAAA/MX/CNAME/TXT/CAA records at the apex and
// from names referenced by NS records. It returns all gathered records plus
// the individual response messages (kept as units for DNSSEC verification).
func collectApexRecords(ctx context.Context, r *Runner, initial *dns.Msg) ([]dns.RR, []*dns.Msg) {
	var all []dns.RR
	var units []*dns.Msg
	// Collect from the initial response.
	all = append(all, initial.Answer...)
	all = append(all, initial.Ns...)

	// Query additional record types at the apex.
	for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeCNAME, dns.TypeTXT, dns.TypeCAA} {
		resp, err := r.query(ctx, dnsutil.SafeNewMsg(r.zone, typ))
		if err != nil {
			continue
		}
		units = append(units, resp)
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
				resp, err := r.query(ctx, dnsutil.SafeNewMsg(strings.ToLower(dns.Fqdn(ns.Ns)), typ))
				if err != nil {
					continue
				}
				units = append(units, resp)
				all = append(all, resp.Answer...)
			}
		}
	}
	return all, units
}

func (r *Result) AddFinding(f *findings.Finding) {
	f.Zone = r.Zone
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
