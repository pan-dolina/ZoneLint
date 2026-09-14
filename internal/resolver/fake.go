package resolver

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// Sentinel errors returned by the fake resolver.
var (
	ErrNoQuestion  = errors.New("dns: no question")
	ErrZoneRefused = errors.New("dns: zone transfer refused")
)

// Zone is an in-memory authoritative zone served by FakeResolver.
type Zone struct {
	Name            string
	Records         map[string][]dns.RR // name (FQDN, lowercase) -> records
	TransferAllowed bool
	Recursive       bool
	SOAOverride     dns.RR
}

// FakeResolver is an in-memory authoritative DNS server for tests. It does not
// touch the network.
type FakeResolver struct {
	mu              sync.Mutex
	zones           map[string]*Zone
	DefaultFallback []dns.RR
	QueryLog        []LoggedQuery
	TransferLimit   int
}

// LoggedQuery records a query received by the fake server.
type LoggedQuery struct {
	Name   string
	Type   uint16
	Server string
}

// NewFake returns an empty FakeResolver.
func NewFake() *FakeResolver {
	return &FakeResolver{zones: map[string]*Zone{}}
}

// AddZone registers a zone.
func (f *FakeResolver) AddZone(z *Zone) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.zones == nil {
		f.zones = map[string]*Zone{}
	}
	f.zones[dns.Fqdn(strings.ToLower(z.Name))] = z
}

// Query serves a query from the appropriate zone.
func (f *FakeResolver) Query(ctx context.Context, server string, req *dns.Msg) (*dns.Msg, error) {
	if req == nil || len(req.Question) == 0 {
		return nil, ErrNoQuestion
	}
	q := req.Question[0]
	f.record(q)

	name := dns.Fqdn(strings.ToLower(q.Name))
	zone := f.findZone(name)
	if zone == nil {
		return f.response(req, dns.RcodeNameError), nil
	}

	resp := f.response(req, dns.RcodeSuccess)
	for _, rr := range zone.Records[name] {
		if rr.Header().Rrtype == q.Qtype || q.Qtype == dns.TypeANY {
			resp.Answer = append(resp.Answer, dns.Copy(rr))
		}
	}
	if len(resp.Answer) == 0 {
		if soa := zoneSOA(zone); soa != nil {
			resp.Ns = append(resp.Ns, dns.Copy(soa))
		}
	}
	if zone.Recursive && q.Qtype != dns.TypeAXFR {
		resp.RecursionAvailable = true
		resp.Answer = append(resp.Answer, f.defaultRecursionAnswer(req)...)
	}
	return resp, nil
}

// Transfer serves an AXFR if allowed, bounded by TransferLimit.
func (f *FakeResolver) Transfer(ctx context.Context, server string, req *dns.Msg) ([]dns.RR, error) {
	if req == nil || len(req.Question) == 0 {
		return nil, ErrNoQuestion
	}
	q := req.Question[0]
	zone := f.findZone(dns.Fqdn(strings.ToLower(q.Name)))
	if zone == nil {
		return nil, ErrZoneRefused
	}
	if !zone.TransferAllowed {
		return nil, ErrZoneRefused
	}
	var out []dns.RR
	for _, rr := range zone.Records[zone.Name] {
		out = append(out, dns.Copy(rr))
		if f.TransferLimit > 0 && len(out) >= f.TransferLimit {
			return out, nil
		}
	}
	return out, nil
}

func (f *FakeResolver) record(q dns.Question) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.QueryLog = append(f.QueryLog, LoggedQuery{Name: q.Name, Type: q.Qtype, Server: "fake"})
}

func (f *FakeResolver) findZone(name string) *Zone {
	var best *Zone
	bestLen := -1
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, z := range f.zones {
		lz := dns.Fqdn(strings.ToLower(z.Name))
		if name == lz || strings.HasSuffix(name, "."+lz) {
			if l := len(z.Name); l > bestLen {
				best = z
				bestLen = l
			}
		}
	}
	return best
}

func (f *FakeResolver) response(req *dns.Msg, rcode int) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetRcode(req, rcode)
	resp.Id = req.Id
	return resp
}

func zoneSOA(z *Zone) dns.RR {
	if z.SOAOverride != nil {
		return z.SOAOverride
	}
	for _, rr := range z.Records[dns.Fqdn(strings.ToLower(z.Name))] {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa
		}
	}
	return nil
}

func (f *FakeResolver) defaultRecursionAnswer(req *dns.Msg) []dns.RR {
	if len(f.DefaultFallback) > 0 {
		return f.DefaultFallback
	}
	a := new(dns.A)
	a.Hdr = dns.RR_Header{Name: dns.Fqdn(strings.ToLower(req.Question[0].Name)), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}
	a.A = net.ParseIP("93.184.216.34")
	return []dns.RR{a}
}
