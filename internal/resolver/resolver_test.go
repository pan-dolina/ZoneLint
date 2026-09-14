package resolver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/example/ZoneLint/internal/budget"

	"github.com/example/ZoneLint/internal/dns"
)

func buildSOA(zone, mname, rname string, serial, refresh, retry, expire, minimum uint32) dns.RR {
	soa := new(dns.SOA)
	soa.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600}
	soa.Ns = mname
	soa.Mbox = rname
	soa.Serial = serial
	soa.Refresh = refresh
	soa.Retry = retry
	soa.Expire = expire
	soa.Minttl = minimum
	return soa
}

func buildNS(zone, ns string) dns.RR {
	n := new(dns.NS)
	n.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}
	n.Ns = ns
	return n
}

func buildA(name, ip string, ttl uint32) dns.RR {
	a := new(dns.A)
	a.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
	a.A = mustParseIP(ip)
	return a
}

func mustParseIP(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		panic("bad ip: " + s)
	}
	return ip
}

func TestFakeResolverServesNS(t *testing.T) {
	f := NewFake()
	zone := "example.test."
	f.AddZone(&Zone{
		Name: zone,
		Records: map[string][]dns.RR{
			zone: {
				buildSOA(zone, "ns1.example.test.", "admin.example.test.", 2024010101, 7200, 3600, 1209600, 300),
				buildNS(zone, "ns1.example.test."),
				buildNS(zone, "ns2.example.test."),
				buildA("ns1.example.test.", "198.51.100.1", 3600),
				buildA("ns2.example.test.", "198.51.100.2", 3600),
			},
		},
	})

	req := dnsutil.SafeNewMsg("example.test.", dns.TypeNS)
	resp, err := f.Query(context.Background(), "fake", req)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected rcode success, got %s", dns.RcodeToString[resp.Rcode])
	}
	ns := dnsutil.NSNames(resp.Answer)
	if len(ns) != 2 {
		t.Fatalf("expected 2 NS records, got %v", ns)
	}
}

func TestFakeResolverNXDOMAIN(t *testing.T) {
	f := NewFake()
	req := dnsutil.SafeNewMsg("missing.test.", dns.TypeA)
	resp, err := f.Query(context.Background(), "fake", req)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got %s", dns.RcodeToString[resp.Rcode])
	}
}

func TestFakeResolverAXFRRefused(t *testing.T) {
	f := NewFake()
	f.AddZone(&Zone{Name: "axfr.test.", Records: map[string][]dns.RR{}})
	req := dnsutil.SafeNewMsg("axfr.test.", dns.TypeAXFR)
	_, err := f.Transfer(context.Background(), "fake", req)
	if err == nil {
		t.Fatal("expected transfer refused error")
	}
}

func TestFakeResolverAXFRAllowed(t *testing.T) {
	f := NewFake()
	zone := "axfr.test."
	f.AddZone(&Zone{
		Name:            zone,
		TransferAllowed: true,
		Records: map[string][]dns.RR{
			zone: {
				buildSOA(zone, "ns1.axfr.test.", "admin.axfr.test.", 1, 1, 1, 1, 1),
				buildNS(zone, "ns1.axfr.test."),
			},
		},
	})
	req := dnsutil.SafeNewMsg("axfr.test.", dns.TypeAXFR)
	recs, err := f.Transfer(context.Background(), "fake", req)
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}
	if len(recs) < 2 {
		t.Fatalf("expected at least 2 records, got %d", len(recs))
	}
}

func TestFakeResolverQueryLog(t *testing.T) {
	f := NewFake()
	f.AddZone(&Zone{Name: "example.test.", Records: map[string][]dns.RR{}})
	req := dnsutil.SafeNewMsg("example.test.", dns.TypeA)
	_, _ = f.Query(context.Background(), "fake", req)
	if len(f.QueryLog) != 1 {
		t.Fatalf("expected 1 logged query, got %d", len(f.QueryLog))
	}
	if f.QueryLog[0].Name != "example.test." {
		t.Fatalf("unexpected logged query name %q", f.QueryLog[0].Name)
	}
}

func TestFakeResolverRecursive(t *testing.T) {
	f := NewFake()
	f.AddZone(&Zone{Name: "recursion.test.", Recursive: true, Records: map[string][]dns.RR{}})
	req := dnsutil.SafeNewMsg("anything.recursion.test.", dns.TypeA)
	resp, err := f.Query(context.Background(), "fake", req)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if !resp.RecursionAvailable {
		t.Fatal("expected recursion available flag")
	}
}

func TestBudgetExhaustion(t *testing.T) {
	c := budget.NewCounter(1)
	if !c.Consume() {
		t.Fatal("first consume should succeed")
	}
	if c.Consume() {
		t.Fatal("second consume should fail")
	}
	if c.Remaining() != 0 {
		t.Fatalf("expected 0 remaining, got %d", c.Remaining())
	}
}

func TestRateLimiter(t *testing.T) {
	rl := budget.NewRateLimiter(100)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := rl.Wait(ctx); err != nil {
		t.Fatalf("rate limiter wait: %v", err)
	}
}
