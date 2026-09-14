package cname

import (
	"testing"

	"github.com/miekg/dns"

	"github.com/example/ZoneLint/internal/findings"
)

func cnameRR(name, target string) dns.RR {
	r := new(dns.CNAME)
	r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}
	r.Target = target
	return r
}

func TestLoop(t *testing.T) {
	g := Build([]dns.RR{
		cnameRR("a.example.test.", "b.example.test."),
		cnameRR("b.example.test.", "a.example.test."),
	})
	fs := Check("example.test.", g, 8, func(string) bool { return true })
	if !hasLoop(fs) {
		t.Fatalf("expected loop finding, got %+v", fs)
	}
}

func TestDangling(t *testing.T) {
	g := Build([]dns.RR{
		cnameRR("cdn.example.test.", "missing.provider.net."),
	})
	// resolveTarget reports that the target does not resolve.
	fs := Check("example.test.", g, 8, func(string) bool { return false })
	if !hasDangling(fs) {
		t.Fatalf("expected dangling finding, got %+v", fs)
	}
}

func TestHealthyChain(t *testing.T) {
	g := Build([]dns.RR{
		cnameRR("www.example.test.", "example.test."),
	})
	fs := Check("example.test.", g, 8, func(string) bool { return true })
	for _, f := range fs {
		if f.Severity != "pass" {
			t.Fatalf("expected pass, got %+v", fs)
		}
	}
}

func hasLoop(fs []*findings.Finding) bool {
	for _, f := range fs {
		if f.ID == "DNS-CNAME-001" {
			return true
		}
	}
	return false
}

func hasDangling(fs []*findings.Finding) bool {
	for _, f := range fs {
		if f.ID == "DNS-CNAME-004" {
			return true
		}
	}
	return false
}
