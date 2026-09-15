package nsec

import (
	"testing"

	"github.com/miekg/dns"

	"github.com/pan-dolina/ZoneLint/internal/findings"
)

func TestNoNSEC(t *testing.T) {
	a := Analyze(nil)
	fs := Check("example.test.", a)
	if !hasNoNSEC(fs) {
		t.Fatalf("expected no-NSEC finding, got %+v", fs)
	}
}

func TestMalformedNSEC3(t *testing.T) {
	rr := new(dns.NSEC3)
	rr.Hdr = dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 3600}
	rr.Iterations = 0
	rr.SaltLength = 0
	a := Analyze([]dns.RR{rr})
	fs := Check("example.test.", a)
	if !hasMalformed(fs) {
		t.Fatalf("expected malformed finding, got %+v", fs)
	}
}

func TestValidNSEC(t *testing.T) {
	rr := new(dns.NSEC)
	rr.Hdr = dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600}
	a := Analyze([]dns.RR{rr})
	fs := Check("example.test.", a)
	for _, f := range fs {
		if f.ID == findings.DNSSECNoNSEC.ID {
			t.Fatal("NSEC present should not flag no-NSEC")
		}
	}
}

func hasNoNSEC(fs []*finding) bool {
	for _, f := range fs {
		if f.ID == findings.DNSSECNoNSEC.ID {
			return true
		}
	}
	return false
}

func hasMalformed(fs []*finding) bool {
	for _, f := range fs {
		if f.ID == findings.DNSSECMalformedNSEC3.ID {
			return true
		}
	}
	return false
}

type finding = findings.Finding
