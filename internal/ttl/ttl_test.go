package ttl

import (
	"testing"

	"github.com/miekg/dns"

	"github.com/example/ZoneLint/internal/findings"
)

func soaRR(ttl uint32) dns.RR {
	r := new(dns.SOA)
	r.Hdr = dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl}
	r.Ns = "ns1.example.test."
	r.Mbox = "admin.example.test."
	return r
}

func nsRR(ttl uint32) dns.RR {
	r := new(dns.NS)
	r.Hdr = dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl}
	r.Ns = "ns1.example.test."
	return r
}

func TestLowTTLInfo(t *testing.T) {
	c := NewCollector()
	c.Add(soaRR(10))
	c.Add(nsRR(10))
	fs := Check("example.test.", string(ProfileBalanced), c)
	if !hasID(fs, findings.TTLShort) {
		t.Fatalf("expected low TTL info finding, got %+v", fs)
	}
	for _, f := range fs {
		if f.Severity != string(findings.SeverityInfo) {
			t.Fatalf("expected info severity, got %s", f.Severity)
		}
	}
}

func TestExtremeTTL(t *testing.T) {
	c := NewCollector()
	c.Add(soaRR(1000000000))
	fs := Check("example.test.", string(ProfileBalanced), c)
	if !hasID(fs, findings.TTLExtreme) {
		t.Fatalf("expected extreme TTL finding, got %+v", fs)
	}
}

func TestWithinProfile(t *testing.T) {
	c := NewCollector()
	c.Add(soaRR(3600))
	c.Add(nsRR(3600))
	fs := Check("example.test.", string(ProfileBalanced), c)
	for _, f := range fs {
		if f.Severity != string(findings.SeverityPass) {
			t.Fatalf("expected pass, got %+v", fs)
		}
	}
}

func TestConservativeStricter(t *testing.T) {
	c := NewCollector()
	c.Add(soaRR(120)) // below conservative min (300) but above balanced (60)
	fs := Check("example.test.", string(ProfileConservative), c)
	if !hasID(fs, findings.TTLShort) {
		t.Fatalf("conservative should flag 120s TTL, got %+v", fs)
	}
	fs = Check("example.test.", string(ProfileBalanced), c)
	if hasID(fs, findings.TTLShort) {
		t.Fatalf("balanced should not flag 120s TTL, got %+v", fs)
	}
}

func TestProfilesDiffer(t *testing.T) {
	consMin, _ := ProfileConservative.Limits()
	agileMin, _ := ProfileAgile.Limits()
	if consMin <= agileMin {
		t.Fatal("conservative min should be stricter than agile")
	}
}

func TestNow(t *testing.T) {
	if Now().Year() < 2024 {
		t.Fatal("now broken")
	}
}

func hasID(fs []*findings.Finding, id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}
