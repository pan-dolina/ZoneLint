package caa

import (
	"testing"

	"github.com/miekg/dns"
)

func caa(flag byte, tag, value string) dns.RR {
	r := new(dns.CAA)
	r.Hdr = dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 300}
	r.Flag = flag
	r.Tag = tag
	r.Value = value
	return r
}

func TestValidIssue(t *testing.T) {
	fs := Check("example.test.", []dns.RR{caa(0, "issue", "letsencrypt.org")})
	if len(fs) != 0 {
		t.Fatalf("expected no findings, got %+v", fs)
	}
}

func TestUnknownCritical(t *testing.T) {
	fs := Check("example.test.", []dns.RR{caa(1, "issuetoken", "url=http://e")})
	if len(fs) == 0 {
		t.Fatal("expected unknown critical finding")
	}
}

func TestMalformedIODF(t *testing.T) {
	fs := Check("example.test.", []dns.RR{caa(0, "iodef", "ftp://bad")})
	if len(fs) == 0 {
		t.Fatal("expected malformed finding")
	}
}

func TestNoCAA(t *testing.T) {
	fs := Check("example.test.", nil)
	if len(fs) != 0 {
		t.Fatalf("expected no findings, got %+v", fs)
	}
}

func TestIssueDeny(t *testing.T) {
	fs := Check("example.test.", []dns.RR{caa(0, "issue", ";")})
	if len(fs) != 0 {
		t.Fatalf("expected deny-all valid, got %+v", fs)
	}
}
