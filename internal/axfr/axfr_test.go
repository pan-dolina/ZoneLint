package axfr

import (
	"testing"

	"github.com/miekg/dns"
)

func TestAllowed(t *testing.T) {
	resp := new(dns.Msg)
	resp.Rcode = dns.RcodeSuccess
	rr := new(dns.NS)
	rr.Hdr = dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}
	rr.Ns = "ns1.example.test."
	resp.Answer = []dns.RR{rr}
	o := ParseTransferResult(resp, DefaultConfig())
	if o.Status != "allowed" {
		t.Fatalf("expected allowed, got %s", o.Status)
	}
	fs := Evaluate("example.test.", "ns1.example.test.", o)
	if len(fs) == 0 || fs[0].ID != "DNS-AXFR-001" {
		t.Fatalf("expected critical AXFR finding, got %+v", fs)
	}
}

func TestRefused(t *testing.T) {
	resp := new(dns.Msg)
	resp.Rcode = dns.RcodeRefused
	o := ParseTransferResult(resp, DefaultConfig())
	if o.Status != "refused" {
		t.Fatalf("expected refused, got %s", o.Status)
	}
}

func TestFailed(t *testing.T) {
	o := ParseTransferResult(nil, DefaultConfig())
	if o.Status != "failed" {
		t.Fatalf("expected failed, got %s", o.Status)
	}
}

func TestLimitRecords(t *testing.T) {
	records := make([]dns.RR, 1500)
	for i := range records {
		rr := new(dns.NS)
		rr.Hdr = dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}
		rr.Ns = "ns1.example.test."
		records[i] = rr
	}
	limited := LimitRecords(records, 1000)
	if len(limited) != 1000 {
		t.Fatalf("expected 1000 limited records, got %d", len(limited))
	}
}
