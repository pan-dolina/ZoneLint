package authserver

import (
	"testing"

	"github.com/miekg/dns"

	dnsutil "github.com/pan-dolina/ZoneLint/internal/dns"
	"github.com/pan-dolina/ZoneLint/internal/findings"
)

func TestUnreachable(t *testing.T) {
	fs := CheckServer("example.test.", "ns1.example.test.", nil)
	if len(fs) != 1 || fs[0].ID != findings.AuthUDPFail.ID {
		t.Fatalf("expected unreachable finding, got %+v", fs)
	}
}

func TestLameServer(t *testing.T) {
	resp := new(dns.Msg)
	resp.Authoritative = false // no AA
	resp.Rcode = dns.RcodeSuccess
	pr := ProbeResponse(resp)
	pr.UDPReachable = true // reachable but non-authoritative
	fs := CheckServer("example.test.", "ns1.example.test.", pr)
	if !hasID(fs, findings.AuthNoAA.ID) {
		t.Fatalf("expected no-AA finding, got %+v", fs)
	}
}

func TestGoodServer(t *testing.T) {
	soa := new(dns.SOA)
	soa.Hdr = dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600}
	soa.Ns = "ns1.example.test."
	soa.Mbox = "admin.example.test."
	ns := new(dns.NS)
	ns.Hdr = dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}
	ns.Ns = "ns1.example.test."

	resp := new(dns.Msg)
	resp.Authoritative = true
	resp.Rcode = dns.RcodeSuccess
	resp.Answer = []dns.RR{ns}
	resp.Ns = []dns.RR{soa}
	dnsutil.SetEDNS(resp, 1232, true)

	pr := ProbeResponse(resp)
	pr.UDPReachable = true
	pr.TCPReachable = true
	pr.AA = true
	pr.HasSOA = true
	pr.HasNS = true
	pr.HasEDNS = true
	pr.Consistent = true
	fs := CheckServer("example.test.", "ns1.example.test.", pr)
	for _, f := range fs {
		if f.Severity != findings.SeverityPass && f.Severity != findings.SeverityInfo {
			t.Fatalf("expected pass/info, got %+v", fs)
		}
	}
}

func hasID(fs []*finding, id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}

type finding = findings.Finding
