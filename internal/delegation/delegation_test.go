package delegation

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	dnsutil "github.com/example/ZoneLint/internal/dns"
	"github.com/example/ZoneLint/internal/findings"
)

func nsRR(zone, host string, ttl uint32) dns.RR {
	r := new(dns.NS)
	r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl}
	r.Ns = host
	return r
}

func aRR(name, ip string, ttl uint32) dns.RR {
	r := new(dns.A)
	r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
	r.A = net.ParseIP(ip)
	return r
}

func TestInconsistentNS(t *testing.T) {
	parent := ParentView{
		NS:   []string{"ns1.example.test.", "ns2.example.test."},
		NSRR: []dns.RR{nsRR("example.test.", "ns1.example.test.", 3600), nsRR("example.test.", "ns2.example.test.", 3600)},
		Glue: map[string][]net.IP{"ns1.example.test.": {net.ParseIP("198.51.100.1")}},
	}
	child := ChildView{
		NS:            []string{"ns1.example.test.", "ns3.example.test."},
		NSRR:          []dns.RR{nsRR("example.test.", "ns1.example.test.", 3600), nsRR("example.test.", "ns3.example.test.", 3600)},
		Authoritative: true,
	}
	fs := Compare("example.test.", parent, child, time.Now())
	if !hasID(fs, findings.DelegInconsistentNS) {
		t.Fatalf("expected inconsistent NS finding, got: %+v", fs)
	}
}

func TestLameDelegation(t *testing.T) {
	parent := ParentView{
		NS:   []string{"ns1.example.test."},
		NSRR: []dns.RR{nsRR("example.test.", "ns1.example.test.", 3600)},
	}
	child := ChildView{
		NS:            []string{"ns1.example.test."},
		NSRR:          []dns.RR{nsRR("example.test.", "ns1.example.test.", 3600)},
		Authoritative: false, // lame: AA=0
	}
	fs := Compare("example.test.", parent, child, time.Now())
	if !hasID(fs, findings.DelegLame) {
		t.Fatalf("expected lame delegation finding, got: %+v", fs)
	}
}

func TestMissingGlue(t *testing.T) {
	parent := ParentView{
		NS:   []string{"ns1.sub.example.test."},
		NSRR: []dns.RR{nsRR("example.test.", "ns1.sub.example.test.", 3600)},
		// In-bailiwick NS with no glue
	}
	child := ChildView{
		NS:            []string{"ns1.sub.example.test."},
		NSRR:          []dns.RR{nsRR("example.test.", "ns1.sub.example.test.", 3600)},
		Authoritative: true,
	}
	fs := Compare("example.test.", parent, child, time.Now())
	if !hasID(fs, findings.DelegMissingGlue) {
		t.Fatalf("expected missing glue finding, got: %+v", fs)
	}
}

func TestHealthyDelegation(t *testing.T) {
	parent := ParentView{
		NS:   []string{"ns1.example.test.", "ns2.example.test."},
		NSRR: []dns.RR{nsRR("example.test.", "ns1.example.test.", 3600), nsRR("example.test.", "ns2.example.test.", 3600)},
		Glue: map[string][]net.IP{
			"ns1.example.test.": {net.ParseIP("198.51.100.1")},
			"ns2.example.test.": {net.ParseIP("198.51.100.2")},
		},
	}
	child := ChildView{
		NS:            []string{"ns1.example.test.", "ns2.example.test."},
		NSRR:          []dns.RR{nsRR("example.test.", "ns1.example.test.", 3600), nsRR("example.test.", "ns2.example.test.", 3600)},
		Authoritative: true,
	}
	fs := Compare("example.test.", parent, child, time.Now())
	for _, f := range fs {
		if f.Severity != string(findings.SeverityPass) {
			t.Fatalf("expected only pass findings, got %+v", fs)
		}
	}
}

func TestExtractNSFromResponse(t *testing.T) {
	resp := new(dns.Msg)
	resp.Answer = []dns.RR{
		nsRR("example.test.", "ns1.example.test.", 3600),
		nsRR("example.test.", "ns2.example.test.", 3600),
		aRR("ns1.example.test.", "198.51.100.1", 3600),
	}
	view := ExtractNSFromResponse(resp, "example.test.")
	if len(view.NS) != 2 {
		t.Fatalf("expected 2 NS, got %v", view.NS)
	}
	if len(view.Glue["ns1.example.test."]) != 1 {
		t.Fatalf("expected glue for ns1, got %v", view.Glue)
	}
	// Ensure NSNames helper agrees.
	if len(dnsutil.NSNames(view.NSRR)) != 2 {
		t.Fatal("NSNames mismatch")
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
