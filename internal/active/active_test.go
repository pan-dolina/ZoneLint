package active

import (
	"net"
	"testing"

	"github.com/miekg/dns"

	"github.com/pan-dolina/ZoneLint/internal/findings"
)

func TestOpenRecursion(t *testing.T) {
	resp := new(dns.Msg)
	resp.RecursionAvailable = true
	resp.Rcode = dns.RcodeSuccess
	resp.Answer = []dns.RR{} // would have an answer in reality
	// Simulate a recursive answer with a record.
	a := new(dns.A)
	a.Hdr = dns.RR_Header{Name: "random.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}
	a.A = net.ParseIP("93.184.216.34")
	resp.Answer = []dns.RR{a}

	r := CheckRecursion("ns1.example.test.", "example.test.", resp)
	if !r.Recursive {
		t.Fatalf("expected recursive, got %+v", r)
	}
	fs := Check("ns1.example.test.", "example.test.", r)
	if len(fs) == 0 || fs[0].ID != findings.RecursionOpen.ID {
		t.Fatalf("expected open recursion finding, got %+v", fs)
	}
}

func TestAuthoritativeNoRecursion(t *testing.T) {
	resp := new(dns.Msg)
	resp.RecursionAvailable = false
	resp.Rcode = dns.RcodeNameError
	r := CheckRecursion("ns1.example.test.", "example.test.", resp)
	if r.Recursive {
		t.Fatal("did not expect recursion")
	}
	fs := Check("ns1.example.test.", "example.test.", r)
	if len(fs) != 0 {
		t.Fatalf("expected no findings, got %+v", fs)
	}
}

func TestRandomName(t *testing.T) {
	name, err := RandomName("example.test.")
	if err != nil {
		t.Fatal(err)
	}
	if len(name) < len("example.test.") {
		t.Fatal("name too short")
	}
}
