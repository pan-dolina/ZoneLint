package addrs

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func aRecord(ip string) dns.RR {
	r := new(dns.A)
	r.Hdr = dns.RR_Header{Name: "host.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}
	r.A = net.ParseIP(ip)
	return r
}

func TestClassifyPrivate(t *testing.T) {
	c := Classify(net.ParseIP("10.0.0.5"))
	if c == nil || c.Category != "private" {
		t.Fatalf("expected private, got %+v", c)
	}
}

func TestClassifyPublic(t *testing.T) {
	if Classify(net.ParseIP("93.184.216.34")) != nil {
		t.Fatal("expected public IP to be nil")
	}
}

func TestClassifyLoopback(t *testing.T) {
	c := Classify(net.ParseIP("127.0.0.1"))
	if c == nil || c.Category != "loopback" {
		t.Fatalf("expected loopback, got %+v", c)
	}
}

func TestClassifyDoc(t *testing.T) {
	c := Classify(net.ParseIP("203.0.113.5"))
	if c == nil || c.Category != "documentation" {
		t.Fatalf("expected documentation, got %+v", c)
	}
}

func TestCheckAll(t *testing.T) {
	fs := CheckAll("example.test.", []dns.RR{
		aRecord("10.0.0.1"),
		aRecord("93.184.216.34"), // public, ignored
	})
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %+v", fs)
	}
}

func TestClassifyIPv6(t *testing.T) {
	if Classify(net.ParseIP("2001:4860:4860::8888")) != nil {
		t.Fatal("expected public IPv6 to be nil")
	}
	if Classify(net.ParseIP("::1")) == nil {
		t.Fatal("expected loopback IPv6 flagged")
	}
	if Classify(net.ParseIP("fc00::1")) == nil {
		t.Fatal("expected ULA flagged")
	}
}
