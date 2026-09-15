package delegation

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// BenchmarkCompareInconsistent benchmarks delegation comparison over a zone
// with inconsistent NS sets.
func BenchmarkCompareInconsistent(b *testing.B) {
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

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Compare("example.test.", parent, child, time.Now())
	}
}

// BenchmarkCompareHealthy benchmarks delegation comparison over a healthy zone.
func BenchmarkCompareHealthy(b *testing.B) {
	parent := ParentView{
		NS:   []string{"ns1.example.test.", "ns2.example.test."},
		NSRR: []dns.RR{nsRR("example.test.", "ns1.example.test.", 3600), nsRR("example.test.", "ns2.example.test.", 3600)},
		Glue: map[string][]net.IP{"ns1.example.test.": {net.ParseIP("198.51.100.1")}},
	}
	child := ChildView{
		NS:            []string{"ns1.example.test.", "ns2.example.test."},
		NSRR:          []dns.RR{nsRR("example.test.", "ns1.example.test.", 3600), nsRR("example.test.", "ns2.example.test.", 3600)},
		Authoritative: true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Compare("example.test.", parent, child, time.Now())
	}
}
