package soa

import (
	"testing"

	"github.com/miekg/dns"
)

func makeSOA(zone, mname, mbox string, serial, refresh, retry, expire, mintl uint32) dns.RR {
	soa := new(dns.SOA)
	soa.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600}
	soa.Ns = mname
	soa.Mbox = mbox
	soa.Serial = serial
	soa.Refresh = refresh
	soa.Retry = retry
	soa.Expire = expire
	soa.Minttl = mintl
	return soa
}

// BenchmarkCheckValid benchmarks SOA validation over a valid SOA record.
func BenchmarkCheckValid(b *testing.B) {
	soa := makeSOA("example.test.", "ns1.example.test.", "admin.example.test.", 2024010101, 7200, 1800, 1209600, 3600)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Check("example.test.", soa.(*dns.SOA))
	}
}

// BenchmarkCheckStaleGlue benchmarks SOA validation over a SOA with stale TTL.
func BenchmarkCheckStaleGlue(b *testing.B) {
	soa := makeSOA("example.test.", "ns1.example.test.", "admin.example.test.", 2024010101, 60, 60, 3600, 60)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Check("example.test.", soa.(*dns.SOA))
	}
}
