package ttl

import (
	"testing"

	"github.com/miekg/dns"

	"github.com/example/ZoneLint/testdata"
)

func txtRecord(name, value string, ttl uint32) dns.RR {
	r := new(dns.TXT)
	r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl}
	r.Txt = []string{value}
	return r
}

// BenchmarkCheckShortTTL benchmarks TTL policy checking over a zone with
// short TTLs.
func BenchmarkCheckShortTTL(b *testing.B) {
	zone := testzones.ShortTTL()
	c := NewCollector()
	for _, rr := range zone.Records["shortttl.test."] {
		c.Add(rr)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Check("shortttl.test.", string(ProfileBalanced), c)
	}
}

// BenchmarkCheckExtremeTTL benchmarks TTL policy checking over a zone with
// extreme TTLs.
func BenchmarkCheckExtremeTTL(b *testing.B) {
	zone := testzones.ExtremeTTL()
	c := NewCollector()
	for _, rr := range zone.Records["extremettl.test."] {
		c.Add(rr)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Check("extremettl.test.", string(ProfileConservative), c)
	}
}

// BenchmarkCollectorAdd benchmarks collecting TTLs from a DNS response.
func BenchmarkCollectorAdd(b *testing.B) {
	resp := &dns.Msg{}
	resp.Answer = []dns.RR{
		txtRecord("host.test.", "v=spf1 -all", 300),
		txtRecord("host.test.", "v=spf1 -all", 3600),
		txtRecord("host.test.", "v=spf1 -all", 86400),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := NewCollector()
		c.CollectAll(resp)
	}
}
