package dnssec

import (
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/example/ZoneLint/testdata"
)

// BenchmarkCheckZoneExpired benchmarks DNSSEC validation over a zone with
// expired signatures.
func BenchmarkCheckZoneExpired(b *testing.B) {
	zone := testzones.ExpireDNSSec()
	resp := &dns.Msg{}
	resp.Answer = zone.Records["expireddnssec.test."]
	zk := Collect(resp)

	now := time.Now()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CheckZone("expireddnssec.test.", zk, now)
	}
}

// BenchmarkCheckZoneBroken benchmarks DNSSEC validation over a zone with
// incomplete DNSSEC (DNSKEY but no RRSIG).
func BenchmarkCheckZoneBroken(b *testing.B) {
	zone := testzones.BrokenDNSSec()
	resp := &dns.Msg{}
	resp.Answer = zone.Records["brokendnssec.test."]
	zk := Collect(resp)

	now := time.Now()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CheckZone("brokendnssec.test.", zk, now)
	}
}

// BenchmarkCollect benchmarks collecting DNSKEY/RRSIG/DS records from a
// response.
func BenchmarkCollect(b *testing.B) {
	zone := testzones.ExpireDNSSec()
	resp := &dns.Msg{}
	resp.Answer = zone.Records["expireddnssec.test."]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Collect(resp.Copy())
	}
}
