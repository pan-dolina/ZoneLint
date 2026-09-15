package addrs

import (
	"testing"

	testzones "github.com/pan-dolina/ZoneLint/testdata"
)

// BenchmarkCheckAllLargeZone benchmarks address classification over a large
// zone with many records.
func BenchmarkCheckAllLargeZone(b *testing.B) {
	zone := testzones.PrivateAddr()
	records := zone.Records["privateaddr.test."]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CheckAll("privateaddr.test.", records)
	}
}

// BenchmarkCheckAllWildcard benchmarks address classification over a wildcard
// zone.
func BenchmarkCheckAllWildcard(b *testing.B) {
	zone := testzones.Wildcard()
	records := zone.Records["wildcard.test."]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CheckAll("wildcard.test.", records)
	}
}

// BenchmarkCheckAllCAA benchmarks CAA record classification.
func BenchmarkCheckAllCAA(b *testing.B) {
	zone := testzones.MalformedCAA()
	records := zone.Records["malformedcaa.test."]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CheckAll("malformedcaa.test.", records)
	}
}
