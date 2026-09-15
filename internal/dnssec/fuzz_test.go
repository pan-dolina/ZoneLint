package dnssec

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"testing"

	"github.com/miekg/dns"
)

func seedDNSKEYRData() []byte {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	out := make([]byte, 3)
	binary.BigEndian.PutUint16(out, 256) // flags
	out = append(out, 15)                // algorithm: Ed25519
	out = append(out, pub...)
	return out
}

// FuzzParseDNSKEY fuzzes DNSKEY parsing with arbitrary rdata bytes.
func FuzzParseDNSKEY(f *testing.F) {
	f.Add(seedDNSKEYRData())

	f.Fuzz(func(t *testing.T, data []byte) {
		rr := new(dns.DNSKEY)
		rr.Flags = 256
		rr.Protocol = 1
		rr.Algorithm = 15
		if len(data) > 3 {
			rr.PublicKey = base64.StdEncoding.EncodeToString(data[3:])
		}
		_, _ = ParseDNSKEY(rr)
	})
}

// FuzzKeyTag fuzzes key tag computation stability.
func FuzzKeyTag(f *testing.F) {
	f.Fuzz(func(t *testing.T, flags uint16, algo uint8, keyLen int) {
		// Bound the key length to a sane range to avoid huge allocations.
		if keyLen < 0 {
			keyLen = -keyLen
		}
		keyLen %= 128
		key := make([]byte, keyLen)
		_, _ = rand.Read(key)
		_ = KeyTag(flags, algo, key)
	})
}
