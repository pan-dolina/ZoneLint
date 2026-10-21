package dnsutil

import (
	"bytes"
	"testing"

	"github.com/miekg/dns"
)

// wireRDATA packs rr with miekg/dns (compression off) and returns the raw
// wire RDATA, which is the ground truth for canonical RDATA encoding.
func wireRDATA(t *testing.T, rr dns.RR) []byte {
	t.Helper()
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{rr}
	buf, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	ownerBuf := make([]byte, 256)
	ownerLen, err := dns.PackDomainName(rr.Header().Name, ownerBuf, 0, nil, false)
	if err != nil {
		t.Fatalf("pack owner: %v", err)
	}
	rdlengthOff := 12 + ownerLen + 8
	if len(buf) < rdlengthOff+2 {
		t.Fatal("packed message too short")
	}
	rdlength := int(buf[rdlengthOff])<<8 | int(buf[rdlengthOff+1])
	start := rdlengthOff + 2
	if len(buf) < start+rdlength {
		t.Fatal("packed rdata truncated")
	}
	return buf[start : start+rdlength]
}

func TestRRDataSOA(t *testing.T) {
	soa := &dns.SOA{
		Hdr:    dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 1800},
		Ns:     "ns1.example.test.",
		Mbox:   "admin.example.test.",
		Serial: 2024010101, Refresh: 7200, Retry: 1800, Expire: 1209600, Minttl: 3600,
	}
	if got, want := RRData(soa), wireRDATA(t, soa); !bytes.Equal(got, want) {
		t.Fatalf("SOA rdata mismatch:\n got %x\nwant %x", got, want)
	}
}

func TestRRDataDNSKEY(t *testing.T) {
	dk := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: "mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
	}
	if got, want := RRData(dk), wireRDATA(t, dk); !bytes.Equal(got, want) {
		t.Fatalf("DNSKEY rdata mismatch:\n got %x\nwant %x", got, want)
	}
}

func TestRRDataNSECMultiWindow(t *testing.T) {
	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "furtangfw.net.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 1800},
		NextDomain: `\000.furtangfw.net.`,
		TypeBitMap: []uint16{
			dns.TypeA, dns.TypeNS, dns.TypeSOA, dns.TypePTR, dns.TypeHINFO, dns.TypeTXT,
			dns.TypeAAAA, dns.TypeLOC, dns.TypeSRV, dns.TypeNAPTR, dns.TypeCERT, dns.TypeSSHFP,
			dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY, dns.TypeTLSA, dns.TypeSMIMEA,
			dns.TypeHIP, dns.TypeCDS, dns.TypeCDNSKEY, dns.TypeOPENPGPKEY,
			64, 65, dns.TypeURI, dns.TypeCAA,
		},
	}
	if got, want := RRData(nsec), wireRDATA(t, nsec); !bytes.Equal(got, want) {
		t.Fatalf("NSEC rdata mismatch:\n got %x\nwant %x", got, want)
	}
}

func TestRRDataNSEC3(t *testing.T) {
	nsec3 := &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: "ck0po2mn6jp3vg1u1u3hvn4p6fm0p0cl.example.", Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300},
		Hash:       1,
		Flags:      1,
		Iterations: 0,
		Salt:       "aabbcc",
		SaltLength: 3,
		NextDomain: "ck0q1gin1jolica2dn0jv0sl4jb7j2m6",
		HashLength: 20,
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC3},
	}
	if got, want := RRData(nsec3), wireRDATA(t, nsec3); !bytes.Equal(got, want) {
		t.Fatalf("NSEC3 rdata mismatch:\n got %x\nwant %x", got, want)
	}
}
