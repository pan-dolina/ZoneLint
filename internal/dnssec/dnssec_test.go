package dnssec

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type testPrivKey struct {
	priv   ed25519.PrivateKey
	keyTag uint16
}

func newTestPrivKey(t *testing.T, flags uint16) *testPrivKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	dk := new(dns.DNSKEY)
	dk.Hdr = dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}
	dk.Flags = flags
	dk.Protocol = 1
	dk.Algorithm = Ed25519
	dk.PublicKey = base64.StdEncoding.EncodeToString(pub)
	k, err := ParseDNSKEY(dk)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	return &testPrivKey{priv: priv, keyTag: k.KeyTag}
}

func (k *testPrivKey) sign(name string, rtype uint16, rdata []byte, now time.Time, ttl uint32) *dns.RRSIG {
	inc := uint32(now.Unix())
	exp := uint32(now.Add(48 * time.Hour).Unix())
	rsigRdata := make([]byte, 18)
	binary.BigEndian.PutUint16(rsigRdata[0:2], rtype)
	rsigRdata[2] = Ed25519
	rsigRdata[3] = 1
	binary.BigEndian.PutUint32(rsigRdata[4:8], ttl)
	binary.BigEndian.PutUint32(rsigRdata[8:12], exp)
	binary.BigEndian.PutUint32(rsigRdata[12:16], inc)
	binary.BigEndian.PutUint16(rsigRdata[16:18], k.keyTag)

	msg := append(append([]byte{}, rsigRdata...), rdata...)
	sig := ed25519.Sign(k.priv, msg)

	r := new(dns.RRSIG)
	r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: ttl}
	r.TypeCovered = rtype
	r.Algorithm = Ed25519
	r.Labels = 1
	r.OrigTtl = ttl
	r.Expiration = exp
	r.Inception = inc
	r.KeyTag = k.keyTag
	r.SignerName = "example.test."
	r.Signature = string(sig)
	return r
}

func mustParseIP(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		panic("bad ip " + s)
	}
	return ip
}

func makeARR(name string, ip string, ttl uint32) dns.RR {
	a := new(dns.A)
	a.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
	a.A = mustParseIP(ip)
	return a
}

func TestKeyTagNonZero(t *testing.T) {
	key := make([]byte, 256)
	for i := range key {
		key[i] = byte(i)
	}
	if KeyTag(256, Ed25519, key) == 0 {
		t.Fatal("expected non-zero key tag")
	}
}

func TestParseEd25519DNSKEY(t *testing.T) {
	priv := newTestPrivKey(t, 256)
	if priv.keyTag == 0 {
		t.Fatal("expected non-zero key tag")
	}
}

func TestVerifyEd25519RRSIG(t *testing.T) {
	priv := newTestPrivKey(t, 256)

	// 203.0.113.58 as IP octets: 203, 0, 113, 58
	adata := []byte{203, 0, 113, 58}
	sig := priv.sign("host.example.test.", dns.TypeA, adata, time.Now(), 300)

	zk := &ZoneKeys{
		DNSKEYs: map[string][]*KeyInfo{"example.test.": {keyFor(priv)}},
		RRSigs:  map[string][]*RRSIGInfo{"host.example.test.": {ParseRRSIG(sig)}},
		ByType:  map[string]map[uint16][]dns.RR{},
	}
	zk.ByType["host.example.test."] = map[uint16][]dns.RR{dns.TypeA: {makeARR("host.example.test.", "203.0.113.58", 300)}}

	if idx := VerifyRRSIGForType(zk, "host.example.test.", dns.TypeA, time.Now()); idx != -1 {
		t.Fatalf("expected valid signature, got failing index %d", idx)
	}
}

func keyFor(priv *testPrivKey) *KeyInfo {
	// Reconstruct the key from the public half.
	pub := priv.priv.Public().(ed25519.PublicKey)
	dk := new(dns.DNSKEY)
	dk.Hdr = dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}
	dk.Flags = 256
	dk.Protocol = 1
	dk.Algorithm = Ed25519
	dk.PublicKey = base64.StdEncoding.EncodeToString(pub)
	k, err := ParseDNSKEY(dk)
	if err != nil {
		panic(err)
	}
	return k
}

func TestVerifyBadRRSIG(t *testing.T) {
	priv := newTestPrivKey(t, 256)

	bad := make([]byte, ed25519.SignatureSize)
	for i := range bad {
		bad[i] = 0xff
	}
	inc := uint32(time.Now().Unix())
	exp := uint32(time.Now().Add(48 * time.Hour).Unix())
	r := new(dns.RRSIG)
	r.Hdr = dns.RR_Header{Name: "host.example.test.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300}
	r.TypeCovered = dns.TypeA
	r.Algorithm = Ed25519
	r.Labels = 1
	r.OrigTtl = 300
	r.Expiration = exp
	r.Inception = inc
	r.KeyTag = priv.keyTag
	r.SignerName = "example.test."
	r.Signature = string(bad)

	zk := &ZoneKeys{
		DNSKEYs: map[string][]*KeyInfo{"example.test.": {keyFor(priv)}},
		RRSigs:  map[string][]*RRSIGInfo{"host.example.test.": {ParseRRSIG(r)}},
		ByType:  map[string]map[uint16][]dns.RR{},
	}
	zk.ByType["host.example.test."] = map[uint16][]dns.RR{dns.TypeA: {makeARR("host.example.test.", "203.0.113.58", 300)}}

	if idx := VerifyRRSIGForType(zk, "host.example.test.", dns.TypeA, time.Now()); idx == -1 {
		t.Fatal("expected invalid signature to fail")
	}
}

func TestExpiredSignature(t *testing.T) {
	sig := &RRSIGInfo{
		Algorithm:  Ed25519,
		Inception:  uint32(time.Now().Add(-48 * time.Hour).Unix()),
		Expiration: uint32(time.Now().Add(-24 * time.Hour).Unix()),
	}
	if !sig.SignatureExpired(time.Now()) {
		t.Fatal("expected expired signature")
	}
	if sig.SignatureNotYetValid(time.Now()) {
		t.Fatal("did not expect not-yet-valid")
	}
}

func TestNotYetValidSignature(t *testing.T) {
	sig := &RRSIGInfo{
		Algorithm:  Ed25519,
		Inception:  uint32(time.Now().Add(48 * time.Hour).Unix()),
		Expiration: uint32(time.Now().Add(72 * time.Hour).Unix()),
	}
	if sig.SignatureExpired(time.Now()) {
		t.Fatal("did not expect expired")
	}
	if !sig.SignatureNotYetValid(time.Now()) {
		t.Fatal("expected not-yet-valid")
	}
}

func TestDSMatchAndMismatch(t *testing.T) {
	priv := newTestPrivKey(t, 256)
	k := keyFor(priv)

	good := &DSInfo{KeyTag: k.KeyTag, Algorithm: Ed25519, DigestType: DigestTypeSHA256}
	good.Digest, _ = ComputeDSDigest(DigestTypeSHA256, DNSKEYRData(k))
	bad := &DSInfo{KeyTag: k.KeyTag, Algorithm: Ed25519, DigestType: DigestTypeSHA256, Digest: []byte{0x00, 0x01, 0x02}}

	zone := &ZoneKeys{DNSKEYs: map[string][]*KeyInfo{"example.test.": {k}}, DSs: map[string][]*DSInfo{"example.test.": {good}}}

	anchorBad := &ZoneKeys{DSs: map[string][]*DSInfo{"example.test.": {bad}}}
	if ValidateChain(anchorBad, zone, time.Now()).DSMatches {
		t.Fatal("expected DS mismatch")
	}

	anchorGood := &ZoneKeys{DSs: map[string][]*DSInfo{"example.test.": {good}}}
	if !ValidateChain(anchorGood, zone, time.Now()).DSMatches {
		t.Fatal("expected DS match")
	}
}

func TestValidateChainExpired(t *testing.T) {
	priv := newTestPrivKey(t, 256)
	k := keyFor(priv)
	sig := &RRSIGInfo{
		Algorithm:  Ed25519,
		Inception:  uint32(time.Now().Add(-48 * time.Hour).Unix()),
		Expiration: uint32(time.Now().Add(-24 * time.Hour).Unix()),
	}
	zone := &ZoneKeys{
		DNSKEYs: map[string][]*KeyInfo{"example.test.": {k}},
		RRSigs:  map[string][]*RRSIGInfo{"example.test.": {sig}},
		ByType:  map[string]map[uint16][]dns.RR{},
	}
	anchor := &ZoneKeys{DSs: map[string][]*DSInfo{"example.test.": {}}}
	if ValidateChain(anchor, zone, time.Now()).Valid {
		t.Fatal("expected invalid chain due to expired sig")
	}
}

func TestCollectFromResponse(t *testing.T) {
	priv := newTestPrivKey(t, 256)
	resp := new(dns.Msg)
	resp.Answer = append(resp.Answer, keyRR(priv))
	zk := Collect(resp)
	if !zk.HasDNSKEY() {
		t.Fatal("expected DNSKEY collected")
	}
}

func keyRR(priv *testPrivKey) dns.RR {
	return keyRRForKey(keyFor(priv))
}

func keyRRForKey(k *KeyInfo) dns.RR {
	dk := new(dns.DNSKEY)
	dk.Hdr = dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}
	dk.Flags = k.Flags
	dk.Algorithm = k.Algorithm
	dk.PublicKey = base64.StdEncoding.EncodeToString(k.KeyBytes)
	return dk
}

func TestAlgoName(t *testing.T) {
	if AlgoName(Ed25519) != "Ed25519" {
		t.Fatalf("unexpected name %q", AlgoName(Ed25519))
	}
	if AlgoName(99) != "UNKNOWN" {
		t.Fatalf("unexpected name %q", AlgoName(99))
	}
}

func TestDeprecatedAlgoFlagged(t *testing.T) {
	zone := &ZoneKeys{
		RRSigs: map[string][]*RRSIGInfo{"example.test.": {
			{Algorithm: AlgRSASHA1, Inception: uint32(time.Now().Unix()), Expiration: uint32(time.Now().Add(24 * time.Hour).Unix())},
		}},
	}
	anchor := &ZoneKeys{}
	res := ValidateChain(anchor, zone, time.Now())
	if len(res.DeprecatedSigs) == 0 {
		t.Fatal("expected deprecated algorithm flagged")
	}
}

var _ = dns.Fqdn
