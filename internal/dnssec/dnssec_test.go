package dnssec

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	dnsutil "github.com/pan-dolina/ZoneLint/internal/dns"
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
	dk.Protocol = 3
	dk.Algorithm = Ed25519
	dk.PublicKey = base64.StdEncoding.EncodeToString(pub)
	k, err := ParseDNSKEY(dk)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	return &testPrivKey{priv: priv, keyTag: k.KeyTag}
}

// signedDataFor builds the RFC 4035 §5.3.2 signed data for an RRset.
func signedDataFor(algo uint8, rtype uint16, labels int, ttl, exp, inc uint32, keyTag uint16, signer, owner string, rdatas [][]byte) []byte {
	hdr := make([]byte, 18)
	binary.BigEndian.PutUint16(hdr[0:2], rtype)
	hdr[2] = algo
	hdr[3] = byte(labels) //#nosec G115 -- test fixture: label count fits in uint8
	binary.BigEndian.PutUint32(hdr[4:8], ttl)
	binary.BigEndian.PutUint32(hdr[8:12], exp)
	binary.BigEndian.PutUint32(hdr[12:16], inc)
	binary.BigEndian.PutUint16(hdr[16:18], keyTag)

	msg := append(append([]byte{}, hdr...), dnsutil.CanonicalName(signer)...)
	for _, rd := range rdatas {
		msg = append(msg, dnsutil.CanonicalName(owner)...)
		var rh [8]byte
		binary.BigEndian.PutUint16(rh[0:2], rtype)
		binary.BigEndian.PutUint16(rh[2:4], dns.ClassINET)
		binary.BigEndian.PutUint32(rh[4:8], ttl)
		msg = append(msg, rh[:]...)
		var rl [2]byte
		binary.BigEndian.PutUint16(rl[:], uint16(len(rd)))
		msg = append(msg, rl[:]...)
		msg = append(msg, rd...)
	}
	return msg
}

func (k *testPrivKey) sign(name string, rtype uint16, rdata []byte, now time.Time, ttl uint32) *dns.RRSIG {
	inc := uint32(now.Unix())
	exp := uint32(now.Add(48 * time.Hour).Unix())
	labels := len(strings.Split(strings.TrimSuffix(dns.Fqdn(name), "."), "."))
	msg := signedDataFor(Ed25519, rtype, labels, ttl, exp, inc, k.keyTag, "example.test.", name, [][]byte{rdata})
	sig := ed25519.Sign(k.priv, msg)

	r := new(dns.RRSIG)
	r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: ttl}
	r.TypeCovered = rtype
	r.Algorithm = Ed25519
	r.Labels = uint8(labels) //#nosec G115 -- test fixture: label count fits in uint8
	r.OrigTtl = ttl
	r.Expiration = exp
	r.Inception = inc
	r.KeyTag = k.keyTag
	r.SignerName = "example.test."
	r.Signature = base64.StdEncoding.EncodeToString(sig)
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
	if KeyTag(256, 3, Ed25519, key) == 0 {
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
	dk.Protocol = 3
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

// TestVerifyECDSAP256RRSIG covers the ECDSA-P256 path (RFC 6605): the DNSKEY
// public key is X || Y without the 0x04 prefix, and the RRSIG signature is
// R || S rather than DER.
func TestVerifyECDSAP256RRSIG(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes := make([]byte, 64)
	priv.X.FillBytes(pubBytes[:32])
	priv.Y.FillBytes(pubBytes[32:])

	dk := new(dns.DNSKEY)
	dk.Hdr = dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}
	dk.Flags = 256
	dk.Protocol = 3
	dk.Algorithm = ECDSAP256
	dk.PublicKey = base64.StdEncoding.EncodeToString(pubBytes)
	ki, err := ParseDNSKEY(dk)
	if err != nil {
		t.Fatalf("parse ECDSA DNSKEY: %v", err)
	}

	owner := "host.example.test."
	a1 := makeARR(owner, "203.0.113.58", 300)
	rdata := dnsutil.RRData(a1)
	inc := uint32(time.Now().Unix())
	exp := uint32(time.Now().Add(48 * time.Hour).Unix())
	labels := len(strings.Split(strings.TrimSuffix(owner, "."), "."))
	msg := signedDataFor(ECDSAP256, dns.TypeA, labels, 300, exp, inc, ki.KeyTag, "example.test.", owner, [][]byte{rdata})
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sigBytes := make([]byte, 64)
	r.FillBytes(sigBytes[:32])
	s.FillBytes(sigBytes[32:])

	rr := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		TypeCovered: dns.TypeA,
		Algorithm:   ECDSAP256,
		Labels:      uint8(labels), //#nosec G115 -- test fixture: label count fits in uint8
		OrigTtl:     300,
		Expiration:  exp,
		Inception:   inc,
		KeyTag:      ki.KeyTag,
		SignerName:  "example.test.",
		Signature:   base64.StdEncoding.EncodeToString(sigBytes),
	}

	zk := &ZoneKeys{
		DNSKEYs: map[string][]*KeyInfo{"example.test.": {ki}},
		RRSigs:  map[string][]*RRSIGInfo{owner: {ParseRRSIG(rr)}},
		ByType:  map[string]map[uint16][]dns.RR{},
	}
	zk.ByType[owner] = map[uint16][]dns.RR{dns.TypeA: {a1}}
	if idx := VerifyRRSIGForType(zk, owner, dns.TypeA, time.Now()); idx != -1 {
		t.Fatalf("expected valid ECDSA signature, got failing index %d", idx)
	}

	// A corrupted signature must fail.
	bad := make([]byte, 64)
	for i := range bad {
		bad[i] = 0xff
	}
	rr.Signature = base64.StdEncoding.EncodeToString(bad)
	zk.RRSigs[owner] = []*RRSIGInfo{ParseRRSIG(rr)}
	if idx := VerifyRRSIGForType(zk, owner, dns.TypeA, time.Now()); idx == -1 {
		t.Fatal("expected invalid ECDSA signature to fail")
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
	good.Digest, _ = ComputeDSDigest(DigestTypeSHA256, "example.test.", DNSKEYRData(k))
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
	dk.Protocol = 3
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
