// Package dnssec implements DNSSEC record parsing and chain validation.
//
// It performs real cryptographic validation: it recomputes RRSIG signatures
// over RDATA, verifies DS->DNSKEY key-tag and digest matches, walks the chain
// of trust from a trusted anchor, and checks signature lifetimes and
// algorithm acceptability.
package dnssec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1" //#nosec G505 -- SHA-1 is required for DNSSEC key tags and SHA1 DS digests (RFC 4034/3757).
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"math/big"
	"time"

	"github.com/miekg/dns"

	dnsutil "github.com/pan-dolina/ZoneLint/internal/dns"
)

// DNSSEC algorithm identifiers (RFC 4034, RFC 6978, RFC 8624).
// These match the wire-format uint8 values.
const (
	AlgRSASHA1      uint8 = 5
	AlgRSASHA1NSEC3 uint8 = 7
	AlgRSASHA256    uint8 = 8
	AlgRSASHA512    uint8 = 10
	ECDSAP256       uint8 = 13
	ECDSAP384       uint8 = 14
	Ed25519         uint8 = 15
)

// Deprecated algorithms (RFC 9037) that should be flagged.
var DeprecatedAlgorithms = map[uint8]bool{
	AlgRSASHA1:      true,
	AlgRSASHA1NSEC3: true,
}

// DS digest types (RFC 4034).
const (
	DigestTypeSHA1   uint8 = 1
	DigestTypeSHA256 uint8 = 2
	DigestTypeSHA512 uint8 = 3
)

var (
	errEmptyKey        = errors.New("dnssec: empty key")
	errBadKeyLength    = errors.New("dnssec: bad public key length")
	errBadSignature    = errors.New("dnssec: bad signature length")
	errKeyMismatch     = errors.New("dnssec: key does not match signature")
	errSigInvalid      = errors.New("dnssec: signature verification failed")
	errUnsupportedAlgo = errors.New("dnssec: unsupported algorithm")
	errBadDigestType   = errors.New("dnssec: unsupported digest type")
)

// AlgoName returns a human-readable algorithm name.
func AlgoName(algo uint8) string {
	switch algo {
	case 1:
		return "RSAMD5"
	case AlgRSASHA256:
		return "RSA-SHA256"
	case AlgRSASHA512:
		return "RSA-SHA512"
	case Ed25519:
		return "Ed25519"
	case ECDSAP256:
		return "ECDSA-P256-SHA256"
	case ECDSAP384:
		return "ECDSA-P384-SHA384"
	default:
		return "UNKNOWN"
	}
}

// KeyInfo holds parsed DNSKEY material.
type KeyInfo struct {
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey crypto.PublicKey
	KeyBytes  []byte
	KeyTag    uint16
}

// KeyTag computes the DNSKEY key tag per RFC 4034 Appendix B: the checksum is
// calculated over the full DNSKEY RDATA (flags, protocol, algorithm, public
// key).
func KeyTag(flags uint16, protocol, algo uint8, key []byte) uint16 {
	rdata := make([]byte, 4+len(key))
	binary.BigEndian.PutUint16(rdata[0:2], flags)
	rdata[2] = protocol
	rdata[3] = algo
	copy(rdata[4:], key)
	var ac uint32
	for i := 0; i < len(rdata); i++ {
		if i&1 == 0 {
			ac += uint32(rdata[i]) << 8
		} else {
			ac += uint32(rdata[i])
		}
	}
	ac += (ac >> 16) & 0xffff
	return uint16(ac & 0xffff)
}

// ParseDNSKEY parses a DNSKEY RR into KeyInfo.
func ParseDNSKEY(rr *dns.DNSKEY) (*KeyInfo, error) {
	key, err := decodeBase64(rr.PublicKey)
	if err != nil {
		return nil, err
	}
	if len(key) == 0 {
		return nil, errEmptyKey
	}
	pub, err := pubkeyFromAlgorithm(rr.Flags, rr.Algorithm, key)
	if err != nil {
		return nil, err
	}
	return &KeyInfo{
		Flags:     rr.Flags,
		Protocol:  rr.Protocol,
		Algorithm: rr.Algorithm,
		PublicKey: pub,
		KeyBytes:  key,
		KeyTag:    KeyTag(rr.Flags, rr.Protocol, rr.Algorithm, key),
	}, nil
}

func pubkeyFromAlgorithm(flags uint16, algo uint8, key []byte) (crypto.PublicKey, error) {
	switch algo {
	case Ed25519:
		if len(key) != ed25519.PublicKeySize {
			return nil, errBadKeyLength
		}
		return ed25519.PublicKey(append(ed25519.PublicKey{}, key...)), nil
	case ECDSAP256:
		return curveKey(elliptic.P256(), key, errBadKeyLength)
	case ECDSAP384:
		return curveKey(elliptic.P384(), key, errBadKeyLength)
	case AlgRSASHA1, AlgRSASHA256, AlgRSASHA512:
		return rsaKey(key, errBadKeyLength)
	default:
		return nil, errUnsupportedAlgo
	}
}

func curveKey(c elliptic.Curve, key []byte, err error) (crypto.PublicKey, error) {
	if len(key) != (c.Params().BitSize+7)/8*2 {
		return nil, errBadKeyLength
	}
	// RFC 6605: the ECDSA public key in a DNSKEY is X || Y without the 0x04
	// uncompressed-point prefix. Add it back for parsing.
	uncompressed := make([]byte, 0, 1+len(key))
	uncompressed = append(uncompressed, 0x04)
	uncompressed = append(uncompressed, key...)
	// ParseUncompressedPublicKey performs the on-curve check and returns a
	// validated *ecdsa.PublicKey without touching the deprecated X/Y fields.
	return ecdsa.ParseUncompressedPublicKey(c, uncompressed)
}

func rsaKey(key []byte, err error) (crypto.PublicKey, error) {
	block, ok := parseDERRSA(key)
	if !ok {
		return nil, errBadKeyLength
	}
	return block, nil
}

// PublicKeyBytes returns the raw public key bytes stored in the DNSKEY.
func (k *KeyInfo) PublicKeyBytes() []byte {
	return k.KeyBytes
}

// RRSIGInfo holds parsed RRSIG fields.
type RRSIGInfo struct {
	TypeCovered  uint16
	Algorithm    uint8
	Labels       uint8
	OriginalTTL  uint32
	Expiration   uint32
	Inception    uint32
	KeyTag       uint16
	SignerName   string
	RawSignature []byte
	RawRdata     []byte
}

// ParseRRSIG parses an RRSIG RR and builds the rdata needed to verify.
func ParseRRSIG(rr *dns.RRSIG) *RRSIGInfo {
	// After wire parsing miekg/dns keeps Signature as base64 text; decode it
	// so RawSignature holds the raw signature bytes.
	sig, err := decodeBase64(rr.Signature)
	if err != nil {
		sig = []byte(rr.Signature)
	}
	return &RRSIGInfo{
		TypeCovered:  rr.TypeCovered,
		Algorithm:    rr.Algorithm,
		Labels:       rr.Labels,
		OriginalTTL:  rr.OrigTtl,
		Expiration:   rr.Expiration,
		Inception:    rr.Inception,
		KeyTag:       rr.KeyTag,
		SignerName:   dns.Fqdn(rr.SignerName),
		RawSignature: sig,
		RawRdata:     sigRDataNoSig(rr), // RRSIG RDATA without the signature
	}
}

// sigRDataNoSig returns the RRSIG RDATA with the Signature field excluded:
// the 18-byte fixed header followed by the signer name in canonical form
// (RFC 4035 §5.3.2).
func sigRDataNoSig(rr *dns.RRSIG) []byte {
	buf := make([]byte, 18)
	binary.BigEndian.PutUint16(buf[0:2], rr.TypeCovered)
	buf[2] = rr.Algorithm
	buf[3] = rr.Labels
	binary.BigEndian.PutUint32(buf[4:8], rr.OrigTtl)
	binary.BigEndian.PutUint32(buf[8:12], rr.Expiration)
	binary.BigEndian.PutUint32(buf[12:16], rr.Inception)
	binary.BigEndian.PutUint16(buf[16:18], rr.KeyTag)
	return append(buf, dnsutil.CanonicalName(rr.SignerName)...)
}

// SignatureExpired reports whether sig expired before now.
func (r *RRSIGInfo) SignatureExpired(now time.Time) bool {
	return now.Unix() > int64(r.Expiration)
}

// SignatureNotYetValid reports whether sig becomes valid after now.
func (r *RRSIGInfo) SignatureNotYetValid(now time.Time) bool {
	return now.Unix() < int64(r.Inception)
}

// Verify checks an RRSIG over the given signed RDATA sets.
func Verify(sig *RRSIGInfo, key *KeyInfo, signedRData [][]byte) error {
	switch key.Algorithm {
	case Ed25519:
		return verifyEd25519(sig, key, signedRData)
	case ECDSAP256:
		return verifyECDSA(sig, key, signedRData, sha256.New)
	case ECDSAP384:
		return verifyECDSA(sig, key, signedRData, sha512.New)
	case AlgRSASHA1, AlgRSASHA256, AlgRSASHA512:
		return verifyRSA(sig, key, signedRData, algoHash(key.Algorithm))
	default:
		return errUnsupportedAlgo
	}
}

func verifyEd25519(sig *RRSIGInfo, key *KeyInfo, signed [][]byte) error {
	pub, ok := key.PublicKey.(ed25519.PublicKey)
	if !ok {
		return errKeyMismatch
	}
	if len(sig.RawSignature) != ed25519.SignatureSize {
		return errBadSignature
	}
	if !ed25519.Verify(pub, concatRData(signed), sig.RawSignature) {
		return errSigInvalid
	}
	return nil
}

func verifyECDSA(sig *RRSIGInfo, key *KeyInfo, signed [][]byte, hashFn func() hash.Hash) error {
	pub, ok := key.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errKeyMismatch
	}
	// RFC 6605: the ECDSA signature in an RRSIG is R || S, not DER.
	half := len(sig.RawSignature) / 2
	if half < 1 || len(sig.RawSignature)%2 != 0 {
		return errBadSignature
	}
	r := new(big.Int).SetBytes(sig.RawSignature[:half])
	s := new(big.Int).SetBytes(sig.RawSignature[half:])
	h := hashFn()
	h.Write(concatRData(signed))
	if !ecdsa.Verify(pub, h.Sum(nil), r, s) {
		return errSigInvalid
	}
	return nil
}

func verifyRSA(sig *RRSIGInfo, key *KeyInfo, signed [][]byte, h crypto.Hash) error {
	pub, ok := key.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errKeyMismatch
	}
	if err := rsaVerifyPKCS1(pub, h, hashDigest(h, concatRData(signed)), sig.RawSignature); err != nil {
		return err
	}
	return nil
}

func algoHash(algo uint8) crypto.Hash {
	switch algo {
	case AlgRSASHA1:
		return crypto.SHA1
	case AlgRSASHA256:
		return crypto.SHA256
	case AlgRSASHA512:
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

func hashDigest(h crypto.Hash, data []byte) []byte {
	var hh hash.Hash
	switch h {
	case crypto.SHA1:
		hh = sha1.New() //#nosec G401 -- SHA-1 is required for DNSSEC RRSIG verification (RFC 4034/3757).
	case crypto.SHA256:
		hh = sha256.New()
	case crypto.SHA512:
		hh = sha512.New()
	default:
		hh = sha256.New()
	}
	hh.Write(data)
	return hh.Sum(nil)
}

func concatRData(records [][]byte) []byte {
	var out []byte
	for _, r := range records {
		out = append(out, r...)
	}
	return out
}

// DSInfo holds a parsed DS record.
type DSInfo struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     []byte
}

// ParseDS parses a DS record.
func ParseDS(rr *dns.DS) *DSInfo {
	d, err := decodeHex(rr.Digest)
	if err != nil {
		return &DSInfo{KeyTag: rr.KeyTag, Algorithm: rr.Algorithm, DigestType: rr.DigestType}
	}
	return &DSInfo{
		KeyTag:     rr.KeyTag,
		Algorithm:  rr.Algorithm,
		DigestType: rr.DigestType,
		Digest:     d,
	}
}

// ComputeDSDigest computes the DS digest over the canonical owner name
// concatenated with the DNSKEY RDATA (RFC 4034 §5.1.4).
func ComputeDSDigest(digestType uint8, owner string, dnskeyRData []byte) ([]byte, error) {
	data := append(dnsutil.CanonicalName(owner), dnskeyRData...)
	switch digestType {
	case DigestTypeSHA1:
		h := sha1.New() //#nosec G401 -- SHA-1 is required for DS digest computation (RFC 4034/3757).
		h.Write(data)
		return h.Sum(nil), nil
	case DigestTypeSHA256:
		h := sha256.New()
		h.Write(data)
		return h.Sum(nil), nil
	case DigestTypeSHA512:
		h := sha512.New()
		h.Write(data)
		return h.Sum(nil), nil
	default:
		return nil, errBadDigestType
	}
}

// DNSKEYRData returns the wire-format rdata for a DNSKEY (without the RR header).
// Wire format: Flags (uint16), Protocol (uint8), Algorithm (uint8), PublicKey.
func DNSKEYRData(k *KeyInfo) []byte {
	out := make([]byte, 4+len(k.KeyBytes))
	binary.BigEndian.PutUint16(out[0:2], k.Flags)
	out[2] = k.Protocol
	out[3] = k.Algorithm
	copy(out[4:], k.KeyBytes)
	return out
}
