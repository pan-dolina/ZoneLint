package dnssec

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

var errBadEncoding = errors.New("dnssec: bad encoding")

func decodeBase64(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	// DNS base64 uses standard base64 with no padding in wire format; miekg
	// already decodes, but we may receive raw base64 text.
	s = trimNewlines(s)
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(s)
	}
	if err != nil {
		return nil, fmt.Errorf("dnssec: bad base64: %w", err)
	}
	return b, nil
}

func decodeHex(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	s = trimNewlines(s)
	return hex.DecodeString(s)
}

func trimNewlines(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r != '\n' && r != '\r' {
			out = append(out, r)
		}
	}
	return string(out)
}

// parseDERRSA decodes a DER-encoded RSA public key. It returns ok=false if the
// bytes are not valid DER.
func parseDERRSA(der []byte) (*rsa.PublicKey, bool) {
	// DNSKEY RSA public key DER: SEQUENCE { INTEGER modulus, INTEGER exponent }.
	if len(der) < 4 {
		return nil, false
	}
	off := 0
	if off+2 >= len(der) || der[off] != 0x30 {
		return nil, false
	}
	off += 2
	// modulus
	if off+2 >= len(der) || der[off] != 0x02 {
		return nil, false
	}
	off += 2
	modLen := int(der[off-2]) & 0xff
	if modLen == 0 { // long form
		return nil, false
	}
	if off+modLen > len(der) {
		return nil, false
	}
	modBytes := der[off : off+modLen]
	off += modLen
	// exponent
	if off+2 >= len(der) || der[off] != 0x02 {
		return nil, false
	}
	off += 2
	expLen := int(der[off-2]) & 0xff
	if expLen == 0 {
		return nil, false
	}
	if off+expLen > len(der) {
		return nil, false
	}
	expBytes := der[off : off+expLen]

	mod := new(big.Int).SetBytes(modBytes)
	exp := new(big.Int).SetBytes(expBytes)
	if mod.Sign() <= 0 || exp.Sign() <= 0 {
		return nil, false
	}
	return &rsa.PublicKey{N: mod, E: int(exp.Int64())}, true
}

// rsaVerifyPKCS1 verifies a PKCS#1 v1.5 signature over digest d using h.
func rsaVerifyPKCS1(pub *rsa.PublicKey, h crypto.Hash, d []byte, sig []byte) error {
	if len(sig) != pub.N.BitLen()/8 {
		return errBadSignature
	}
	return rsa.VerifyPKCS1v15(pub, h, d, sig)
}

// rsaSignPKCS1 signs a digest (used by tests/fixtures).
func rsaSignPKCS1(priv *rsa.PrivateKey, h crypto.Hash, d []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(randReader(), priv, h, d)
}
