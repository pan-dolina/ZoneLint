// Package active implements opt-in, safe active scans: recursion checking and
// limited protocol probes. It issues a minimal number of queries and never
// performs DoS, amplification, spoofing, or poisoning.
package active

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/miekg/dns"

	dnsutil "github.com/example/ZoneLint/internal/dns"
	"github.com/example/ZoneLint/internal/findings"
)

// RecursionResult reports whether a server performs unrestricted recursion.
type RecursionResult struct {
	Server      string
	Recursive   bool
	QueriesSent int
}

// CheckRecursion issues a single query for a random name to an authoritative
// server and reports whether it answers recursively.
func CheckRecursion(server, zone string, resp *dns.Msg) *RecursionResult {
	r := &RecursionResult{Server: server, QueriesSent: 1}
	if resp == nil {
		return r
	}
	// A server is "open" if it answers a non-existent name with a resolved
	// answer (recursion available) rather than NXDOMAIN/refused.
	if resp.RecursionAvailable && resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
		r.Recursive = true
	}
	return r
}

// Check evaluates a recursion result and returns findings.
func Check(server, zone string, r *RecursionResult) []*findings.Finding {
	var out []*findings.Finding
	if r == nil || !r.Recursive {
		return out
	}
	f := findings.New(findings.RecursionOpen, findings.SeverityHigh, findings.CategoryRecursion,
		"Open recursion on authoritative server")
	f.Explanation = "The authoritative server answers recursive queries for arbitrary names, exposing it as an open resolver."
	f.AddEvidence("server %s answered recursion with %d query(s)", server, r.QueriesSent)
	f.WithZone(zone)
	f.Subject = server
	f.Recommendation = "Disable recursion on authoritative servers; restrict to trusted clients."
	f.References = []string{"CVE-relevant open resolver guidance", "RFC 1996"}
	out = append(out, f)
	return out
}

// RandomName generates a cryptographically random label for active probes.
func RandomName(zone string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b) + "." + zone, nil
}

// RecursionQuery builds a single recursion-probe query.
func RecursionQuery(zone string) *dns.Msg {
	name, _ := RandomName(zone)
	m := dnsutil.SafeNewMsg(name, dns.TypeA)
	return m
}

var _ = dns.Fqdn
