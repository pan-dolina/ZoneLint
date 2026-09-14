// Package wildcard detects wildcard DNS records using a single cryptographically
// random query name. It never brute-forces subdomains.
package wildcard

import (
	"crypto/rand"
	"encoding/hex"
	"strings"

	"github.com/miekg/dns"

	"github.com/example/ZoneLint/internal/findings"
)

// ProbeName generates a cryptographically random label for a wildcard probe.
func ProbeName(zone string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	label := hex.EncodeToString(b)
	return label + "." + zone, nil
}

// Check evaluates a wildcard probe result.
func Check(zone, probeName string, hasWildcard bool) []*findings.Finding {
	if !hasWildcard {
		return nil
	}
	f := findings.New(findings.WildcardPresent, findings.SeverityInfo, findings.CategoryWildcard,
		"Wildcard DNS record present")
	f.Explanation = "The zone answers a non-existent, randomly-generated name with a record. Wildcards can mask typosquatting and cause unexpected resolution."
	f.AddEvidence("queried %s and received a wildcard/nxdomain-clobbering answer", probeName)
	f.WithZone(zone)
	f.Recommendation = "Confirm the wildcard is intentional; if so, document it. Wildcards can obscure NXDOMAIN semantics."
	f.References = []string{"RFC 1034 §4.3.3", "RFC 4592"}
	return []*findings.Finding{f}
}

// IsWildcardResponse reports whether a response indicates a wildcard answer.
// probeName is the random name queried; a wildcard answer returns records for
// that name even though it does not exist.
func IsWildcardResponse(resp *dns.Msg, probeName string) bool {
	if resp == nil {
		return false
	}
	if resp.Rcode != dns.RcodeSuccess {
		return false
	}
	queried := strings.ToLower(dns.Fqdn(probeName))
	for _, rr := range resp.Answer {
		if rr == nil {
			continue
		}
		name := strings.ToLower(dns.Fqdn(rr.Header().Name))
		if strings.Contains(name, "*.") || name == queried {
			return true
		}
	}
	return false
}
