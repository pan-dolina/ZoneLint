// Package soa validates SOA configuration against RFC 1035 / 2308 heuristics.
// These are treated as operational heuristics, not hard violations.
package soa

import (
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/example/ZoneLint/internal/findings"
)

// Check validates a single SOA record and returns findings.
func Check(zone string, soa *dns.SOA) []*findings.Finding {
	var out []*findings.Finding
	if soa == nil {
		return out
	}

	// RNAME must be a valid FQDN (admin address uses . instead of @).
	if !validName(soa.Mbox) {
		f := findings.New(findings.SOAInvalidRNAME, findings.SeverityMedium, findings.CategorySOA,
			"Malformed SOA RNAME")
		f.Explanation = "The SOA RNAME (responsible email address) is not a valid domain name."
		f.AddEvidence("RNAME=%s", soa.Mbox)
		f.WithZone(zone)
		f.Recommendation = "Provide a valid RNAME such as admin.example.test."
		f.References = []string{"RFC 1035 §4.1.3"}
		out = append(out, f)
	}
	if !validName(soa.Ns) {
		f := findings.New(findings.SOAInvalidMNAME, findings.SeverityMedium, findings.CategorySOA,
			"Malformed SOA MNAME")
		f.Explanation = "The SOA MNAME (primary name server) is not a valid domain name."
		f.AddEvidence("MNAME=%s", soa.Ns)
		f.WithZone(zone)
		f.Recommendation = "Provide a valid MNAME pointing to the primary name server."
		f.References = []string{"RFC 1035 §4.1.3"}
		out = append(out, f)
	}

	// Serial sanity: must be close to current date (YYYYMMDDnn form) and not in the future.
	if serialIssues(soa.Serial) != nil {
		f := findings.New(findings.SOASerialFormat, findings.SeverityLow, findings.CategorySOA,
			"SOA serial format heuristic")
		f.Explanation = "The SOA serial does not resemble the canonical YYYYMMDDnn form and may indicate manual increments."
		f.AddEvidence("serial=%d", soa.Serial)
		f.WithZone(zone)
		f.Recommendation = "Prefer a counter or ISO-Date serial to avoid accidental downgrade."
		f.References = []string{"RFC 1982 §2.1"}
		out = append(out, f)
	}

	// Schedule sanity: 0 < retry < refresh, expire reasonable, minimum >= 0.
	if issues := scheduleIssues(soa); issues != nil {
		f := findings.New(findings.SOASchedule, findings.SeverityLow, findings.CategorySOA,
			"SOA refresh/retry/expire heuristic")
		f.Explanation = issues.Error()
		f.WithZone(zone)
		f.AddEvidence("refresh=%d retry=%d expire=%d minimum=%d", soa.Refresh, soa.Retry, soa.Expire, soa.Minttl)
		f.Recommendation = "Align refresh/retry/expire with RFC 2308 guidance."
		f.References = []string{"RFC 2308 §3", "RFC 1035 §4.1.3"}
		out = append(out, f)
	}

	// Negative TTL (minimum) too low is an operational heuristic.
	if soa.Minttl < 30 {
		f := findings.New(findings.SOANegativeTTL, findings.SeverityInfo, findings.CategorySOA,
			"Low SOA minimum/negative TTL")
		f.Explanation = "A very low negative-cache TTL can increase loader queries; treated as info, not a violation."
		f.WithZone(zone)
		f.Recommendation = "Consider a negative TTL of at least 30s."
		f.References = []string{"RFC 2308 §3.1"}
		out = append(out, f)
	}

	return out
}

func validName(n string) bool {
	if n == "" || n == "." {
		return false
	}
	// Must be a fully-qualified name ending in a dot.
	if !dns.IsFqdn(n) {
		return false
	}
	// Reject labels longer than 63 chars and the root.
	for _, label := range strings.Split(n, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
	}
	return true
}

func serialIssues(serial uint32) error {
	now := time.Now()
	year := uint32(now.Year())*10000 + uint32(now.Month())*100 + uint32(now.Day())
	// Allow the canonical form within +/- 2 days.
	if serial >= year-2 && serial <= year+2 {
		return nil
	}
	// Allow very large monotonic counters (RFC 1982) that are clearly increasing.
	if serial > 2000010100 {
		return nil
	}
	return errNonCanonical
}

var errNonCanonical = &issueErr{"serial not in YYYYMMDDnn form"}

type issueErr struct{ s string }

func (e *issueErr) Error() string { return e.s }

func scheduleIssues(soa *dns.SOA) error {
	if soa.Retry >= soa.Refresh {
		return &issueErr{"retry >= refresh"}
	}
	if soa.Expire == 0 || soa.Expire > 0x7fffffff {
		return &issueErr{"expire out of range"}
	}
	if soa.Refresh == 0 {
		return &issueErr{"refresh is zero"}
	}
	return nil
}
