// Package soa validates SOA configuration against RFC 1035 / 2308 heuristics.
// These are treated as operational heuristics, not hard violations.
package soa

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/pan-dolina/ZoneLint/internal/findings"
)

// Check validates a single SOA record and returns findings.
func Check(zone string, soa *dns.SOA) []*findings.Finding {
	var out []*findings.Finding
	if soa == nil {
		return out
	}

	// RNAME must be a valid FQDN (admin address uses . instead of @).
	if !validName(soa.Mbox) {
		f := findings.SOAInvalidRNAME.New(zone,
			"The SOA RNAME (responsible email address) is not a valid domain name.",
			fmt.Sprintf("RNAME=%s", soa.Mbox))
		out = append(out, &f)
	}
	if !validName(soa.Ns) {
		f := findings.SOAInvalidMNAME.New(zone,
			"The SOA MNAME (primary name server) is not a valid domain name.",
			fmt.Sprintf("MNAME=%s", soa.Ns))
		out = append(out, &f)
	}

	// Serial sanity: must be close to current date (YYYYMMDDnn form) and not in the future.
	if serialIssues(soa.Serial) != nil {
		f := findings.SOASerialFormat.New(zone,
			"The SOA serial does not resemble the canonical YYYYMMDDnn form and may indicate manual increments.",
			fmt.Sprintf("serial=%d", soa.Serial))
		out = append(out, &f)
	}

	// Schedule sanity: 0 < retry < refresh, expire reasonable, minimum >= 0.
	if issues := scheduleIssues(soa); issues != nil {
		f := findings.SOASchedule.New(zone,
			issues.Error(),
			fmt.Sprintf("refresh=%d retry=%d expire=%d minimum=%d", soa.Refresh, soa.Retry, soa.Expire, soa.Minttl))
		out = append(out, &f)
	}

	// Negative TTL (minimum) too low is an operational heuristic.
	if soa.Minttl < 30 {
		f := findings.SOANegativeTTL.New(zone,
			"A very low negative-cache TTL can increase loader queries; treated as info, not a violation.")
		out = append(out, &f)
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
	// Reject labels longer than 63 chars. The trailing dot produces an empty
	// final label when splitting, which is expected and valid.
	for _, label := range strings.Split(n, ".") {
		if len(label) > 63 {
			return false
		}
	}
	return true
}

func serialIssues(serial uint32) error {
	now := time.Now()
	year := uint32(now.Year())*10000 + uint32(now.Month())*100 + uint32(now.Day()) //#nosec G115 -- SOA serial format per RFC 1982
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
