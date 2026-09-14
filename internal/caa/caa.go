// Package caa validates CAA records per RFC 8659.
package caa

import (
	"strings"

	"github.com/miekg/dns"

	"github.com/example/ZoneLint/internal/findings"
)

// Known non-critical tags.
var knownTags = map[string]bool{
	"issue": true, "issuewild": true, "iodef": true,
	"validationmode": true,
}

// Check evaluates CAA records for a zone.
func Check(zone string, records []dns.RR) []*findings.Finding {
	var out []*findings.Finding
	cas := dnsutilCAA(records)
	if len(cas) == 0 {
		return out
	}

	var criticalUnknown, malformed int
	for _, c := range cas {
		tag := strings.ToLower(strings.TrimSpace(c.Tag))
		if c.Flag&0x01 != 0 && !knownTags[tag] {
			criticalUnknown++
			f := findings.New(findings.CAACriticalUnknown, findings.SeverityMedium, findings.CategoryCAA,
				"Unknown critical CAA property")
			f.Explanation = "A CAA record sets the critical bit for a tag this tool does not recognize; relying on it could block issuance or be ignored."
			f.AddEvidence("flags=%d tag=%q value=%q", c.Flag, c.Tag, c.Value)
			f.WithZone(zone)
			f.Recommendation = "Only set the critical bit on known tags (issue, issuewild, iodef)."
			f.References = []string{"RFC 8659 §3"}
			out = append(out, f)
		}
		if issues := validateTag(tag, c.Flag, c.Value); issues != "" {
			malformed++
			f := findings.New(findings.CAACriticalUnknown, findings.SeverityLow, findings.CategoryCAA,
				"Malformed CAA record")
			f.Explanation = issues
			f.AddEvidence("tag=%q value=%q", c.Tag, c.Value)
			f.WithZone(zone)
			f.Recommendation = "Fix the CAA record syntax."
			f.References = []string{"RFC 8659 §2.1, §2.2"}
			out = append(out, f)
		}
	}
	_ = criticalUnknown
	return out
}

func validateTag(tag string, flag byte, value string) string {
	switch tag {
	case "issue", "issuewild":
		// Value may be empty (deny), or [issuer;]domain.
		if value == "" {
			return ""
		}
		return validateIssue(value)
	case "iodef":
		if !strings.HasPrefix(value, "mailto:") && !strings.HasPrefix(value, "http://") && !strings.HasPrefix(value, "https://") {
			return "iodef value must be a mailto: or URL"
		}
		return ""
	default:
		return ""
	}
}

func validateIssue(value string) string {
	// Optional leading issuer domain followed by ';'.
	i := strings.IndexByte(value, ';')
	domain := value
	if i >= 0 {
		domain = value[:i]
		value = value[i+1:]
	}
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return "" // deny-all is valid
	}
	if !validDomainLabel(domain) {
		return "issue issuer domain is malformed"
	}
	if value != "" && !validDomainLabel(value) {
		return "issue target domain is malformed"
	}
	return ""
}

func validDomainLabel(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	if !dns.IsFqdn(s) && !strings.Contains(s, ".") {
		// allow bare issuer tokens loosely; require at least one dot or fqdn
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
	}
	return true
}

func dnsutilCAA(records []dns.RR) []*dns.CAA {
	var out []*dns.CAA
	for _, rr := range records {
		if c, ok := rr.(*dns.CAA); ok {
			out = append(out, c)
		}
	}
	return out
}
