// Package findings defines the core data model for ZoneLint audit results:
// Finding, Severity, and stable Finding IDs.
//
// Every finding carries a stable ID (e.g. DNS-DELEGATION-001) so that
// downstream tooling and golden tests can rely on deterministic output.
package findings

import (
	"fmt"
	"sort"
)

// Severity is the impact rating of a Finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
	SeverityPass     Severity = "pass"
)

// SeverityRank orders severities for aggregation and fail-on thresholds.
var SeverityRank = map[Severity]int{
	SeverityPass:     0,
	SeverityInfo:     1,
	SeverityLow:      2,
	SeverityMedium:   3,
	SeverityHigh:     4,
	SeverityCritical: 5,
}

// IsAtLeast reports whether s meets or exceeds min.
func (s Severity) IsAtLeast(min Severity) bool {
	return SeverityRank[s] >= SeverityRank[min]
}

// Category groups findings by the subsystem that produced them.
type Category string

const (
	CategoryDelegation Category = "delegation"
	CategoryAuthServer Category = "authserver"
	CategorySOA        Category = "soa"
	CategoryAXFR       Category = "axfr"
	CategoryDNSSEC     Category = "dnssec"
	CategoryTTL        Category = "ttl"
	CategoryCAA        Category = "caa"
	CategoryCNAME      Category = "cname"
	CategoryAddress    Category = "address"
	CategoryWildcard   Category = "wildcard"
	CategoryRecursion  Category = "recursion"
	CategoryTransport  Category = "transport"
	CategoryGeneral    Category = "general"
)

// Finding is a single audit result.
type Finding struct {
	ID             string   `json:"id"`
	Severity       string   `json:"severity"`
	Category       string   `json:"category"`
	Title          string   `json:"title"`
	Explanation    string   `json:"explanation"`
	Evidence       []string `json:"evidence"`
	Recommendation string   `json:"recommendation"`
	References     []string `json:"references"`
	Zone           string   `json:"zone,omitempty"`
	Subject        string   `json:"subject,omitempty"`
}

// AddEvidence appends non-empty evidence strings.
func (f *Finding) AddEvidence(format string, args ...any) {
	var s string
	if len(args) == 0 {
		s = format
	} else {
		s = fmt.Sprintf(format, args...)
	}
	if s != "" {
		f.Evidence = append(f.Evidence, s)
	}
}

// WithZone sets the zone context on a copy-safe basis (mutates in place).
func (f *Finding) WithZone(zone string) *Finding {
	f.Zone = zone
	return f
}

// WithSubject sets the subject (host, record, address) a finding concerns.
func (f *Finding) WithSubject(subject string) *Finding {
	f.Subject = subject
	return f
}

// New builds a Finding, guarding against nil evidence slices.
func New(id string, sev Severity, cat Category, title string) *Finding {
	return &Finding{
		ID:         id,
		Severity:   string(sev),
		Category:   string(cat),
		Title:      title,
		Evidence:   []string{},
		References: []string{},
	}
}

// Sorted returns findings ordered by severity rank (descending), then ID.
func Sorted(fs []*Finding) []*Finding {
	out := make([]*Finding, len(fs))
	copy(out, fs)
	sort.SliceStable(out, func(i, j int) bool {
		if SeverityRank[Severity(out[i].Severity)] != SeverityRank[Severity(out[j].Severity)] {
			return SeverityRank[Severity(out[i].Severity)] > SeverityRank[Severity(out[j].Severity)]
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// MaxSeverity returns the highest severity present, or "" if empty.
func MaxSeverity(fs []*Finding) Severity {
	var max Severity
	for _, f := range fs {
		if max == "" || SeverityRank[Severity(f.Severity)] > SeverityRank[max] {
			max = Severity(f.Severity)
		}
	}
	return max
}

// CountBySeverity tallies findings per severity.
func CountBySeverity(fs []*Finding) map[Severity]int {
	out := map[Severity]int{}
	for _, f := range fs {
		out[Severity(f.Severity)]++
	}
	return out
}
