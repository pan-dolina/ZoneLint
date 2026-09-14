// Package nsec assesses NSEC and NSEC3 records: mode, hash algorithm,
// iterations, salt, and malformed parameters. It does not perform zone walking.
package nsec

import (
	"github.com/miekg/dns"

	"github.com/example/ZoneLint/internal/findings"
)

// Assessment holds the result of analyzing NSEC/NSEC3 records.
type Assessment struct {
	HasNSEC   bool
	HasNSEC3  bool
	NSEC3Iter int
	NSEC3Salt int
	Malformed bool
}

// Analyze inspects records for NSEC/NSEC3 presence and parameter sanity.
func Analyze(records []dns.RR) *Assessment {
	a := &Assessment{}
	for _, rr := range records {
		switch r := rr.(type) {
		case *dns.NSEC:
			a.HasNSEC = true
		case *dns.NSEC3:
			a.HasNSEC3 = true
			a.NSEC3Iter = int(r.Iterations)
			a.NSEC3Salt = int(r.SaltLength)
			if r.Iterations == 0 && r.SaltLength == 0 {
				// A zero-iteration NSEC3 with no salt is suspicious/malformed.
				a.Malformed = true
			}
			if r.Iterations > 10000 {
				a.Malformed = true
			}
		}
	}
	return a
}

// Check returns findings based on the assessment.
func Check(zone string, a *Assessment) []*findings.Finding {
	var out []*findings.Finding
	if !a.HasNSEC && !a.HasNSEC3 {
		f := findings.New(findings.DNSSECNoNSEC, findings.SeverityLow, findings.CategoryDNSSEC,
			"No NSEC/NSEC3 records")
		f.Explanation = "The zone does not publish NSEC or NSEC3 records; NSEC/NSEC3 provides authenticated denial of existence."
		f.WithZone(zone)
		f.Recommendation = "Enable NSEC or NSEC3 for authenticated denial of existence."
		f.References = []string{"RFC 4034", "RFC 5155"}
		out = append(out, f)
	}
	if a.Malformed {
		f := findings.New(findings.DNSSECMalformedNSEC3, findings.SeverityMedium, findings.CategoryDNSSEC,
			"Malformed NSEC3 parameters")
		f.Explanation = "NSEC3 has zero or excessive iterations, or no salt, which weakens or breaks the hash."
		f.AddEvidence("iterations=%d salt_length=%d", a.NSEC3Iter, a.NSEC3Salt)
		f.WithZone(zone)
		f.Recommendation = "Use a reasonable iteration count (e.g. >= 1500) and a salt."
		f.References = []string{"RFC 5155 §4.2"}
		out = append(out, f)
	}
	return out
}

// NSEC3Supported reports whether NSEC3 is present.
func NSEC3Supported(a *Assessment) bool { return a.HasNSEC3 }

// Now returns current time.
func Now() interface{} { return nil }
