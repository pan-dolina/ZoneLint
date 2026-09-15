// Package nsec assesses NSEC and NSEC3 records: mode, hash algorithm,
// iterations, salt, and malformed parameters. It does not perform zone walking.
package nsec

import (
	"fmt"

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
		f := findings.DNSSECNoNSEC.New(zone,
			"The zone does not publish NSEC or NSEC3 records; NSEC/NSEC3 provides authenticated denial of existence.")
		out = append(out, &f)
	}
	if a.Malformed {
		f := findings.DNSSECMalformedNSEC3.New(zone,
			"NSEC3 has zero or excessive iterations, or no salt, which weakens or breaks the hash.",
			fmt.Sprintf("iterations=%d salt_length=%d", a.NSEC3Iter, a.NSEC3Salt))
		out = append(out, &f)
	}
	return out
}

// NSEC3Supported reports whether NSEC3 is present.
func NSEC3Supported(a *Assessment) bool { return a.HasNSEC3 }

// Now returns current time.
func Now() interface{} { return nil }
