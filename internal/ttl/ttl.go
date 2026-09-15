// Package ttl collects TTLs from records and evaluates them against policy
// profiles. Low TTLs are treated as resilience/operations heuristics, never
// as vulnerabilities.
package ttl

import (
	"fmt"
	"time"

	"github.com/miekg/dns"

	"github.com/pan-dolina/ZoneLint/internal/findings"
)

// Profile selects a TTL policy.
type Profile string

const (
	ProfileConservative Profile = "conservative"
	ProfileBalanced     Profile = "balanced"
	ProfileAgile        Profile = "agile"
)

// Limits returns [min acceptable, extreme threshold] for a profile.
func (p Profile) Limits() (minTTL, extremeTTL uint32) {
	switch p {
	case ProfileConservative:
		return 300, 86400
	case ProfileBalanced:
		return 60, 604800
	case ProfileAgile:
		return 10, 604800
	default:
		return 60, 604800
	}
}

// Collector gathers TTLs by record type.
type Collector struct {
	Values  map[uint16]uint32 // rtype -> min TTL observed
	Records map[uint16][]dns.RR
}

// NewCollector returns an empty collector.
func NewCollector() *Collector {
	return &Collector{Values: map[uint16]uint32{}, Records: map[uint16][]dns.RR{}}
}

// Add records a record's TTL.
func (c *Collector) Add(rr dns.RR) {
	if rr == nil {
		return
	}
	typ := rr.Header().Rrtype
	t := rr.Header().Ttl
	if prev, ok := c.Values[typ]; !ok || t < prev {
		c.Values[typ] = t
	}
	c.Records[typ] = append(c.Records[typ], rr)
}

// CollectAll adds every record from the given sections.
func (c *Collector) CollectAll(resp *dns.Msg) {
	for _, rr := range append(append([]dns.RR{}, resp.Answer...), resp.Ns...) {
		c.Add(rr)
	}
}

// ProfileName returns the profile as a string.
func ProfileName(p Profile) string { return string(p) }

// Check evaluates collected TTLs against the profile and returns findings.
func Check(zone, profile string, c *Collector) []*findings.Finding {
	p := Profile(profile)
	if p == "" {
		p = ProfileBalanced
	}
	minTTL, extremeTTL := p.Limits()
	var out []*findings.Finding

	// Record types we care about.
	types := []uint16{
		dns.TypeSOA, dns.TypeNS, dns.TypeA, dns.TypeAAAA,
		dns.TypeMX, dns.TypeCNAME, dns.TypeTXT, dns.TypeCAA,
		dns.TypeDNSKEY, dns.TypeDS,
	}
	for _, typ := range types {
		t, ok := c.Values[typ]
		if !ok {
			continue
		}
		if t == 0 {
			continue
		}
		if t > extremeTTL {
			f := findings.TTLExtreme.New(zone,
				"A very high TTL reduces operational agility and delays propagation of legitimate changes.",
				fmt.Sprintf("%s TTL=%d (limit %d)", dnsTypeString(typ), t, extremeTTL))
			out = append(out, &f)
			continue
		}
		if t < minTTL {
			f := findings.TTLShort.New(zone,
				"A low TTL is an operational/resilience heuristic: it improves propagation agility but increases query load and reduces cache efficiency. It is not reported as a vulnerability.",
				fmt.Sprintf("%s TTL=%d (profile minimum %d)", dnsTypeString(typ), t, minTTL))
			out = append(out, &f)
		}
	}
	return out
}

func dnsTypeString(typ uint16) string {
	return dns.TypeToString[typ]
}

// Now returns the current time (injected for tests).
func Now() time.Time { return time.Now() }
