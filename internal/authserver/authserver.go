// Package authserver probes authoritative name servers for reachability,
// authoritative response, SOA/NS presence, EDNS support, and response
// consistency.
package authserver

import (
	"time"

	"github.com/miekg/dns"

	dnsutil "github.com/example/ZoneLint/internal/dns"
	"github.com/example/ZoneLint/internal/findings"
)

// ProbeResult holds the outcome of probing a single NS host.
type ProbeResult struct {
	Host         string
	UDPReachable bool
	TCPReachable bool
	AA           bool
	HasSOA       bool
	HasNS        bool
	HasEDNS      bool
	Consistent   bool
	Errors       []string
}

// CheckServer evaluates a probe result and returns findings.
func CheckServer(zone, server string, r *ProbeResult) []*findings.Finding {
	var out []*findings.Finding
	if r == nil {
		f := findings.New(findings.AuthUDPFail, findings.SeverityHigh, findings.CategoryAuthServer,
			"Authoritative server unreachable")
		f.Explanation = "The name server could not be reached."
		f.AddEvidence("server %s", server)
		f.WithZone(zone)
		f.Subject = server
		f.Recommendation = "Verify the server is running and reachable."
		f.References = []string{"RFC 1035 §2.4"}
		return []*findings.Finding{f}
	}

	if !r.UDPReachable {
		f := findings.New(findings.AuthUDPFail, findings.SeverityHigh, findings.CategoryAuthServer,
			"UDP not reachable")
		f.Explanation = "The authoritative server did not answer over UDP."
		f.AddEvidence("server %s", server)
		f.WithZone(zone)
		f.Subject = server
		f.Recommendation = "Ensure UDP/53 is open on the server."
		f.References = []string{"RFC 1035 §2.4"}
		out = append(out, f)
	}
	if !r.TCPReachable {
		f := findings.New(findings.AuthTCPFail, findings.SeverityMedium, findings.CategoryAuthServer,
			"TCP not reachable")
		f.Explanation = "The authoritative server did not answer over TCP (needed for large responses and AXFR)."
		f.WithZone(zone)
		f.Subject = server
		f.Recommendation = "Ensure TCP/53 is open on the server."
		f.References = []string{"RFC 1035 §2.4"}
		out = append(out, f)
	}
	if r.UDPReachable && !r.AA {
		f := findings.New(findings.AuthNoAA, findings.SeverityHigh, findings.CategoryAuthServer,
			"Non-authoritative response")
		f.Explanation = "The server answered but did not set the AA flag for a zone NS/SOA query."
		f.WithZone(zone)
		f.Subject = server
		f.Recommendation = "Configure the server as authoritative for the zone."
		f.References = []string{"RFC 1034 §4.1.1"}
		out = append(out, f)
	}
	if r.UDPReachable && !r.HasSOA {
		f := findings.New(findings.AuthNoSOA, findings.SeverityMedium, findings.CategoryAuthServer,
			"SOA not in response")
		f.Explanation = "The authoritative server did not include the zone SOA in the authority section."
		f.WithZone(zone)
		f.Subject = server
		f.Recommendation = "Verify the zone is loaded on the server."
		f.References = []string{"RFC 1035 §4.1.1"}
		out = append(out, f)
	}
	if r.UDPReachable && !r.HasNS {
		f := findings.New(findings.AuthNoNS, findings.SeverityLow, findings.CategoryAuthServer,
			"NS not in response")
		f.Explanation = "The authoritative server did not include NS records for the zone apex."
		f.WithZone(zone)
		f.Subject = server
		f.Recommendation = "Verify the zone's NS records."
		f.References = []string{"RFC 1035 §4.2.3"}
		out = append(out, f)
	}
	if r.UDPReachable && !r.HasEDNS {
		f := findings.New(findings.AuthNoEDNS, findings.SeverityInfo, findings.CategoryAuthServer,
			"EDNS/DO unsupported")
		f.Explanation = "The server does not support EDNS0 with the DO bit; DNSSEC responses may be truncated."
		f.WithZone(zone)
		f.Subject = server
		f.Recommendation = "Enable EDNS0 to allow large, DNSSEC-signed responses."
		f.References = []string{"RFC 6891"}
		out = append(out, f)
	}
	if !r.Consistent {
		f := findings.New(findings.AuthInconsistent, findings.SeverityMedium, findings.CategoryAuthServer,
			"Inconsistent responses")
		f.Explanation = "The server returned inconsistent answers across repeated queries."
		f.WithZone(zone)
		f.Subject = server
		f.Recommendation = "Investigate server configuration or split-horizon DNS."
		f.References = []string{"RFC 1034 §4.1.1"}
		out = append(out, f)
	}
	return out
}

// ProbeResponse parses a response into the fields used by CheckServer.
func ProbeResponse(resp *dns.Msg) *ProbeResult {
	r := &ProbeResult{AA: resp.Authoritative, HasEDNS: resp.IsEdns0() != nil}
	if resp == nil {
		return r
	}
	for _, rr := range resp.Answer {
		if soa := dnsutil.SOA([]dns.RR{rr}); soa != nil {
			r.HasSOA = true
		}
		if ns, ok := rr.(*dns.NS); ok {
			r.HasNS = true
			_ = ns
		}
	}
	for _, rr := range resp.Ns {
		if soa := dnsutil.SOA([]dns.RR{rr}); soa != nil {
			r.HasSOA = true
		}
	}
	return r
}

// Now returns current time (injected for tests).
func Now() time.Time { return time.Now() }
