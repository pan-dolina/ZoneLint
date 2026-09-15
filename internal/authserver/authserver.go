// Package authserver probes authoritative name servers for reachability,
// authoritative response, SOA/NS presence, EDNS support, and response
// consistency.
package authserver

import (
	"fmt"
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
		f := findings.AuthUDPFail.New(server, "The name server could not be reached.",
			fmt.Sprintf("server %s", server))
		f = f.WithZone(zone)
		return []*findings.Finding{&f}
	}

	if !r.UDPReachable {
		f := findings.AuthUDPFail.New(server, "The authoritative server did not answer over UDP.",
			fmt.Sprintf("server %s", server))
		f = f.WithZone(zone)
		out = append(out, &f)
	}
	if !r.TCPReachable {
		f := findings.AuthTCPFail.New(server, "The authoritative server did not answer over TCP (needed for large responses and AXFR).")
		f = f.WithZone(zone)
		out = append(out, &f)
	}
	if r.UDPReachable && !r.AA {
		f := findings.AuthNoAA.New(server, "The server answered but did not set the AA flag for a zone NS/SOA query.")
		f = f.WithZone(zone)
		out = append(out, &f)
	}
	if r.UDPReachable && !r.HasSOA {
		f := findings.AuthNoSOA.New(server, "The authoritative server did not include the zone SOA in the authority section.")
		f = f.WithZone(zone)
		out = append(out, &f)
	}
	if r.UDPReachable && !r.HasNS {
		f := findings.AuthNoNS.New(server, "The authoritative server did not include NS records for the zone apex.")
		f = f.WithZone(zone)
		out = append(out, &f)
	}
	if r.UDPReachable && !r.HasEDNS {
		f := findings.AuthNoEDNS.New(server, "The server does not support EDNS0 with the DO bit; DNSSEC responses may be truncated.")
		f = f.WithZone(zone)
		out = append(out, &f)
	}
	if !r.Consistent {
		f := findings.AuthInconsistent.New(server, "The server returned inconsistent answers across repeated queries.")
		f = f.WithZone(zone)
		out = append(out, &f)
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
