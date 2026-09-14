// Package dns provides defensive DNS message parsing and record-extraction
// helpers built on top of github.com/miekg/dns. All functions are tolerant of
// hostile or malformed input: they never panic and always bound their work.
package dnsutil

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

// SafeNewMsg returns a well-formed query message.
func SafeNewMsg(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = false
	return m
}

// SetEDNS configures EDNS0 with the DO (DNSSEC-OK) bit when dnssec is true and
// a reasonable udp size. It never fails.
func SetEDNS(m *dns.Msg, udpSize int, dnssec bool) {
	if udpSize <= 0 {
		udpSize = 1232
	}
	edns := m.IsEdns0()
	if edns == nil {
		return
	}
	edns.SetUDPSize(uint16(udpSize))
	edns.SetDo(dnssec)
}

// RRByName groups resource records by their name (lowercased, no trailing dot).
func RRByName(records []dns.RR) map[string][]dns.RR {
	out := map[string][]dns.RR{}
	for _, rr := range records {
		if rr == nil {
			continue
		}
		name := dns.Fqdn(rr.Header().Name)
		out[normName(name)] = append(out[normName(name)], rr)
	}
	return out
}

func normName(n string) string {
	return strings.ToLower(n)
}

// Names returns the set of hostnames referenced by NS records.
func NSNames(records []dns.RR) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, rr := range records {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		n := normName(ns.Ns)
		if _, dup := seen[n]; !dup {
			seen[n] = struct{}{}
			out = append(out, n)
		}
	}
	return out
}

// Addrs returns the addresses referenced by A/AAAA records, normalized.
func Addrs(records []dns.RR) []net.IP {
	var out []net.IP
	for _, rr := range records {
		switch r := rr.(type) {
		case *dns.A:
			if r.A != nil {
				out = append(out, r.A)
			}
		case *dns.AAAA:
			if r.AAAA != nil {
				out = append(out, r.AAAA)
			}
		}
	}
	return out
}

// TTL returns the TTL of a record header, guarding against nil.
func TTL(rr dns.RR) uint32 {
	if rr == nil || rr.Header() == nil {
		return 0
	}
	return rr.Header().Ttl
}

// SOA extracts an SOA record from a record set, if present.
func SOA(records []dns.RR) *dns.SOA {
	for _, rr := range records {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa
		}
	}
	return nil
}

// First returns the first record of a given type, or nil.
func First(records []dns.RR, typ uint16) dns.RR {
	for _, rr := range records {
		if rr == nil {
			continue
		}
		if rr.Header().Rrtype == typ {
			return rr
		}
	}
	return nil
}

// RRsOfType returns records of a given type.
func RRsOfType(records []dns.RR, typ uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range records {
		if rr != nil && rr.Header().Rrtype == typ {
			out = append(out, rr)
		}
	}
	return out
}

// RcodeString is a safe Rcode string.
func RcodeString(m *dns.Msg) string {
	if m == nil {
		return "nil"
	}
	return dns.RcodeToString[m.Rcode]
}
