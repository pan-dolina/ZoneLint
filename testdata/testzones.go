// Package testzones builds controlled authoritative DNS zones used by ZoneLint
// tests. Each constructor returns a resolver.Zone with deterministic records
// so functional tests can assert on stable findings.
package testzones

import (
	"net"

	"github.com/miekg/dns"

	"github.com/example/ZoneLint/internal/resolver"
)

func name(s string) string { return dns.Fqdn(s) }

func mustIP(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		panic("bad ip: " + s)
	}
	return ip
}

func soa(zone, mname, mbox string, serial, refresh, retry, expire, mintl uint32, ttl uint32) dns.RR {
	r := new(dns.SOA)
	r.Hdr = dns.RR_Header{Name: name(zone), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl}
	r.Ns = name(mname)
	r.Mbox = name(mbox)
	r.Serial = serial
	r.Refresh = refresh
	r.Retry = retry
	r.Expire = expire
	r.Minttl = mintl
	return r
}

func ns(zone, nsname string, ttl uint32) dns.RR {
	r := new(dns.NS)
	r.Hdr = dns.RR_Header{Name: name(zone), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl}
	r.Ns = name(nsname)
	return r
}

func a(zone, ip string, ttl uint32) dns.RR {
	r := new(dns.A)
	r.Hdr = dns.RR_Header{Name: name(zone), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
	r.A = mustIP(ip)
	return r
}

func aaaa(zone, ip string, ttl uint32) dns.RR {
	r := new(dns.AAAA)
	r.Hdr = dns.RR_Header{Name: name(zone), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}
	r.AAAA = mustIP(ip)
	return r
}

func txt(zone, s string, ttl uint32) dns.RR {
	r := new(dns.TXT)
	r.Hdr = dns.RR_Header{Name: name(zone), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl}
	r.Txt = []string{s}
	return r
}

func mx(zone, exchange string, pref uint16, ttl uint32) dns.RR {
	r := new(dns.MX)
	r.Hdr = dns.RR_Header{Name: name(zone), Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: ttl}
	r.Mx = name(exchange)
	r.Preference = pref
	return r
}

func cname(zone, target string, ttl uint32) dns.RR {
	r := new(dns.CNAME)
	r.Hdr = dns.RR_Header{Name: name(zone), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl}
	r.Target = name(target)
	return r
}

func caa(zone string, critical int, tag, value string, ttl uint32) dns.RR {
	r := new(dns.CAA)
	r.Hdr = dns.RR_Header{Name: name(zone), Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: ttl}
	r.Tag = tag
	r.Value = value
	r.Flags = byte(critical)
	return r
}

// Healthy returns a well-formed, secure zone.
func Healthy() *resolver.Zone {
	zone := "healthy.test."
	return &resolver.Zone{
		Name: zone,
		Records: map[string][]dns.RR{
			zone: {
				soa(zone, "ns1.healthy.test.", "admin.healthy.test.", 2024010101, 7200, 1800, 1209600, 3600, 3600),
				ns(zone, "ns1.healthy.test.", 3600),
				ns(zone, "ns2.healthy.test.", 3600),
				a("ns1.healthy.test.", "198.51.100.10", 3600),
				a("ns2.healthy.test.", "198.51.100.20", 3600),
				a("healthy.test.", "203.0.113.10", 300),
				txt("healthy.test.", "v=spf1 -all", 300),
			},
		},
	}
}

// LameDelegation has child NS pointing at servers that are not authoritative.
func LameDelegation() *resolver.Zone {
	zone := "lamedelegation.test."
	sub := "sub.lamedelegation.test."
	return &resolver.Zone{
		Name: zone,
		Records: map[string][]dns.RR{
			zone: {
				soa(zone, "ns1.lamedelegation.test.", "admin.lamedelegation.test.", 1, 7200, 1800, 1209600, 3600, 3600),
				ns(zone, "ns1.lamedelegation.test.", 3600),
				// child NS set is inconsistent with parent (parent only lists ns1)
			},
			sub: {
				ns(sub, "ns1.lamedelegation.test.", 3600),
				ns(sub, "ns2.lamedelegation.test.", 3600),
				a("ns1.lamedelegation.test.", "198.51.100.10", 3600),
			},
		},
	}
}

// AXFRAllowed permits zone transfer.
func AXFRAllowed() *resolver.Zone {
	zone := "axfr.test."
	return &resolver.Zone{
		Name:            zone,
		TransferAllowed: true,
		Records: map[string][]dns.RR{
			zone: {
				soa(zone, "ns1.axfr.test.", "admin.axfr.test.", 1, 7200, 1800, 1209600, 3600, 3600),
				ns(zone, "ns1.axfr.test.", 3600),
				a("ns1.axfr.test.", "198.51.100.30", 3600),
				a("axfr.test.", "203.0.113.40", 300),
			},
		},
	}
}

// AXFRDenied refuses transfer.
func AXFRDenied() *resolver.Zone {
	zone := "axfrdenied.test."
	return &resolver.Zone{
		Name: zone,
		Records: map[string][]dns.RR{
			zone: {
				soa(zone, "ns1.axfrdenied.test.", "admin.axfrdenied.test.", 1, 7200, 1800, 1209600, 3600, 3600),
				ns(zone, "ns1.axfrdenied.test.", 3600),
				a("ns1.axfrdenied.test.", "198.51.100.40", 3600),
			},
		},
	}
}

// Recursion enables open recursion probing.
func Recursion() *resolver.Zone {
	return &resolver.Zone{
		Name:      "recursion.test.",
		Recursive: true,
		Records: map[string][]dns.RR{
			"recursion.test.": {
				soa("recursion.test.", "ns1.recursion.test.", "admin.recursion.test.", 1, 7200, 1800, 1209600, 3600, 3600),
				ns("recursion.test.", "ns1.recursion.test.", 3600),
				a("ns1.recursion.test.", "198.51.100.50", 3600),
			},
		},
	}
}

// ShortTTL uses very low TTLs.
func ShortTTL() *resolver.Zone {
	zone := "shortttl.test."
	return &resolver.Zone{
		Name: zone,
		Records: map[string][]dns.RR{
			zone: {
				soa(zone, "ns1.shortttl.test.", "admin.shortttl.test.", 1, 60, 60, 3600, 60, 30),
				ns(zone, "ns1.shortttl.test.", 30),
				a(zone, "203.0.113.60", 30),
			},
		},
	}
}

// Wildcard has a wildcard record.
func Wildcard() *resolver.Zone {
	zone := "wildcard.test."
	return &resolver.Zone{
		Name: zone,
		Records: map[string][]dns.RR{
			zone: {
				soa(zone, "ns1.wildcard.test.", "admin.wildcard.test.", 1, 7200, 1800, 1209600, 3600, 3600),
				ns(zone, "ns1.wildcard.test.", 3600),
				a("ns1.wildcard.test.", "198.51.100.60", 3600),
				a(zone, "203.0.113.70", 300),
				a("*.wildcard.test.", "203.0.113.71", 300),
			},
		},
	}
}

// CNANameLoop has a CNAME loop a -> b -> a.
func CNANameLoop() *resolver.Zone {
	zone := "cnameraise.test."
	return &resolver.Zone{
		Name: zone,
		Records: map[string][]dns.RR{
			zone: {
				soa(zone, "ns1.cnameraise.test.", "admin.cnameraise.test.", 1, 7200, 1800, 1209600, 3600, 3600),
				ns(zone, "ns1.cnameraise.test.", 3600),
				a("ns1.cnameraise.test.", "198.51.100.70", 3600),
			},
			"a.cnameraise.test.": cname("a.cnameraise.test.", "b.cnameraise.test.", 300),
			"b.cnameraise.test.": cname("b.cnameraise.test.", "a.cnameraise.test.", 300),
		},
	}
}

// CNDangling has a CNAME pointing to a non-existent target.
func CNDangling() *resolver.Zone {
	zone := "cnameraisedangle.test."
	return &resolver.Zone{
		Name: zone,
		Records: map[string][]dns.RR{
			zone: {
				soa(zone, "ns1.cnameraisedangle.test.", "admin.cnameraisedangle.test.", 1, 7200, 1800, 1209600, 3600, 3600),
				ns(zone, "ns1.cnameraisedangle.test.", 3600),
				a("ns1.cnameraisedangle.test.", "198.51.100.80", 3600),
			},
			"dangling.cnameraisedangle.test.": cname("dangling.cnameraisedangle.test.", "missing.example.", 300),
		},
	}
}

// PrivateAddr has a public record pointing to a private IP.
func PrivateAddr() *resolver.Zone {
	zone := "privateaddr.test."
	return &resolver.Zone{
		Name: zone,
		Records: map[string][]dns.RR{
			zone: {
				soa(zone, "ns1.privateaddr.test.", "admin.privateaddr.test.", 1, 7200, 1800, 1209600, 3600, 3600),
				ns(zone, "ns1.privateaddr.test.", 3600),
				a("ns1.privateaddr.test.", "198.51.100.90", 3600),
				a("host.privateaddr.test.", "10.0.0.5", 300),
			},
		},
	}
}

// MalformedCAA has an unknown critical CAA property.
func MalformedCAA() *resolver.Zone {
	zone := "malformedcaa.test."
	return &resolver.Zone{
		Name: zone,
		Records: map[string][]dns.RR{
			zone: {
				soa(zone, "ns1.malformedcaa.test.", "admin.malformedcaa.test.", 1, 7200, 1800, 1209600, 3600, 3600),
				ns(zone, "ns1.malformedcaa.test.", 3600),
				a("ns1.malformedcaa.test.", "198.51.100.100", 3600),
				// unknown critical tag "issuetoken" with critical bit set
				caa(zone, 1, "issuetoken", "url=...", 300),
			},
		},
	}
}

// ExtremeTTL uses an absurdly high TTL.
func ExtremeTTL() *resolver.Zone {
	zone := "extremettl.test."
	return &resolver.Zone{
		Name: zone,
		Records: map[string][]dns.RR{
			zone: {
				soa(zone, "ns1.extremettl.test.", "admin.extremettl.test.", 1, 7200, 1800, 1209600, 3600, 3600),
				ns(zone, "ns1.extremettl.test.", 3600),
				a(zone, "203.0.113.110", 999999999),
			},
		},
	}
}
