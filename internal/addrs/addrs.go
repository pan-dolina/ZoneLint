// Package addrs classifies IP addresses that public DNS records point to,
// flagging those within RFC1918, loopback, link-local, reserved, or
// documentation ranges.
package addrs

import (
	"net"

	"github.com/miekg/dns"

	"github.com/example/ZoneLint/internal/findings"
)

// Classification describes the category of an address.
type Classification struct {
	Category string
	Severity string
	Reason   string
}

// Classify returns a classification for an IP, or nil if it is public.
func Classify(ip net.IP) *Classification {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return classifyV4(v4)
	}
	if v6 := ip.To16(); v6 != nil {
		return classifyV6(v6)
	}
	return nil
}

func classifyV4(ip net.IP) *Classification {
	switch {
	case isLoopbackV4(ip):
		return &Classification{Category: "loopback", Severity: string(findings.SeverityMedium), Reason: "IPv4 loopback 127.0.0.0/8"}
	case isPrivateV4(ip, 10):
		return &Classification{Category: "private", Severity: string(findings.SeverityMedium), Reason: "RFC1918 10.0.0.0/8"}
	case isPrivateV4(ip, 172):
		return &Classification{Category: "private", Severity: string(findings.SeverityMedium), Reason: "RFC1918 172.16.0.0/12"}
	case isPrivateV4(ip, 192):
		return &Classification{Category: "private", Severity: string(findings.SeverityMedium), Reason: "RFC1918 192.168.0.0/16"}
	case ip[0] == 169 && ip[1] == 254:
		return &Classification{Category: "link-local", Severity: string(findings.SeverityLow), Reason: "link-local 169.254.0.0/16"}
	case isDocV4(ip):
		return &Classification{Category: "documentation", Severity: string(findings.SeverityLow), Reason: "documentation 198.51.100.0/24 / 203.0.113.0/24"}
	case ip[0] == 192 && ip[1] == 0 && ip[2] == 0 && ip[3] == 2:
		return &Classification{Category: "reserved", Severity: string(findings.SeverityLow), Reason: "reserved 192.0.0.0/24"}
	case ip[0] >= 224:
		return &Classification{Category: "reserved", Severity: string(findings.SeverityLow), Reason: "reserved/multicast/unicast-multicast"}
	}
	return nil
}

func classifyV6(ip net.IP) *Classification {
	switch {
	case isLoopbackV6(ip):
		return &Classification{Category: "loopback", Severity: string(findings.SeverityMedium), Reason: "IPv6 loopback ::1"}
	case isUniqueLocalV6(ip):
		return &Classification{Category: "private", Severity: string(findings.SeverityMedium), Reason: "IPv6 unique-local fc00::/7"}
	case isLinkLocalV6(ip):
		return &Classification{Category: "link-local", Severity: string(findings.SeverityLow), Reason: "IPv6 link-local fe80::/10"}
	case isUnspecifiedV6(ip):
		return &Classification{Category: "reserved", Severity: string(findings.SeverityLow), Reason: "IPv6 unspecified ::"}
	}
	return nil
}

func isLoopbackV4(ip net.IP) bool {
	return ip[0] == 127
}

func isPrivateV4(ip net.IP, second uint8) bool {
	return ip[0] == second && ip[1] <= 255 && ip[1] >= 0
}

func isDocV4(ip net.IP) bool {
	return (ip[0] == 198 && ip[1] == 51 && ip[2] == 100) ||
		(ip[0] == 203 && ip[1] == 0 && ip[2] == 113)
}

func isLoopbackV6(ip net.IP) bool {
	return ip.IsLoopback()
}

func isUniqueLocalV6(ip net.IP) bool {
	return ip.IsPrivate()
}

func isLinkLocalV6(ip net.IP) bool {
	return ip.IsLinkLocalUnicast()
}

func isUnspecifiedV6(ip net.IP) bool {
	return ip.IsUnspecified()
}

// CheckAll inspects addresses gathered from records and returns findings.
func CheckAll(zone string, records []dns.RR) []*findings.Finding {
	var out []*findings.Finding
	seen := map[string]bool{}
	for _, rr := range records {
		for _, ip := range dnsutilAddrs(rr) {
			c := Classify(ip)
			if c == nil {
				continue
			}
			key := ip.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			f := findings.New(classificationID(c.Category), findings.Severity(c.Severity), findings.CategoryAddress,
				"Public record points to "+c.Category+" address")
			f.Explanation = c.Reason
			f.AddEvidence("address %s", ip.String())
			f.WithZone(zone)
			f.Recommendation = "Public records should not resolve to private/reserved addresses unless intended."
			f.References = []string{"RFC 1918", "RFC 6890"}
			out = append(out, f)
		}
	}
	return out
}

func classificationID(category string) string {
	switch category {
	case "private":
		return findings.AddrPrivate
	case "loopback":
		return findings.AddrLoopback
	case "link-local":
		return findings.AddrLocal
	case "reserved":
		return findings.AddrReserved
	case "documentation":
		return findings.AddrDocumentation
	}
	return findings.AddrReserved
}

func dnsutilAddrs(rr dns.RR) []net.IP {
	if rr == nil {
		return nil
	}
	switch r := rr.(type) {
	case *dns.A:
		if r.A == nil {
			return nil
		}
		return []net.IP{r.A}
	case *dns.AAAA:
		if r.AAAA == nil {
			return nil
		}
		return []net.IP{r.AAAA}
	}
	return nil
}
