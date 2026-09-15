// Package delegation compares parent-issued NS records against the child
// authoritative server's NS records and glue, producing findings for lame
// delegations, stale/missing glue, unreachable NS, and inconsistent answer sets.
package delegation

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"

	dnsutil "github.com/pan-dolina/ZoneLint/internal/dns"
	"github.com/pan-dolina/ZoneLint/internal/findings"
)

// ParentView holds what the parent zone says about a delegation.
type ParentView struct {
	NS   []string // NS hostnames from parent
	NSRR []dns.RR // NS records from parent
	// Glue: NS hostname -> addresses (only present for in-bailiwick NS).
	Glue map[string][]net.IP
	// GlueAAAA: NS hostname -> IPv6 addresses.
	GlueAAAA map[string][]net.IP
	// NSFromParentRRset are the raw NS RRs for consistency checks.
	NSFromParentRRset []dns.RR
}

// ChildView holds what the child authoritative server reports.
type ChildView struct {
	NS   []string
	NSRR []dns.RR
	// NSAddr: authoritative NS hostname -> addresses it serves.
	NSAddr map[string][]net.IP
	// NSAddrAAAA: authoritative NS hostname -> IPv6 addresses.
	NSAddrAAAA map[string][]net.IP
	// Authoritative indicates the server claims authority for the zone.
	Authoritative bool
}

// Result aggregates delegation findings.
type Result struct {
	Findings []*finding
}

// finding is a type alias to avoid import cycle in signatures.
type finding = findings.Finding

// Compare builds delegation findings from parent and child views.
func Compare(zone string, parent ParentView, child ChildView, now time.Time) []*finding {
	var out []*finding

	// 1. Parent NS set vs child NS set consistency.
	parentNS := sortedNames(parent.NS)
	childNS := sortedNames(child.NS)
	if !equalSets(parentNS, childNS) {
		f := findings.DelegInconsistentNS.New(zone,
			"The parent zone delegates with a different set of name servers than the child authoritative server claims to serve.",
			fmt.Sprintf("parent NS: %v", parentNS),
			fmt.Sprintf("child NS: %v", childNS))
		out = append(out, &f)
	}

	// 2. Lame delegation: child does not claim authority.
	if !child.Authoritative && len(child.NS) > 0 {
		f := findings.DelegLame.New("zone apex",
			"The authoritative server for the zone did not respond authoritatively (AA=0) to a zone NS/SOA query.")
		f = f.WithZone(zone)
		out = append(out, &f)
	}

	// 3. Unreachable / non-authoritative NS.
	for _, nsHost := range parentNS {
		// Reachability is assessed by the caller via AuthServer; here we flag
		// NS records that exist in parent but are absent from child.
		if !contains(childNS, nsHost) {
			f := findings.DelegNonAuthNS.New(nsHost,
				"The parent lists a name server that the child authoritative server does not include in its own NS set.",
				fmt.Sprintf("parent NS: %s", nsHost))
			f = f.WithZone(zone)
			out = append(out, &f)
		}
	}

	// 4. Missing glue: in-bailiwick NS without A/AAAA.
	for _, nsHost := range parentNS {
		if isSubDomain(nsHost, zone) {
			if len(parent.Glue[nsHost]) == 0 && len(parent.GlueAAAA[nsHost]) == 0 {
				f := findings.DelegMissingGlue.New(nsHost,
					"An in-bailiwick name server has no glue A/AAAA records, so resolvers cannot reach it.",
					fmt.Sprintf("NS %s has no glue", nsHost))
				f = f.WithZone(zone)
				out = append(out, &f)
			}
		}
	}

	return out
}

func sortedNames(names []string) []string {
	out := append([]string{}, names...)
	sort.Strings(out)
	return out
}

func equalSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func isSubDomain(name, zone string) bool {
	n := dns.Fqdn(strings.ToLower(name))
	z := dns.Fqdn(strings.ToLower(zone))
	return n == z || hasSuffix(n, "."+z)
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

// ExtractNSFromResponse parses NS records from a response for a given name.
func ExtractNSFromResponse(resp *dns.Msg, name string) ParentView {
	fqdn := dns.Fqdn(strings.ToLower(name))
	byName := dnsutil.RRByName(resp.Answer)
	byNameAuthority := dnsutil.RRByName(resp.Ns)
	var nsRR []dns.RR
	for _, set := range [][]dns.RR{byName[fqdn], byNameAuthority[fqdn]} {
		nsRR = append(nsRR, set...)
	}
	view := ParentView{Glue: map[string][]net.IP{}, GlueAAAA: map[string][]net.IP{}}
	view.NSRR = nsRR
	view.NS = dnsutil.NSNames(nsRR)
	// Extract glue (A/AAAA) at the apex that corresponds to NS hosts.
	for _, rr := range resp.Answer {
		if rr == nil {
			continue
		}
		switch r := rr.(type) {
		case *dns.A:
			view.Glue[strings.ToLower(r.Hdr.Name)] = append(view.Glue[strings.ToLower(r.Hdr.Name)], r.A)
		case *dns.AAAA:
			view.GlueAAAA[strings.ToLower(r.Hdr.Name)] = append(view.GlueAAAA[strings.ToLower(r.Hdr.Name)], r.AAAA)
		}
	}
	return view
}

// ExtractChildFromResponse builds a ChildView from the child authoritative
// server's response to a zone NS query.
func ExtractChildFromResponse(resp *dns.Msg, zone string) ChildView {
	fqdn := dns.Fqdn(strings.ToLower(zone))
	byName := dnsutil.RRByName(resp.Answer)
	byNameAuthority := dnsutil.RRByName(resp.Ns)
	var nsRR []dns.RR
	for _, set := range [][]dns.RR{byName[fqdn], byNameAuthority[fqdn]} {
		nsRR = append(nsRR, set...)
	}
	view := ChildView{NSAddr: map[string][]net.IP{}, NSAddrAAAA: map[string][]net.IP{}}
	view.NSRR = nsRR
	view.NS = dnsutil.NSNames(nsRR)
	// Collect glue from the child response.
	for _, rr := range append(append([]dns.RR{}, resp.Answer...), resp.Ns...) {
		if rr == nil {
			continue
		}
		switch r := rr.(type) {
		case *dns.A:
			view.NSAddr[strings.ToLower(r.Hdr.Name)] = append(view.NSAddr[strings.ToLower(r.Hdr.Name)], r.A)
		case *dns.AAAA:
			view.NSAddrAAAA[strings.ToLower(r.Hdr.Name)] = append(view.NSAddrAAAA[strings.ToLower(r.Hdr.Name)], r.AAAA)
		}
	}
	return view
}
