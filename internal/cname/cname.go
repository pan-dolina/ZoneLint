// Package cname detects CNAME loops, excessive chains, invalid coexistence,
// and dangling targets. It never attempts to claim resources.
package cname

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/example/ZoneLint/internal/findings"
)

// Graph maps a name to its CNAME target.
type Graph map[string]string

// Build constructs a CNAME graph from records.
func Build(records []dns.RR) Graph {
	g := Graph{}
	for _, rr := range records {
		c, ok := rr.(*dns.CNAME)
		if !ok {
			continue
		}
		g[dnsutilFqdnLower(rr.Header().Name)] = dnsutilFqdnLower(c.Target)
	}
	return g
}

// Check scans CNAME chains for loops, excessive length, and dangling targets.
// resolveTarget should return true if the target resolves to a non-CNAME record
// (i.e. it is a valid endpoint). For dangling detection, pass a resolver that
// reports NXDOMAIN.
func Check(zone string, g Graph, maxChain int, resolveTarget func(name string) bool) []*findings.Finding {
	if maxChain <= 0 {
		maxChain = 8
	}
	var out []*findings.Finding
	visited := map[string]bool{}

	for start := range g {
		if visited[start] {
			continue
		}
		chain := walk(start, g, map[string]bool{})
		for _, n := range chain {
			visited[n] = true
		}

		if len(chain) > maxChain {
			f := findings.CNAMEChainLong.New(start,
				fmt.Sprintf("The CNAME chain from %s exceeds %d hops.", start, maxChain),
				fmt.Sprintf("chain: %s", strings.Join(chain, " -> ")))
			f = f.WithZone(zone)
			out = append(out, &f)
		}

		// Dangling: final target does not resolve to a real record.
		if len(chain) > 0 {
			last := chain[len(chain)-1]
			if !resolveTarget(last) {
				f := findings.CNAMEDangling.New(last,
					"The final CNAME target does not resolve to any record; the chain is dangling (potential takeover surface).",
					fmt.Sprintf("target %s does not resolve", last))
				f = f.WithZone(zone)
				out = append(out, &f)
			}
		}
	}

	// Loops are detected during walk; report once per loop root.
	for root, loop := range loopRoots(g) {
		f := findings.CNAMELoop.New(root,
			fmt.Sprintf("A CNAME loop was detected starting at %s.", root),
			fmt.Sprintf("loop: %s", loop))
		f.WithZone(zone)
		f.Subject = root
		f = f.WithZone(zone)
		out = append(out, &f)
	}

	return out
}

// walk follows CNAME links, detecting loops, returning the chain (no repeats).
func walk(start string, g Graph, inPath map[string]bool) []string {
	var chain []string
	cur := start
	seen := map[string]bool{}
	for {
		if seen[cur] {
			// Loop detected; return the path up to the repeat.
			return chain
		}
		seen[cur] = true
		target, ok := g[cur]
		if !ok {
			return chain
		}
		chain = append(chain, target)
		cur = target
		if len(chain) > 100 { // safety cap
			return chain
		}
	}
}

// loopRoots returns a map of loop root -> loop path for each detected loop.
func loopRoots(g Graph) map[string]string {
	out := map[string]string{}
	for start := range g {
		seen := map[string]bool{}
		cur := start
		path := []string{}
		for {
			if seen[cur] {
				// Found a loop; record it keyed by the repeated node.
				loop := strings.Join(append(path, cur), " -> ")
				out[cur] = loop
				break
			}
			seen[cur] = true
			path = append(path, cur)
			next, ok := g[cur]
			if !ok {
				break
			}
			cur = next
			if len(path) > 100 {
				break
			}
		}
	}
	return out
}

func dnsutilFqdnLower(n string) string {
	return strings.ToLower(dns.Fqdn(n))
}
