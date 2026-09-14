// Package auditfunctional provides 20 end-to-end functional tests that run the
// full audit pipeline against the controlled in-memory zones.
package auditfunctional

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/example/ZoneLint/internal/audit"
	"github.com/example/ZoneLint/internal/findings"
	"github.com/example/ZoneLint/internal/report"
	"github.com/example/ZoneLint/internal/resolver"
	"github.com/example/ZoneLint/internal/ttl"
	"github.com/example/ZoneLint/testdata"
)

// findID reports whether any finding has the given ID.
func findID(fs []*findings.Finding, id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}

// maxSeverity returns the highest severity rank present.
func maxSeverity(fs []*findings.Finding) int {
	max := -1
	for _, f := range fs {
		if r := findings.SeverityRank[findings.Severity(f.Severity)]; r > max {
			max = r
		}
	}
	return max
}

func run(t *testing.T, zone string, z *resolver.Zone, opts audit.Options) *audit.Result {
	t.Helper()
	fake := resolver.NewFake()
	fake.AddZone(z)
	r := audit.NewWithResolver(zone, opts, fake)
	return r.Run(context.Background())
}

func hasID(fs []*findings.Finding, id string) bool { return findID(fs, id) }

// 1. Healthy zone: no high/critical findings.
func TestHealthyNoHigh(t *testing.T) {
	res := run(t, "healthy.test.", testzones.Healthy(), audit.Options{Resolver: "fake", Profile: string(ttl.ProfileBalanced)})
	if maxSeverity(res.Findings) >= int(findings.SeverityRank[findings.SeverityHigh]) {
		t.Fatalf("healthy zone has high+ findings: %+v", res.Findings)
	}
}

// 2. Healthy zone: DNSSEC present and valid (no missing-key/chain findings).
func TestHealthyDNSSECValid(t *testing.T) {
	res := run(t, "healthy.test.", testzones.Healthy(), audit.Options{Resolver: "fake"})
	if hasID(res.Findings, findings.DNSSECNoDNSKEY) || hasID(res.Findings, findings.DNSSECNoRRSIG) {
		t.Fatalf("healthy zone should have valid DNSSEC: %+v", res.Findings)
	}
}

// 3. AXFR allowed produces critical finding.
func TestAXFRAllowed(t *testing.T) {
	res := run(t, "axfr.test.", testzones.AXFRAllowed(), audit.Options{Resolver: "fake", Active: true})
	if !hasID(res.Findings, findings.AXFRAllowed) {
		t.Fatalf("expected AXFR allowed: %+v", res.Findings)
	}
	if res.Findings[0].Severity != string(findings.SeverityCritical) {
		t.Fatalf("expected critical, got %s", res.Findings[0].Severity)
	}
}

// 4. AXFR denied produces pass finding, not critical.
func TestAXFRDenied(t *testing.T) {
	res := run(t, "axfrdenied.test.", testzones.AXFRDenied(), audit.Options{Resolver: "fake", Active: true})
	if hasID(res.Findings, findings.AXFRAllowed) {
		t.Fatalf("did not expect AXFR allowed: %+v", res.Findings)
	}
	if !hasID(res.Findings, findings.AXFRRefused) {
		t.Fatalf("expected AXFR refused: %+v", res.Findings)
	}
}

// 5. Lame delegation: parent/child NS mismatch produces high finding.
func TestLameDelegation(t *testing.T) {
	res := run(t, "lamedelegation.test.", testzones.LameDelegation(), audit.Options{Resolver: "fake"})
	if maxSeverity(res.Findings) < int(findings.SeverityRank[findings.SeverityHigh]) {
		t.Fatalf("expected high finding for lame delegation: %+v", res.Findings)
	}
}

// 6. Short TTL produces info finding.
func TestShortTTL(t *testing.T) {
	res := run(t, "shortttl.test.", testzones.ShortTTL(), audit.Options{Resolver: "fake", Profile: string(ttl.ProfileBalanced)})
	if !hasID(res.Findings, findings.TTLShort) {
		t.Fatalf("expected short TTL: %+v", res.Findings)
	}
}

// 7. Extreme TTL produces low finding.
func TestExtremeTTL(t *testing.T) {
	res := run(t, "extremettl.test.", testzones.ExtremeTTL(), audit.Options{Resolver: "fake", Profile: string(ttl.ProfileBalanced)})
	if !hasID(res.Findings, findings.TTLExtreme) {
		t.Fatalf("expected extreme TTL: %+v", res.Findings)
	}
}

// 8. Wildcard produces info finding.
func TestWildcard(t *testing.T) {
	res := run(t, "wildcard.test.", testzones.Wildcard(), audit.Options{Resolver: "fake"})
	if !hasID(res.Findings, findings.WildcardPresent) {
		t.Fatalf("expected wildcard finding: %+v", res.Findings)
	}
}

// 9. CNAME loop produces high finding.
func TestCNAMELoop(t *testing.T) {
	res := run(t, "cnameraise.test.", testzones.CNANameLoop(), audit.Options{Resolver: "fake"})
	if !hasID(res.Findings, findings.CNAMELoop) {
		t.Fatalf("expected CNAME loop: %+v", res.Findings)
	}
}

// 10. CNAME dangling produces high finding.
func TestCNAMEDangling(t *testing.T) {
	res := run(t, "cnameraisedangle.test.", testzones.CNDangling(), audit.Options{Resolver: "fake"})
	if !hasID(res.Findings, findings.CNAMEDangling) {
		t.Fatalf("expected dangling: %+v", res.Findings)
	}
}

// 11. Private address produces finding.
func TestPrivateAddr(t *testing.T) {
	res := run(t, "privateaddr.test.", testzones.PrivateAddr(), audit.Options{Resolver: "fake"})
	if !hasID(res.Findings, findings.AddrPrivate) {
		t.Fatalf("expected private address: %+v", res.Findings)
	}
}

// 12. Malformed CAA produces finding.
func TestMalformedCAA(t *testing.T) {
	res := run(t, "malformedcaa.test.", testzones.MalformedCAA(), audit.Options{Resolver: "fake"})
	if !hasID(res.Findings, findings.CAACriticalUnknown) {
		t.Fatalf("expected CAA finding: %+v", res.Findings)
	}
}

// 13. Expired DNSSEC produces finding.
func TestExpiredDNSSEC(t *testing.T) {
	res := run(t, "expireddnssec.test.", testzones.ExpireDNSSec(), audit.Options{Resolver: "fake"})
	if !hasID(res.Findings, findings.DNSSECSignExpired) {
		t.Fatalf("expected expired signature: %+v", res.Findings)
	}
}

// 14. Broken DNSSEC produces finding.
func TestBrokenDNSSEC(t *testing.T) {
	res := run(t, "brokendnssec.test.", testzones.BrokenDNSSec(), audit.Options{Resolver: "fake"})
	// Should have at least one DNSSEC finding.
	found := false
	for _, f := range res.Findings {
		if strings.HasPrefix(f.ID, "DNS-DNSSEC-") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected DNSSEC finding: %+v", res.Findings)
	}
}

// 15. Recursion zone produces open recursion finding when active.
func TestRecursion(t *testing.T) {
	res := run(t, "recursion.test.", testzones.Recursion(), audit.Options{Resolver: "fake", Active: true})
	if !hasID(res.Findings, findings.RecursionOpen) {
		t.Fatalf("expected open recursion: %+v", res.Findings)
	}
}

// 16. Output is JSON-serializable and schema_version is set.
func TestJSONOutput(t *testing.T) {
	res := run(t, "healthy.test.", testzones.Healthy(), audit.Options{Resolver: "fake"})
	var buf strings.Builder
	err := report.Render(&buf, "healthy.test.", report.FormatJSON, report.BuildSummary(res.Findings), res.Findings)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(buf.String()), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed["schema_version"] != "1" {
		t.Fatalf("missing schema_version: %v", parsed["schema_version"])
	}
}

// 17. Findings are sorted by severity.
func TestFindingsSorted(t *testing.T) {
	res := run(t, "axfr.test.", testzones.AXFRAllowed(), audit.Options{Resolver: "fake", Active: true})
	for i := 1; i < len(res.Findings); i++ {
		prev := findings.SeverityRank[findings.Severity(res.Findings[i-1].Severity)]
		cur := findings.SeverityRank[findings.Severity(res.Findings[i].Severity)]
		if prev < cur {
			t.Fatalf("findings not sorted descending at index %d", i)
		}
	}
}

// 18. Every finding has required fields populated.
func TestFindingsComplete(t *testing.T) {
	res := run(t, "axfr.test.", testzones.AXFRAllowed(), audit.Options{Resolver: "fake", Active: true})
	for _, f := range res.Findings {
		if f.ID == "" || f.Title == "" || f.Explanation == "" {
			t.Fatalf("finding missing fields: %+v", f)
		}
		if f.Zone == "" {
			t.Fatalf("finding missing zone: %+v", f)
		}
	}
}

// 19. No-color output is valid text.
func TestHumanOutput(t *testing.T) {
	res := run(t, "healthy.test.", testzones.Healthy(), audit.Options{Resolver: "fake"})
	var buf strings.Builder
	err := report.Render(&buf, "healthy.test.", report.FormatHuman, report.BuildSummary(res.Findings), res.Findings)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "ZoneLint report for") {
		t.Fatalf("expected human report header: %q", buf.String())
	}
}

// 20. SARIF output is valid SARIF 2.1.0.
func TestSARIFOutput(t *testing.T) {
	res := run(t, "axfr.test.", testzones.AXFRAllowed(), audit.Options{Resolver: "fake", Active: true})
	var buf strings.Builder
	err := report.Render(&buf, "axfr.test.", report.FormatSARIF, report.BuildSummary(res.Findings), res.Findings)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(buf.String()), &parsed); err != nil {
		t.Fatalf("invalid SARIF: %v", err)
	}
	if parsed["version"] != "2.1.0" {
		t.Fatalf("missing SARIF version: %v", parsed["version"])
	}
}
