package findings

import "testing"

func TestSeverityRank(t *testing.T) {
	order := []Severity{SeverityPass, SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for i := 1; i < len(order); i++ {
		if !order[i].IsAtLeast(order[i-1]) {
			t.Fatalf("%s should be >= %s", order[i], order[i-1])
		}
		if order[i-1].IsAtLeast(order[i]) && order[i] != order[i-1] {
			t.Fatalf("%s should not be >= %s", order[i-1], order[i])
		}
	}
}

func TestSorted(t *testing.T) {
	fs := []*Finding{
		New(DelegMissing, SeverityLow, CategoryDelegation, "x"),
		New(DNSSECBrokenChain, SeverityCritical, CategoryDNSSEC, "y"),
		New(SOAInvalidMNAME, SeverityMedium, CategorySOA, "z"),
	}
	sorted := Sorted(fs)
	if sorted[0].ID != DNSSECBrokenChain {
		t.Fatalf("expected critical first, got %s", sorted[0].ID)
	}
	if sorted[len(sorted)-1].ID != DelegMissing {
		t.Fatalf("expected lowest severity last, got %s", sorted[len(sorted)-1].ID)
	}
}

func TestMaxSeverity(t *testing.T) {
	fs := []*Finding{New(AXFRRefused, SeverityInfo, CategoryAXFR, "x")}
	if MaxSeverity(fs) != SeverityInfo {
		t.Fatalf("expected info, got %s", MaxSeverity(fs))
	}
	fs = append(fs, New(AXFRAllowed, SeverityCritical, CategoryAXFR, "y"))
	if MaxSeverity(fs) != SeverityCritical {
		t.Fatalf("expected critical, got %s", MaxSeverity(fs))
	}
}

func TestAddEvidence(t *testing.T) {
	f := New(DelegLame, SeverityHigh, CategoryDelegation, "lame")
	f.AddEvidence("server %s", "ns1.example.com")
	f.AddEvidence("rcode %d", 5)
	if len(f.Evidence) != 2 {
		t.Fatalf("expected 2 evidence lines, got %d", len(f.Evidence))
	}
}

func TestIDsStable(t *testing.T) {
	ids := map[string]string{
		DelegMissing:      "DNS-DELEGATION-001",
		DNSSECBrokenChain: "DNS-DNSSEC-008",
		AXFRAllowed:       "DNS-AXFR-001",
	}
	for id, want := range ids {
		if id != want {
			t.Fatalf("ID %q != %q", id, want)
		}
	}
}
