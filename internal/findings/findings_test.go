package findings

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "update docs/findings.md from the catalog")

func TestSeverityRank(t *testing.T) {
	order := []Severity{SeverityPass, SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for i := 1; i < len(order); i++ {
		if order[i] < order[i-1] {
			t.Fatalf("%s should be >= %s", order[i], order[i-1])
		}
		if order[i-1] >= order[i] && order[i] != order[i-1] {
			t.Fatalf("%s should not be >= %s", order[i-1], order[i])
		}
	}
}

func TestSorted(t *testing.T) {
	fs := []Finding{
		DelegMissing.New("", "x"),
		AXFRAllowed.New("", "y"),
		SOAInvalidMNAME.New("", "z"),
	}
	Sort(fs)
	if fs[0].ID != AXFRAllowed.ID {
		t.Fatalf("expected critical first, got %s", fs[0].ID)
	}
	if fs[len(fs)-1].ID != SOAInvalidMNAME.ID {
		t.Fatalf("expected lowest severity last, got %s", fs[len(fs)-1].ID)
	}
}

func TestMaxSeverity(t *testing.T) {
	fs := []Finding{AXFRRefused.New("", "x")}
	if Max(fs) != SeverityPass {
		t.Fatalf("expected pass, got %s", Max(fs))
	}
	fs = append(fs, AXFRAllowed.New("", "y"))
	if Max(fs) != SeverityCritical {
		t.Fatalf("expected critical, got %s", Max(fs))
	}
}

func TestAddEvidence(t *testing.T) {
	f := DelegLame.New("", "lame", "server ns1.example.com", "rcode 5")
	if len(f.Evidence) != 2 {
		t.Fatalf("expected 2 evidence lines, got %d", len(f.Evidence))
	}
}

func TestIDsStable(t *testing.T) {
	ids := map[string]string{
		DelegMissing.ID:      "DNS-DELEGATION-001",
		DNSSECBrokenChain.ID: "DNS-DNSSEC-006",
		AXFRAllowed.ID:       "DNS-AXFR-001",
	}
	for id, want := range ids {
		if id != want {
			t.Fatalf("ID %q != %q", id, want)
		}
	}
}

// TestCatalogDocumented keeps docs/findings.md in sync with the catalog so
// that any change to a public finding ID is visible in review.
func TestCatalogDocumented(t *testing.T) {
	const path = "../../docs/findings.md"
	want := renderCatalogMarkdown()
	if *update {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/findings -update)", err)
	}
	if string(got) != want {
		t.Errorf("docs/findings.md is out of date; run: go test ./internal/findings -update")
	}
}

func renderCatalogMarkdown() string {
	order := []Component{ComponentDelegation, ComponentAuthServer, ComponentSOA,
		ComponentAXFR, ComponentDNSSEC, ComponentTTL, ComponentCAA, ComponentCNAME,
		ComponentAddress, ComponentWildcard, ComponentRecursion, ComponentTransport,
		ComponentGeneral}
	byComponent := map[Component][]Rule{}
	for _, r := range Rules() {
		byComponent[r.Component] = append(byComponent[r.Component], r)
	}

	var b strings.Builder
	b.WriteString("# Finding catalog\n\n")
	b.WriteString("Finding IDs are stable across releases. This file is generated from\n")
	b.WriteString("`internal/findings/catalog.go` by `go test ./internal/findings -update`.\n\n")
	b.WriteString("Severity is the default; context may raise or lower it for a specific\nfinding.\n")
	for _, c := range order {
		rules := byComponent[c]
		if len(rules) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n## %s\n\n", c)
		b.WriteString("| ID | Default severity | Category | Title |\n")
		b.WriteString("|----|------------------|----------|-------|\n")
		for _, r := range rules {
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", r.ID, r.Severity, r.Category, r.Title)
		}
	}
	return b.String()
}
