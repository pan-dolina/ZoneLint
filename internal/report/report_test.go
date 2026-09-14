package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/example/ZoneLint/internal/findings"
)

func sampleFindings() []*findings.Finding {
	var fs []*findings.Finding
	fs = append(fs, findings.New(findings.GeneralError, findings.SeverityHigh, findings.CategoryGeneral, "Test high"))
	fs = append(fs, findings.New(findings.TTLShort, findings.SeverityInfo, findings.CategoryTTL, "Test info"))
	fs = append(fs, findings.New(findings.AXFRAllowed, findings.SeverityCritical, findings.CategoryAXFR, "Test critical"))
	return fs
}

func TestHuman(t *testing.T) {
	var buf bytes.Buffer
	err := Render(&buf, "example.test.", FormatHuman, BuildSummary(sampleFindings()), sampleFindings(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "ZoneLint report for example.test.") {
		t.Fatal("missing header")
	}
	if !strings.Contains(out, "CRITICAL") || !strings.Contains(out, "HIGH") {
		t.Fatal("missing severities")
	}
}

func TestJSON(t *testing.T) {
	var buf bytes.Buffer
	err := Render(&buf, "example.test.", FormatJSON, BuildSummary(sampleFindings()), sampleFindings(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed["schema_version"] != "1" {
		t.Fatal("missing schema_version")
	}
	findingsArr, ok := parsed["findings"].([]interface{})
	if !ok || len(findingsArr) != 3 {
		t.Fatalf("expected 3 findings, got %v", parsed["findings"])
	}
}

func TestSARIF(t *testing.T) {
	var buf bytes.Buffer
	err := Render(&buf, "example.test.", FormatSARIF, BuildSummary(sampleFindings()), sampleFindings(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid SARIF: %v", err)
	}
	if parsed["version"] != "2.1.0" {
		t.Fatal("missing SARIF version")
	}
	runs, ok := parsed["runs"].([]interface{})
	if !ok || len(runs) != 1 {
		t.Fatal("expected one run")
	}
}

func TestSummaryCounts(t *testing.T) {
	s := BuildSummary(sampleFindings())
	if s.Critical != 1 || s.High != 1 || s.Info != 1 || s.Total != 3 {
		t.Fatalf("unexpected summary: %+v", s)
	}
}
