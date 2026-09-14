// Package report renders audit results as human-readable text, JSON, or SARIF.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/example/ZoneLint/internal/findings"
)

// Format selects the output format.
type Format string

const (
	FormatHuman Format = "human"
	FormatJSON  Format = "json"
	FormatSARIF Format = "sarif"
)

// Summary aggregates finding counts.
type Summary struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
	Pass     int
	Total    int
}

// Summary computes finding counts by severity.
func BuildSummary(fs []*findings.Finding) Summary {
	s := Summary{}
	for _, f := range fs {
		s.Total++
		switch f.Severity {
		case string(findings.SeverityCritical):
			s.Critical++
		case string(findings.SeverityHigh):
			s.High++
		case string(findings.SeverityMedium):
			s.Medium++
		case string(findings.SeverityLow):
			s.Low++
		case string(findings.SeverityInfo):
			s.Info++
		case string(findings.SeverityPass):
			s.Pass++
		}
	}
	return s
}

// severityRank orders severities for sorting.
var severityRank = map[string]int{
	string(findings.SeverityCritical): 0,
	string(findings.SeverityHigh):     1,
	string(findings.SeverityMedium):   2,
	string(findings.SeverityLow):      3,
	string(findings.SeverityInfo):     4,
	string(findings.SeverityPass):     5,
}

// human renders a human-readable report.
func human(sb *strings.Builder, zone string, s Summary, fs []*findings.Finding) {
	fmt.Fprintf(sb, "ZoneLint report for %s\n", zone)
	fmt.Fprintf(sb, "Severity: critical=%d high=%d medium=%d low=%d info=%d pass=%d total=%d\n\n",
		s.Critical, s.High, s.Medium, s.Low, s.Info, s.Pass, s.Total)

	// Sorted by severity, then category, then ID.
	sorted := make([]*findings.Finding, len(fs))
	copy(sorted, fs)
	sort.SliceStable(sorted, func(i, j int) bool {
		ri, rj := severityRank[sorted[i].Severity], severityRank[sorted[j].Severity]
		if ri != rj {
			return ri < rj
		}
		if sorted[i].Category != sorted[j].Category {
			return sorted[i].Category < sorted[j].Category
		}
		return sorted[i].ID < sorted[j].ID
	})

	for _, f := range sorted {
		fmt.Fprintf(sb, "[%s] %s — %s\n", strings.ToUpper(f.Severity), f.ID, f.Title)
		if f.Subject != "" {
			fmt.Fprintf(sb, "  Subject: %s\n", f.Subject)
		}
		fmt.Fprintf(sb, "  %s\n", f.Explanation)
		for _, e := range f.Evidence {
			fmt.Fprintf(sb, "  Evidence: %s\n", e)
		}
		if f.Recommendation != "" {
			fmt.Fprintf(sb, "  Recommendation: %s\n", f.Recommendation)
		}
		if len(f.References) > 0 {
			fmt.Fprintf(sb, "  References: %s\n", strings.Join(f.References, ", "))
		}
		fmt.Fprintf(sb, "\n")
	}
}

// JSON renders findings as structured JSON.
func JSON(sb *strings.Builder, zone string, s Summary, fs []*findings.Finding, queries, records int) error {
	out := map[string]interface{}{
		"schema_version": "1",
		"zone":           zone,
		"summary":        s,
		"findings":       findingsToJSON(fs),
	}
	if queries > 0 {
		out["queries"] = queries
	}
	if records > 0 {
		out["records"] = records
	}
	enc, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	sb.Write(enc)
	sb.WriteString("\n")
	return nil
}

func findingsToJSON(fs []*findings.Finding) []map[string]interface{} {
	var out []map[string]interface{}
	for _, f := range fs {
		m := map[string]interface{}{
			"id":             f.ID,
			"severity":       f.Severity,
			"category":       f.Category,
			"title":          f.Title,
			"explanation":    f.Explanation,
			"evidence":       f.Evidence,
			"recommendation": f.Recommendation,
			"references":     f.References,
		}
		if f.Subject != "" {
			m["subject"] = f.Subject
		}
		out = append(out, m)
	}
	return out
}

// sarif renders findings as SARIF 2.1.0 JSON.
func sarif(sb *strings.Builder, zone string, s Summary, fs []*findings.Finding) error {
	rules := map[string]string{}
	runs := []map[string]interface{}{}
	for _, f := range fs {
		rules[f.ID] = f.Title
	}
	// Group findings by rule id.
	results := []map[string]interface{}{}
	for _, f := range fs {
		loc := map[string]interface{}{
			"logicalLocations": []map[string]interface{}{{
				"fullyQualifiedName": zone,
				"namespace":          zone,
			}},
		}
		msg := map[string]interface{}{"text": f.Explanation}
		if len(f.Evidence) > 0 {
			msg["attachments"] = []map[string]interface{}{}
		}
		results = append(results, map[string]interface{}{
			"ruleId":    f.ID,
			"level":     sarifLevel(f.Severity),
			"message":   msg,
			"locations": []map[string]interface{}{loc},
		})
	}
	runs = append(runs, map[string]interface{}{
		"tool": map[string]interface{}{
			"driver": map[string]interface{}{
				"name":           "ZoneLint",
				"informationUri": "https://github.com/example/ZoneLint",
				"rules":          ruleList(rules),
			},
		},
		"results": results,
	})
	out := map[string]interface{}{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs":    runs,
	}
	enc, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	sb.Write(enc)
	sb.WriteString("\n")
	return nil
}

func ruleList(rules map[string]string) []map[string]interface{} {
	var out []map[string]interface{}
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		out = append(out, map[string]interface{}{"id": id, "shortDescription": map[string]interface{}{"text": rules[id]}})
	}
	return out
}

func sarifLevel(sev string) string {
	switch sev {
	case string(findings.SeverityCritical), string(findings.SeverityHigh):
		return "error"
	case string(findings.SeverityMedium):
		return "warning"
	default:
		return "note"
	}
}

// Render writes a report in the given format to w.
func Render(w io.Writer, zone string, format Format, s Summary, fs []*findings.Finding, queries, records int) error {
	var sb strings.Builder
	switch format {
	case FormatJSON:
		JSON(&sb, zone, s, fs, queries, records)
	case FormatSARIF:
		sarif(&sb, zone, s, fs)
	default:
		human(&sb, zone, s, fs)
	}
	_, err := io.WriteString(w, sb.String())
	return err
}
