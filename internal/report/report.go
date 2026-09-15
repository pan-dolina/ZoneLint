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
func BuildSummary(fs []findings.Finding) Summary {
	s := Summary{}
	for _, f := range fs {
		s.Total++
		switch f.Severity {
		case findings.SeverityCritical:
			s.Critical++
		case findings.SeverityHigh:
			s.High++
		case findings.SeverityMedium:
			s.Medium++
		case findings.SeverityLow:
			s.Low++
		case findings.SeverityInfo:
			s.Info++
		case findings.SeverityPass:
			s.Pass++
		}
	}
	return s
}

// human renders a human-readable report.
func human(sb *strings.Builder, zone string, s Summary, fs []findings.Finding) {
	fmt.Fprintf(sb, "ZoneLint report for %s\n", zone)
	fmt.Fprintf(sb, "Severity: critical=%d high=%d medium=%d low=%d info=%d pass=%d total=%d\n\n",
		s.Critical, s.High, s.Medium, s.Low, s.Info, s.Pass, s.Total)

	// Sorted by severity, then ID.
	sorted := make([]findings.Finding, len(fs))
	copy(sorted, fs)
	findings.Sort(sorted)

	for _, f := range sorted {
		fmt.Fprintf(sb, "[%s] %s — %s\n", strings.ToUpper(f.Severity.String()), f.ID, f.Title)
		if f.Subject != "" {
			fmt.Fprintf(sb, "  Subject: %s\n", f.Subject)
		}
		fmt.Fprintf(sb, "  %s\n", f.Description)
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
func JSON(sb *strings.Builder, zone string, s Summary, fs []findings.Finding, queries, records int) error {
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

func findingsToJSON(fs []findings.Finding) []map[string]interface{} {
	var out []map[string]interface{}
	for _, f := range fs {
		m := map[string]interface{}{
			"id":             f.ID,
			"severity":       f.Severity.String(),
			"category":       string(f.Category),
			"component":      string(f.Component),
			"title":          f.Title,
			"description":    f.Description,
			"evidence":       f.Evidence,
			"recommendation": f.Recommendation,
			"references":     f.References,
		}
		if f.Subject != "" {
			m["subject"] = f.Subject
		}
		if f.Zone != "" {
			m["zone"] = f.Zone
		}
		out = append(out, m)
	}
	return out
}

// sarif renders findings as SARIF 2.1.0 JSON.
func sarif(sb *strings.Builder, zone string, s Summary, fs []findings.Finding) error {
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
		msg := map[string]interface{}{"text": f.Description}
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

func sarifLevel(sev findings.Severity) string {
	switch sev {
	case findings.SeverityCritical, findings.SeverityHigh:
		return "error"
	case findings.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// Render writes a report in the given format to w.
func Render(w io.Writer, zone string, format Format, s Summary, fs []findings.Finding, queries, records int) error {
	var sb strings.Builder
	var renderErr error
	switch format {
	case FormatJSON:
		renderErr = JSON(&sb, zone, s, fs, queries, records)
	case FormatSARIF:
		renderErr = sarif(&sb, zone, s, fs)
	default:
		human(&sb, zone, s, fs)
	}
	if renderErr != nil {
		return renderErr
	}
	_, err := io.WriteString(w, sb.String())
	return err
}
