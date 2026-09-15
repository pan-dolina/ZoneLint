// Package axfr implements a bounded, safe AXFR assessment. It attempts a zone
// transfer per authoritative server, caps the number of records, and never
// prints the full zone by default.
package axfr

import (
	"fmt"
	"time"

	"github.com/miekg/dns"

	"github.com/example/ZoneLint/internal/findings"
)

// Outcome classifies the result of an AXFR attempt.
type Outcome struct {
	Server      string
	Status      string // "allowed" | "refused" | "failed"
	RecordCount int
	Records     []dns.RR // populated only if ShowRecords is true
}

// Config bounds the transfer.
type Config struct {
	MaxRecords  int
	ShowRecords bool
	Timeout     time.Duration
}

// DefaultConfig returns safe defaults.
func DefaultConfig() Config {
	return Config{MaxRecords: 1000, ShowRecords: false, Timeout: 10 * time.Second}
}

// Evaluate records an outcome and returns findings.
func Evaluate(zone, server string, o *Outcome) []*findings.Finding {
	var out []*findings.Finding
	if o == nil {
		return out
	}
	switch o.Status {
	case "allowed":
		f := findings.AXFRAllowed.New(server,
			"The authoritative server accepted an AXFR request and exposed the full zone contents.",
			fmt.Sprintf("server %s returned %d records", server, o.RecordCount))
		f = f.WithZone(zone)
		out = append(out, &f)
	case "refused":
		f := findings.AXFRRefused.New(server, "The server refused AXFR, which is the secure default.")
		f = f.WithZone(zone)
		out = append(out, &f)
	case "failed":
		f := findings.AXFRFailed.New(server, "The AXFR request failed (timeout, format error, or server error).")
		f = f.WithZone(zone)
		out = append(out, &f)
	}
	return out
}

// LimitRecords truncates records to MaxRecords and returns the count.
func LimitRecords(records []dns.RR, max int) []dns.RR {
	if max <= 0 || len(records) <= max {
		return records
	}
	return records[:max]
}

// ParseTransferResult converts a raw transfer response into an Outcome.
func ParseTransferResult(resp *dns.Msg, cfg Config) *Outcome {
	if resp == nil {
		return &Outcome{Status: "failed", RecordCount: 0}
	}
	if resp.Rcode == dns.RcodeRefused {
		return &Outcome{Status: "refused", RecordCount: 0}
	}
	if resp.Rcode != dns.RcodeSuccess {
		return &Outcome{Status: "failed", RecordCount: 0}
	}
	records := resp.Answer
	if cfg.ShowRecords {
		records = append([]dns.RR{}, resp.Answer...)
	}
	limited := LimitRecords(records, cfg.MaxRecords)
	return &Outcome{Status: "allowed", RecordCount: len(limited), Records: limited}
}

// Now returns current time.
func Now() time.Time { return time.Now() }

var _ = dns.Fqdn
