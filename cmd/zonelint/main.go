// Command zonelint is a read-only DNS audit and lint tool.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/pan-dolina/ZoneLint/internal/audit"
	"github.com/pan-dolina/ZoneLint/internal/findings"
	"github.com/pan-dolina/ZoneLint/internal/report"
	"github.com/pan-dolina/ZoneLint/internal/version"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("zonelint", flag.ContinueOnError)
	var (
		jsonOut     = fs.Bool("json", false, "emit JSON output")
		sarifOut    = fs.String("format", "", "output format: human, json, sarif")
		active      = fs.Bool("active", false, "enable opt-in active scans")
		resolver    = fs.String("resolver", "", "resolver to query (default: system resolver)")
		profile     = fs.String("profile", "balanced", "TTL profile: conservative, balanced, agile")
		failOn      = fs.String("fail-on", "", "exit non-zero if a finding at this severity or higher is found: critical, high, medium, low, info")
		timeout     = fs.Duration("timeout", 10*time.Second, "overall query timeout")
		maxQPS      = fs.Int("max-qps", 50, "max queries per second")
		maxQueries  = fs.Int("max-queries", 400, "max total queries")
		noColor     = fs.Bool("no-color", false, "disable colored output")
		quiet       = fs.Bool("quiet", false, "suppress non-finding output")
		verbose     = fs.Bool("verbose", false, "verbose logging")
		showAXFR    = fs.Bool("show-axfr-records", false, "include AXFR record names in output")
		showVersion = fs.Bool("version", false, "print version and exit")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "zonelint — read-only DNS audit tool")
		fmt.Fprintln(stderr, "\nUsage:")
		fmt.Fprintln(stderr, "  zonelint [flags] <domain> [<domain> ...]")
		fmt.Fprintln(stderr, "\nFlags:")
		fs.PrintDefaults()
		fmt.Fprintln(stderr, "\nExit codes:")
		fmt.Fprintln(stderr, "  0  no findings at or above the --fail-on threshold")
		fmt.Fprintln(stderr, "  1  an error occurred, or a finding at or above the")
		fmt.Fprintln(stderr, "     --fail-on threshold was reported")
	}
	if err := fs.Parse(args); err != nil {
		// `--help` prints usage and asks for help; treat it as a graceful
		// exit rather than an error so the CLI returns status 0.
		if err.Error() == "flag: help requested" {
			return nil
		}
		return err
	}

	if *showVersion {
		fmt.Fprintf(stdout, "zonelint %s\n", version.VersionString())
		return nil
	}

	domains := fs.Args()
	if len(domains) == 0 {
		fs.Usage()
		return fmt.Errorf("no domain specified")
	}

	// Allow `zonelint version` as a shortcut for `zonelint -version`.
	if len(domains) == 1 && domains[0] == "version" {
		fmt.Fprintf(stdout, "zonelint %s\n", version.VersionString())
		return nil
	}

	format := report.FormatHuman
	switch {
	case *sarifOut != "":
		format = report.Format(*sarifOut)
	case *jsonOut:
		format = report.FormatJSON
	}

	if format != report.FormatHuman && format != report.FormatJSON && format != report.FormatSARIF {
		return fmt.Errorf("unknown format %q (want human, json, or sarif)", *sarifOut)
	}

	opts := audit.Options{
		Resolver:   *resolver,
		Profile:    *profile,
		Timeout:    *timeout,
		MaxQPS:     *maxQPS,
		MaxQueries: *maxQueries,
		Active:     *active,
		ShowAXFR:   *showAXFR,
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	var failThreshold findings.Severity
	if *failOn != "" {
		v, err := findings.ParseSeverity(strings.ToLower(*failOn))
		if err != nil {
			return fmt.Errorf("unknown --fail-on value %q", *failOn)
		}
		failThreshold = v
	}

	exitCode := 0
	for _, domain := range domains {
		res := audit.New(domain, opts).Run(ctx)
		if err := writeReport(stdout, stderr, domain, format, res, *noColor, *quiet, *verbose); err != nil {
			return err
		}
		if failThreshold > 0 {
			for _, f := range res.Findings {
				if f.Severity >= failThreshold {
					exitCode = 1
					break
				}
			}
		}
	}

	if exitCode != 0 {
		return errExit
	}
	return nil
}

var errExit = fmt.Errorf("findings at or above threshold")

func writeReport(stdout, stderr io.Writer, domain string, format report.Format, res *audit.Result, noColor, quiet, verbose bool) error {
	findings := make([]findings.Finding, len(res.Findings))
	for i, f := range res.Findings {
		findings[i] = *f
	}
	summary := report.BuildSummary(findings)

	if verbose && !quiet {
		fmt.Fprintf(stderr, "audited %s: %d queries, %d records, %d findings (%.1fms)\n",
			domain, res.Queries, res.Records, summary.Total, float64(res.Duration.Microseconds())/1000.0)
	}

	if err := report.Render(stdout, domain, format, summary, findings, res.Queries, res.Records); err != nil {
		return err
	}
	return nil
}
