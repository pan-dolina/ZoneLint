package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/example/ZoneLint/internal/audit"
	"github.com/example/ZoneLint/internal/resolver"
	"github.com/example/ZoneLint/testdata"
)

func installFake(t *testing.T, zone string) {
	t.Helper()
	orig := audit.ResolverFactory
	audit.ResolverFactory = func(cfg resolver.Config, opt audit.Options) resolver.Resolver {
		fake := resolver.NewFake()
		fake.AddZone(fakeZoneFor(zone))
		return fake
	}
	t.Cleanup(func() { audit.ResolverFactory = orig })
}

func fakeZoneFor(zone string) *resolver.Zone {
	switch {
	case strings.Contains(zone, "healthy"):
		return testzones.Healthy()
	case strings.Contains(zone, "axfr"):
		return testzones.AXFRAllowed()
	default:
		return testzones.Healthy()
	}
}

func TestCLIVersion(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"version"}, &fakeFile{&out}, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "zonelint 0.1.0") {
		t.Fatalf("version output: %q", out.String())
	}
}

func TestCLIAuditJSON(t *testing.T) {
	installFake(t, "healthy.test.")
	var out bytes.Buffer
	err := run([]string{"-json", "healthy.test."}, &fakeFile{&out}, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "schema_version") {
		t.Fatalf("expected JSON output, got %q", out.String())
	}
}

func TestCLIAuditHuman(t *testing.T) {
	installFake(t, "healthy.test.")
	var out bytes.Buffer
	err := run([]string{"healthy.test."}, &fakeFile{&out}, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "ZoneLint report for healthy.test.") {
		t.Fatalf("expected human report, got %q", out.String())
	}
}

func TestCLIAuditFailOn(t *testing.T) {
	installFake(t, "axfr.test.")
	var out bytes.Buffer
	err := run([]string{"-fail-on", "critical", "axfr.test."}, &fakeFile{&out}, os.Stderr)
	if err == nil {
		t.Fatal("expected error exit for critical finding")
	}
	if !strings.Contains(err.Error(), "threshold") {
		t.Fatalf("unexpected error: %v", err)
	}
}

type fakeFile struct {
	*bytes.Buffer
}

func (f *fakeFile) Write(p []byte) (int, error) { return f.Buffer.Write(p) }
