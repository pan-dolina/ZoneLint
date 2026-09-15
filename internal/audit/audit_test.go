package audit

import (
	"context"
	"testing"

	"github.com/pan-dolina/ZoneLint/internal/findings"
	"github.com/pan-dolina/ZoneLint/internal/resolver"
	"github.com/pan-dolina/ZoneLint/internal/ttl"
	"github.com/pan-dolina/ZoneLint/testdata"
)

func findID(fs []*findings.Finding, id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}

func TestHealthyZone(t *testing.T) {
	fake := resolver.NewFake()
	fake.AddZone(testzones.Healthy())
	r := NewWithResolver("healthy.test.", Options{Resolver: "fake", Profile: string(ttl.ProfileBalanced)}, fake)
	res := r.Run(context.Background())
	for _, f := range res.Findings {
		if f.Severity == findings.SeverityCritical || f.Severity == findings.SeverityHigh {
			t.Fatalf("healthy zone should have no high/critical findings, got %+v", f)
		}
	}
}

func TestAXFRAllowed(t *testing.T) {
	fake := resolver.NewFake()
	fake.AddZone(testzones.AXFRAllowed())
	r := NewWithResolver("axfr.test.", Options{Resolver: "fake", Active: true}, fake)
	res := r.Run(context.Background())
	if !findID(res.Findings, findings.AXFRAllowed.ID) {
		t.Fatalf("expected AXFR allowed finding, got %+v", res.Findings)
	}
}

func TestAXFRDenied(t *testing.T) {
	fake := resolver.NewFake()
	fake.AddZone(testzones.AXFRDenied())
	r := NewWithResolver("axfrdenied.test.", Options{Resolver: "fake", Active: true}, fake)
	res := r.Run(context.Background())
	// Should not report AXFR allowed.
	if findID(res.Findings, findings.AXFRAllowed.ID) {
		t.Fatalf("did not expect AXFR allowed, got %+v", res.Findings)
	}
}

func TestPrivateAddr(t *testing.T) {
	fake := resolver.NewFake()
	fake.AddZone(testzones.PrivateAddr())
	r := NewWithResolver("privateaddr.test.", Options{Resolver: "fake"}, fake)
	res := r.Run(context.Background())
	if !findID(res.Findings, findings.AddrPrivate.ID) {
		t.Fatalf("expected private address finding, got %+v", res.Findings)
	}
}

func TestShortTTL(t *testing.T) {
	fake := resolver.NewFake()
	fake.AddZone(testzones.ShortTTL())
	r := NewWithResolver("shortttl.test.", Options{Resolver: "fake", Profile: string(ttl.ProfileBalanced)}, fake)
	res := r.Run(context.Background())
	if !findID(res.Findings, findings.TTLShort.ID) {
		t.Fatalf("expected short TTL finding, got %+v", res.Findings)
	}
}

func TestCNAMELoop(t *testing.T) {
	fake := resolver.NewFake()
	fake.AddZone(testzones.CNANameLoop())
	r := NewWithResolver("cnameraise.test.", Options{Resolver: "fake"}, fake)
	res := r.Run(context.Background())
	if !findID(res.Findings, findings.CNAMELoop.ID) {
		t.Fatalf("expected CNAME loop finding, got %+v", res.Findings)
	}
}

func TestMalformedCAA(t *testing.T) {
	fake := resolver.NewFake()
	fake.AddZone(testzones.MalformedCAA())
	r := NewWithResolver("malformedcaa.test.", Options{Resolver: "fake"}, fake)
	res := r.Run(context.Background())
	if !findID(res.Findings, findings.CAACriticalUnknown.ID) {
		t.Fatalf("expected CAA finding, got %+v", res.Findings)
	}
}

func TestLameDelegation(t *testing.T) {
	fake := resolver.NewFake()
	fake.AddZone(testzones.LameDelegation())
	r := NewWithResolver("lamedelegation.test.", Options{Resolver: "fake"}, fake)
	res := r.Run(context.Background())
	// The lame delegation should surface as a high-severity finding.
	found := false
	for _, f := range res.Findings {
		if f.Severity == findings.SeverityHigh {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected high-severity finding for lame delegation, got %+v", res.Findings)
	}
}
