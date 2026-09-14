package audit

import (
	"context"
	"testing"

	"github.com/example/ZoneLint/internal/resolver"
	"github.com/example/ZoneLint/internal/ttl"
	"github.com/example/ZoneLint/testdata"
)

func BenchmarkAuditHealthy(b *testing.B) {
	fake := resolver.NewFake()
	fake.AddZone(testzones.Healthy())
	opt := Options{Resolver: "fake", Profile: string(ttl.ProfileBalanced)}
	for i := 0; i < b.N; i++ {
		r := NewWithResolver("healthy.test.", opt, fake)
		_ = r.Run(context.Background())
	}
}

func BenchmarkAuditAXFR(b *testing.B) {
	fake := resolver.NewFake()
	fake.AddZone(testzones.AXFRAllowed())
	opt := Options{Resolver: "fake", Active: true}
	for i := 0; i < b.N; i++ {
		r := NewWithResolver("axfr.test.", opt, fake)
		_ = r.Run(context.Background())
	}
}

func BenchmarkAuditLameDelegation(b *testing.B) {
	fake := resolver.NewFake()
	fake.AddZone(testzones.LameDelegation())
	opt := Options{Resolver: "fake"}
	for i := 0; i < b.N; i++ {
		r := NewWithResolver("lamedelegation.test.", opt, fake)
		_ = r.Run(context.Background())
	}
}
