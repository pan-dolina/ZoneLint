//go:build race

package resolver

import (
	"context"
	"sync"
	"testing"

	"github.com/miekg/dns"

	dnsutil "github.com/example/ZoneLint/internal/dns"
)

// TestConcurrentFakeAccess hammers the fake resolver from many goroutines to
// surface races in its internal maps. Run with:
//
//	go test -race ./internal/resolver
func TestConcurrentFakeAccess(t *testing.T) {
	fake := NewFake()
	fake.AddZone(&Zone{
		Name: "example.test.",
		Records: map[string][]dns.RR{
			"example.test.": {
				buildSOA("example.test.", "ns1.example.test.", "admin.example.test.", 2024010101, 7200, 1800, 1209600, 3600),
				buildNS("example.test.", "ns1.example.test."),
				buildNS("example.test.", "ns2.example.test."),
				buildA("ns1.example.test.", "198.51.100.1", 3600),
				buildA("ns2.example.test.", "198.51.100.2", 3600),
			},
		},
	})

	const workers = 25
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				m := dnsutil.SafeNewMsg("example.test.", dns.TypeNS)
				_, err := fake.Query(context.Background(), "fake", m)
				if err != nil {
					t.Errorf("query failed: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestConcurrentFakeTransfer hammers zone transfer from many goroutines.
func TestConcurrentFakeTransfer(t *testing.T) {
	fake := NewFake()
	fake.AddZone(&Zone{
		Name:            "transfer.test.",
		TransferAllowed: true,
		Records: map[string][]dns.RR{
			"transfer.test.": {
				buildSOA("transfer.test.", "ns1.transfer.test.", "admin.transfer.test.", 2024010101, 7200, 1800, 1209600, 3600),
				buildNS("transfer.test.", "ns1.transfer.test."),
			},
		},
	})

	const workers = 10
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			m := dnsutil.SafeNewMsg("transfer.test.", dns.TypeAXFR)
			for j := 0; j < 3; j++ {
				_, err := fake.Transfer(context.Background(), "fake", m)
				if err != nil {
					t.Errorf("transfer failed: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
