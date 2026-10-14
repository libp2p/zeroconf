package zeroconf

import (
	"context"
	"log"
	"testing"
	"time"
)

var (
	mdnsName    = "test--xxxxxxxxxxxx"
	mdnsService = "_test--xxxx._tcp"
	mdnsSubtype = "_test--xxxx._tcp,_fancy"
	mdnsDomain  = "local."
	mdnsPort    = 8888
)

func startMDNS(t *testing.T, port int, name, service, domain string) {
	// 5353 is default mdns port
	server, err := registerTestService(t, name, service, domain, port, []string{"txtv=0", "lo=1", "la=2"})
	if err != nil {
		t.Fatalf("error while registering mdns service: %s", err)
	}
	t.Cleanup(server.Shutdown)
	log.Printf("Published service: %s, type: %s, domain: %s", name, service, domain)
}

func TestQuickShutdown(t *testing.T) {
	server, err := registerTestService(t, mdnsName, mdnsService, mdnsDomain, mdnsPort, []string{"txtv=0", "lo=1", "la=2"})
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		server.Shutdown()
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("shutdown took longer than 500ms")
	}
}

func TestBasic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	startMDNS(t, mdnsPort, mdnsName, mdnsService, mdnsDomain)

	time.Sleep(time.Second)

	entries := make(chan *ServiceEntry, 100)
	if err := Browse(ctx, mdnsService, mdnsDomain, entries, SelectIfaces(testMulticastIfaces(t)), SelectIPTraffic(IPv4)); err != nil {
		t.Fatalf("Expected browse success, but got %v", err)
	}
	<-ctx.Done()

	if len(entries) != 1 {
		t.Fatalf("Expected number of service entries is 1, but got %d", len(entries))
	}
	result := <-entries
	if result.Domain != mdnsDomain {
		t.Fatalf("Expected domain is %s, but got %s", mdnsDomain, result.Domain)
	}
	if result.Service != mdnsService {
		t.Fatalf("Expected service is %s, but got %s", mdnsService, result.Service)
	}
	if result.Instance != mdnsName {
		t.Fatalf("Expected instance is %s, but got %s", mdnsName, result.Instance)
	}
	if result.Port != mdnsPort {
		t.Fatalf("Expected port is %d, but got %d", mdnsPort, result.Port)
	}
}

func TestNoRegister(t *testing.T) {
	ifaces := testMulticastIfaces(t)
	// before register, mdns resolve shuold not have any entry
	entries := make(chan *ServiceEntry)
	go func(results <-chan *ServiceEntry) {
		s := <-results
		if s != nil {
			t.Errorf("Expected empty service entries but got %v", *s)
		}
	}(entries)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := Browse(ctx, mdnsService, mdnsDomain, entries, SelectIfaces(ifaces), SelectIPTraffic(IPv4)); err != nil {
		t.Fatalf("Expected browse success, but got %v", err)
	}
	<-ctx.Done()
	cancel()
}

func TestSubtype(t *testing.T) {
	t.Run("browse with subtype", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		startMDNS(t, mdnsPort, mdnsName, mdnsSubtype, mdnsDomain)

		time.Sleep(time.Second)

		entries := make(chan *ServiceEntry, 100)
		if err := Browse(ctx, mdnsSubtype, mdnsDomain, entries, SelectIfaces(testMulticastIfaces(t)), SelectIPTraffic(IPv4)); err != nil {
			t.Fatalf("Expected browse success, but got %v", err)
		}
		<-ctx.Done()

		if len(entries) != 1 {
			t.Fatalf("Expected number of service entries is 1, but got %d", len(entries))
		}
		result := <-entries
		if result.Domain != mdnsDomain {
			t.Fatalf("Expected domain is %s, but got %s", mdnsDomain, result.Domain)
		}
		if result.Service != mdnsService {
			t.Fatalf("Expected service is %s, but got %s", mdnsService, result.Service)
		}
		if result.Instance != mdnsName {
			t.Fatalf("Expected instance is %s, but got %s", mdnsName, result.Instance)
		}
		if result.Port != mdnsPort {
			t.Fatalf("Expected port is %d, but got %d", mdnsPort, result.Port)
		}
	})

	t.Run("browse without subtype", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		startMDNS(t, mdnsPort, mdnsName, mdnsSubtype, mdnsDomain)

		time.Sleep(time.Second)

		entries := make(chan *ServiceEntry, 100)
		if err := Browse(ctx, mdnsService, mdnsDomain, entries, SelectIfaces(testMulticastIfaces(t)), SelectIPTraffic(IPv4)); err != nil {
			t.Fatalf("Expected browse success, but got %v", err)
		}
		<-ctx.Done()

		if len(entries) != 1 {
			t.Fatalf("Expected number of service entries is 1, but got %d", len(entries))
		}
		result := <-entries
		if result.Domain != mdnsDomain {
			t.Fatalf("Expected domain is %s, but got %s", mdnsDomain, result.Domain)
		}
		if result.Service != mdnsService {
			t.Fatalf("Expected service is %s, but got %s", mdnsService, result.Service)
		}
		if result.Instance != mdnsName {
			t.Fatalf("Expected instance is %s, but got %s", mdnsName, result.Instance)
		}
		if result.Port != mdnsPort {
			t.Fatalf("Expected port is %d, but got %d", mdnsPort, result.Port)
		}
	})

	t.Run("short ttl remains discoverable", func(t *testing.T) {
		origTTL := defaultTTL
		origInitialQueryInterval := initialQueryInterval
		t.Cleanup(func() {
			defaultTTL = origTTL
			initialQueryInterval = origInitialQueryInterval
		})
		defaultTTL = 1 // 1 second
		initialQueryInterval = 100 * time.Millisecond

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		startMDNS(t, mdnsPort, mdnsName, mdnsSubtype, mdnsDomain)

		entries := make(chan *ServiceEntry, 100)
		if err := Browse(ctx, mdnsService, mdnsDomain, entries, SelectIfaces(testMulticastIfaces(t)), SelectIPTraffic(IPv4)); err != nil {
			t.Fatalf("Expected browse success, but got %v", err)
		}

		<-ctx.Done()
		if len(entries) < 1 {
			t.Fatal("expected at least one entry")
		}
		var instance string
		for len(entries) > 0 {
			entry := <-entries
			if instance == "" {
				instance = entry.ServiceInstanceName()
			}
			if entry.ServiceInstanceName() != instance {
				t.Fatalf("entry instance = %q, want %q", entry.ServiceInstanceName(), instance)
			}
		}
	})
}
