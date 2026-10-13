package zeroconf

import (
	"context"
	"testing"
	"time"
)

func TestBrowseEmitsUnannouncement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	ifaces := testMulticastIfaces(t)
	entries := make(chan *ServiceEntry, 10)
	browseErrors := make(chan error, 1)
	go func() {
		browseErrors <- Browse(ctx, "_goodbye--xxxx._tcp", mdnsDomain, entries, Unannouncements(), SelectIfaces(ifaces), SelectIPTraffic(IPv4))
	}()

	server, err := registerTestService(t, "goodbye--xxxxxxxxxxxx", "_goodbye--xxxx._tcp", mdnsDomain, mdnsPort, []string{"id=goodbye"})
	if err != nil {
		t.Fatal(err)
	}

	select {
	case entry := <-entries:
		if !entry.Expiry.After(time.Now()) {
			server.Shutdown()
			t.Fatalf("first event expired at %s", entry.Expiry)
		}
	case err := <-browseErrors:
		server.Shutdown()
		t.Fatalf("browse ended before add event: %v", err)
	case <-ctx.Done():
		server.Shutdown()
		t.Fatal("timed out waiting for add event")
	}

	server.Shutdown()
	select {
	case entry := <-entries:
		if entry.Expiry.After(time.Now()) {
			t.Fatalf("goodbye event expiry = %s, want expired", entry.Expiry)
		}
	case err := <-browseErrors:
		t.Fatalf("browse ended before goodbye event: %v", err)
	case <-ctx.Done():
		t.Fatal("timed out waiting for goodbye event")
	}

	cancel()
	if err := <-browseErrors; err != nil {
		t.Fatalf("browse shutdown: %v", err)
	}
}
