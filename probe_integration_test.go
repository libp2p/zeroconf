package zeroconf

import (
	"context"
	"testing"
	"time"
)

func TestBrowseDoesNotEmitTentativeProbe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	entries := make(chan *ServiceEntry, 10)
	results := make(chan error, 1)
	cl, err := newClient(applyOpts(SelectIfaces(testMulticastIfaces(t)), SelectIPTraffic(IPv4)))
	if err != nil {
		t.Fatal(err)
	}
	params := defaultParams("_tentative._tcp")
	params.Domain = "local."
	params.Entries = entries
	params.isBrowsing = true
	go func() { results <- cl.run(ctx, params) }()
	server, err := registerTestService(t, "tentative", "_tentative._tcp", "local.", 9000, []string{"v=1"})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown()
	select {
	case entry := <-entries:
		if entry == nil {
			t.Fatal("browse closed without an established result")
		}
		server.mu.Lock()
		ready := server.readySet && server.readyErr == nil
		server.mu.Unlock()
		if !ready {
			t.Error("browse emitted a tentative probe as an established registration")
		}
	case <-ctx.Done():
		t.Error("no established browse result")
	}
	cancel()
	if err := <-results; err != nil {
		t.Fatal(err)
	}
}

// Socket creation must not race the exclusive bind used to choose QU probes.
func TestConcurrentServerAndClientSockets(t *testing.T) {
	ifaces := testMulticastIfaces(t)
	for attempt := 0; attempt < 100; attempt++ {
		start := make(chan struct{})
		servers := make(chan error, 1)
		clients := make(chan error, 1)
		go func() {
			<-start
			s, err := newServer(ifaces, applyServerOpts())
			if s != nil {
				s.Shutdown()
			}
			servers <- err
		}()
		go func() {
			<-start
			c, err := newClient(applyOpts(SelectIfaces(ifaces), SelectIPTraffic(IPv4)))
			if c != nil {
				c.shutdown()
			}
			clients <- err
		}()
		close(start)
		serverErr, clientErr := <-servers, <-clients
		if serverErr != nil || clientErr != nil {
			t.Fatalf("attempt %d: server: %v; client: %v", attempt, serverErr, clientErr)
		}
	}
}
