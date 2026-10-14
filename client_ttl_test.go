package zeroconf

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestForkRefreshCachedEntryDoesNotMutateDeliveredEntry(t *testing.T) {
	delivered := &ServiceEntry{Text: []string{"id=one"}, Expiry: time.Now().Add(time.Second)}
	cached := cloneServiceEntry(delivered)
	sent := map[string]*ServiceEntry{"service": cached}
	refreshed := cloneServiceEntry(delivered)
	refreshed.Expiry = delivered.Expiry.Add(10 * time.Second)

	if !refreshCachedEntry(sent, "service", refreshed) {
		t.Fatal("unchanged entry was not treated as an expiry refresh")
	}
	if !delivered.Expiry.Equal(cached.Expiry.Add(-10 * time.Second)) {
		t.Fatalf("delivered expiry changed to %s", delivered.Expiry)
	}
	if !cached.Expiry.Equal(refreshed.Expiry) {
		t.Fatalf("cached expiry = %s, want %s", cached.Expiry, refreshed.Expiry)
	}
}

func TestForkCloneServiceEntryCopiesNestedMetadata(t *testing.T) {
	entry := &ServiceEntry{ServiceRecord: ServiceRecord{Subtypes: []string{"_secure"}}, Text: []string{"id=one"}, AddrIPv4: []net.IP{net.ParseIP("192.0.2.10")}, AddrIPv6: []net.IP{net.ParseIP("2001:db8::10")}}
	cloned := cloneServiceEntry(entry)
	entry.Subtypes[0] = "changed"
	entry.Text[0] = "changed"
	entry.AddrIPv4[0][0] = 198
	entry.AddrIPv6[0][0] = 0x30
	if cloned.Subtypes[0] == "changed" || cloned.Text[0] == "changed" || cloned.AddrIPv4[0].String() != "192.0.2.10" || cloned.AddrIPv6[0].String() != "2001:db8::10" {
		t.Fatal("clone aliases source")
	}
	cloned.Text[0] = "clone changed"
	cloned.AddrIPv4[0][0] = 199
	if entry.Text[0] != "changed" || entry.AddrIPv4[0][0] != 198 {
		t.Fatal("source aliases clone")
	}
}

func TestForkChangedCachedEntryIsNotSuppressed(t *testing.T) {
	original := &ServiceEntry{HostName: "old.local.", Port: 8080, Text: []string{"id=one"}, AddrIPv4: []net.IP{net.ParseIP("192.0.2.10")}, AddrIPv6: []net.IP{net.ParseIP("2001:db8::10")}, Expiry: time.Now().Add(time.Minute)}
	for name, change := range map[string]func(*ServiceEntry){
		"hostname": func(e *ServiceEntry) { e.HostName = "new.local." },
		"port":     func(e *ServiceEntry) { e.Port = 8443 },
		"txt":      func(e *ServiceEntry) { e.Text[0] = "id=two" },
		"ipv4":     func(e *ServiceEntry) { e.AddrIPv4[0] = net.ParseIP("192.0.2.20") },
		"ipv6":     func(e *ServiceEntry) { e.AddrIPv6[0] = net.ParseIP("2001:db8::20") },
	} {
		t.Run(name, func(t *testing.T) {
			cached := cloneServiceEntry(original)
			changed := cloneServiceEntry(original)
			change(changed)
			if refreshCachedEntry(map[string]*ServiceEntry{"service": cached}, "service", changed) {
				t.Fatal("changed content suppressed")
			}
			if !sameService(original, cached) {
				t.Fatal("change check mutated cache")
			}
		})
	}
}

type manualExpiryClock struct {
	mu    sync.Mutex
	now   time.Time
	timer *manualExpiryTimer
}

type manualExpiryTimer struct {
	clock     *manualExpiryClock
	mu        sync.Mutex
	channel   chan time.Time
	deadline  time.Time
	active    bool
	stopCalls int
}

func newManualExpiryClock(now time.Time) *manualExpiryClock {
	return &manualExpiryClock{now: now}
}

func (c *manualExpiryClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *manualExpiryClock) NewTimer(duration time.Duration) expiryTimer {
	c.mu.Lock()
	defer c.mu.Unlock()
	timer := &manualExpiryTimer{clock: c, channel: make(chan time.Time, 1), deadline: c.now.Add(duration), active: true}
	c.timer = timer
	return timer
}

func (c *manualExpiryClock) Advance(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	now, timer := c.now, c.timer
	c.mu.Unlock()
	if timer == nil {
		return
	}
	timer.mu.Lock()
	if timer.active && !timer.deadline.After(now) {
		timer.active = false
		timer.channel <- now
	}
	timer.mu.Unlock()
}

func (c *manualExpiryClock) timerDeadline() time.Time {
	c.mu.Lock()
	timer := c.timer
	c.mu.Unlock()
	if timer == nil {
		return time.Time{}
	}
	timer.mu.Lock()
	defer timer.mu.Unlock()
	return timer.deadline
}

func (c *manualExpiryClock) timerStopped() bool {
	c.mu.Lock()
	timer := c.timer
	c.mu.Unlock()
	if timer == nil {
		return false
	}
	timer.mu.Lock()
	defer timer.mu.Unlock()
	return !timer.active && timer.stopCalls > 0
}

func (t *manualExpiryTimer) C() <-chan time.Time { return t.channel }

func (t *manualExpiryTimer) Stop() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	wasActive := t.active
	t.active = false
	t.stopCalls++
	return wasActive
}

func (t *manualExpiryTimer) Reset(duration time.Duration) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	wasActive := t.active
	t.deadline = t.clock.Now().Add(duration)
	if len(t.channel) > 0 {
		<-t.channel
	}
	t.active = true
	return wasActive
}

func TestForkMDNSExpiryRefreshChangeRemovalAndCancellation(t *testing.T) {
	start := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	clock := newManualExpiryClock(start)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entries := make(chan *ServiceEntry, 8)
	params := newLookupParams("", "_http._tcp", "local", true, entries)
	params.isBrowsing = true
	messages := make(chan *dns.Msg, 8)
	client := &client{unannouncements: true}
	done := make(chan struct{})
	go func() {
		defer close(done)
		client.mainloopWithMessages(ctx, params, messages, clock)
	}()

	messages <- mdnsServicePacket(10, 8080, "id=one", "192.0.2.10")
	added := receiveEntry(t, entries)
	if added.Removed || added.Port != 8080 || added.Text[0] != "id=one" {
		t.Fatalf("added entry = %#v", added)
	}
	waitForExpiryDeadline(t, clock, start.Add(10*time.Second))

	clock.Advance(3 * time.Second)
	messages <- mdnsServicePacket(20, 8080, "id=one", "192.0.2.10")
	waitForExpiryDeadline(t, clock, start.Add(23*time.Second))
	select {
	case event := <-entries:
		t.Fatalf("TTL refresh emitted an event: %#v", event)
	default:
	}

	messages <- mdnsServicePacket(4, 8443, "id=two", "192.0.2.20")
	changed := receiveEntry(t, entries)
	if changed.Removed || changed.Port != 8443 || changed.Text[0] != "id=two" || changed.AddrIPv4[0].String() != "192.0.2.20" {
		t.Fatalf("changed entry = %#v", changed)
	}
	waitForExpiryDeadline(t, clock, start.Add(7*time.Second))

	clock.Advance(4 * time.Second)
	removed := receiveEntry(t, entries)
	if !removed.Removed || removed.Port != 8443 || removed.Text[0] != "id=two" {
		t.Fatalf("removal event = %#v", removed)
	}
	clock.Advance(time.Minute)
	select {
	case event := <-entries:
		t.Fatalf("expired service emitted another event: %#v", event)
	default:
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("mainloop did not stop after cancellation")
	}
	if _, open := <-entries; open {
		t.Fatal("entries channel remained open after cancellation")
	}
	if !clock.timerStopped() {
		t.Fatal("expiry timer was not stopped on cancellation")
	}
}

func mdnsServicePacket(ttl uint32, port uint16, text, address string) *dns.Msg {
	const serviceName = "_http._tcp.local."
	const instanceName = "api._http._tcp.local."
	const hostName = "host.local."
	return &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}, Answer: []dns.RR{
		&dns.PTR{Hdr: dns.RR_Header{Name: serviceName, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttl}, Ptr: instanceName},
		&dns.SRV{Hdr: dns.RR_Header{Name: instanceName, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: ttl}, Port: port, Target: hostName},
		&dns.TXT{Hdr: dns.RR_Header{Name: instanceName, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl}, Txt: []string{text}},
		&dns.A{Hdr: dns.RR_Header{Name: hostName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: net.ParseIP(address).To4()},
	}}
}

func receiveEntry(t *testing.T, entries <-chan *ServiceEntry) *ServiceEntry {
	t.Helper()
	select {
	case entry, ok := <-entries:
		if !ok {
			t.Fatal("entries channel closed unexpectedly")
		}
		return entry
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for service event")
		return nil
	}
}

func waitForExpiryDeadline(t *testing.T, clock *manualExpiryClock, expected time.Time) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if clock.timerDeadline().Equal(expected) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("expiry deadline = %s, want %s", clock.timerDeadline(), expected)
}

func startExpiryLoop(t *testing.T, enabled bool, buffer int) (*manualExpiryClock, chan *dns.Msg, chan *ServiceEntry, context.CancelFunc, <-chan struct{}) {
	t.Helper()
	clock := newManualExpiryClock(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	ctx, cancel := context.WithCancel(context.Background())
	entries := make(chan *ServiceEntry, buffer)
	messages := make(chan *dns.Msg, 8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		(&client{unannouncements: enabled}).mainloopWithMessages(ctx, newLookupParams("", "_http._tcp", "local", true, entries), messages, clock)
	}()
	t.Cleanup(func() { cancel(); waitLoopDone(t, done) })
	return clock, messages, entries, cancel, done
}

func waitLoopDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("loop did not cancel")
	}
}

func expiryStopCalls(clock *manualExpiryClock) int {
	clock.mu.Lock()
	timer := clock.timer
	clock.mu.Unlock()
	if timer == nil {
		return 0
	}
	timer.mu.Lock()
	defer timer.mu.Unlock()
	return timer.stopCalls
}

func waitExpiryCycle(t *testing.T, clock *manualExpiryClock, previous int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if expiryStopCalls(clock) > previous {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timer cycle was not processed")
}

func assertNoEntry(t *testing.T, entries <-chan *ServiceEntry) {
	t.Helper()
	select {
	case e := <-entries:
		t.Fatalf("unexpected event: %#v", e)
	default:
	}
}

func TestForkRenewalOriginalDeadlineAndStaleTimer(t *testing.T) {
	clock, messages, entries, _, _ := startExpiryLoop(t, true, 8)
	start := clock.Now()
	messages <- mdnsServicePacket(10, 8080, "id=one", "192.0.2.10")
	delivered := receiveEntry(t, entries)
	waitForExpiryDeadline(t, clock, start.Add(10*time.Second))
	// Mutating a subscriber snapshot must not change resolver-owned data.
	delivered.Text[0] = "subscriber mutation"
	delivered.AddrIPv4[0][0] = 198
	clock.Advance(3 * time.Second)
	messages <- mdnsServicePacket(20, 8080, "id=one", "192.0.2.10")
	waitForExpiryDeadline(t, clock, start.Add(23*time.Second))
	assertNoEntry(t, entries)
	if !delivered.Expiry.Equal(start.Add(10 * time.Second)) {
		t.Fatal("renewal mutated delivered expiry")
	}
	clock.Advance(7 * time.Second)
	// Simulate an old timer notification after renewal. The current clock,
	// rather than the notification's timestamp, controls expiry.
	previous := expiryStopCalls(clock)
	clock.mu.Lock()
	timer := clock.timer
	clock.mu.Unlock()
	timer.channel <- clock.Now()
	waitExpiryCycle(t, clock, previous)
	assertNoEntry(t, entries)
	clock.Advance(13 * time.Second)
	removed := receiveEntry(t, entries)
	if !removed.Removed || removed.Text[0] != "id=one" || removed.AddrIPv4[0].String() != "192.0.2.10" {
		t.Fatalf("removal reflects subscriber mutation: %#v", removed)
	}
	previous = expiryStopCalls(clock)
	messages <- mdnsServicePacket(0, 8080, "id=one", "192.0.2.10")
	waitExpiryCycle(t, clock, previous)
	assertNoEntry(t, entries)
}

func renamedServicePacket(instance string, ttl uint32) *dns.Msg {
	msg := mdnsServicePacket(ttl, 8080, "id="+instance, "192.0.2.10")
	name := instance + "._http._tcp.local."
	msg.Answer[0].(*dns.PTR).Ptr = name
	msg.Answer[1].Header().Name = name
	msg.Answer[2].Header().Name = name
	return msg
}

func TestForkMultipleServicesEarliestExpiry(t *testing.T) {
	clock, messages, entries, _, _ := startExpiryLoop(t, true, 8)
	start := clock.Now()
	messages <- renamedServicePacket("late", 20)
	receiveEntry(t, entries)
	waitForExpiryDeadline(t, clock, start.Add(20*time.Second))
	messages <- renamedServicePacket("early", 5)
	receiveEntry(t, entries)
	waitForExpiryDeadline(t, clock, start.Add(5*time.Second))
	clock.Advance(5 * time.Second)
	removed := receiveEntry(t, entries)
	if !removed.Removed || removed.Instance != "early" {
		t.Fatalf("wrong first removal: %#v", removed)
	}
	waitForExpiryDeadline(t, clock, start.Add(20*time.Second))
	clock.Advance(15 * time.Second)
	removed = receiveEntry(t, entries)
	if !removed.Removed || removed.Instance != "late" {
		t.Fatalf("wrong second removal: %#v", removed)
	}
}

func TestForkRemovalOptInAndGoodbye(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, goodbye := range []bool{false, true} {
			t.Run(fmt.Sprintf("enabled=%v/goodbye=%v", enabled, goodbye), func(t *testing.T) {
				clock, messages, entries, cancel, done := startExpiryLoop(t, enabled, 8)
				start := clock.Now()
				messages <- mdnsServicePacket(10, 8080, "latest=one", "192.0.2.10")
				receiveEntry(t, entries)
				waitForExpiryDeadline(t, clock, start.Add(10*time.Second))
				previous := expiryStopCalls(clock)
				if goodbye {
					// A PTR-only goodbye uses the last complete cached snapshot.
					packet := mdnsServicePacket(0, 0, "", "192.0.2.99")
					packet.Answer = packet.Answer[:1]
					messages <- packet
				} else {
					clock.Advance(10 * time.Second)
				}
				waitExpiryCycle(t, clock, previous)
				if enabled {
					removed := receiveEntry(t, entries)
					if !removed.Removed || removed.Port != 8080 || removed.Text[0] != "latest=one" {
						t.Fatalf("bad removal: %#v", removed)
					}
				}
				assertNoEntry(t, entries)
				cancel()
				waitLoopDone(t, done)
				if _, open := <-entries; open {
					t.Fatal("result channel remains open")
				}
				if !clock.timerStopped() {
					t.Fatal("timer remains active")
				}
			})
		}
	}
}

func TestForkCancellationInterruptsBlockedDelivery(t *testing.T) {
	for _, event := range []string{"add", "change", "expiry", "goodbye"} {
		t.Run(event, func(t *testing.T) {
			clock, messages, entries, cancel, done := startExpiryLoop(t, true, 0)
			start := clock.Now()
			messages <- mdnsServicePacket(10, 8080, "id=one", "192.0.2.10")
			if event != "add" {
				receiveEntry(t, entries)
				waitForExpiryDeadline(t, clock, start.Add(10*time.Second))
				switch event {
				case "change":
					messages <- mdnsServicePacket(10, 8443, "id=two", "192.0.2.20")
				case "expiry":
					clock.Advance(10 * time.Second)
				case "goodbye":
					messages <- mdnsServicePacket(0, 8080, "id=one", "192.0.2.10")
				}
			}
			// Wait until the packet is consumed, then allow delivery to reach the
			// unbuffered result channel with no receiver.
			deadline := time.Now().Add(time.Second)
			for len(messages) != 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if len(messages) != 0 {
				t.Fatal("packet was not consumed")
			}
			select {
			case <-done:
				t.Fatal("loop exited before cancellation")
			case <-time.After(20 * time.Millisecond):
			}
			// No receiver exists for the next event. Cancellation must release delivery.
			cancel()
			waitLoopDone(t, done)
			if _, open := <-entries; open {
				t.Fatal("result channel remains open")
			}
		})
	}
}

func TestForkChangedSnapshotReplacement(t *testing.T) {
	for name, change := range map[string]func(*dns.Msg){
		"hostname": func(m *dns.Msg) {
			m.Answer[1].(*dns.SRV).Target = "new.local."
			m.Answer[3].Header().Name = "new.local."
		},
		"port":    func(m *dns.Msg) { m.Answer[1].(*dns.SRV).Port = 8443 },
		"txt":     func(m *dns.Msg) { m.Answer[2].(*dns.TXT).Txt = []string{"id=two"} },
		"address": func(m *dns.Msg) { m.Answer[3].(*dns.A).A = net.ParseIP("192.0.2.20").To4() },
	} {
		t.Run(name, func(t *testing.T) {
			clock, messages, entries, _, _ := startExpiryLoop(t, true, 8)
			start := clock.Now()
			messages <- mdnsServicePacket(10, 8080, "id=one", "192.0.2.10")
			receiveEntry(t, entries)
			waitForExpiryDeadline(t, clock, start.Add(10*time.Second))
			packet := mdnsServicePacket(5, 8080, "id=one", "192.0.2.10")
			change(packet)
			messages <- packet
			changed := receiveEntry(t, entries)
			waitForExpiryDeadline(t, clock, start.Add(5*time.Second))
			clock.Advance(5 * time.Second)
			removed := receiveEntry(t, entries)
			if !removed.Removed || removed.HostName != changed.HostName || removed.Port != changed.Port || !reflect.DeepEqual(removed.Text, changed.Text) || !reflect.DeepEqual(removed.AddrIPv4, changed.AddrIPv4) {
				t.Fatalf("removal lost latest content: %#v", removed)
			}
		})
	}
}
