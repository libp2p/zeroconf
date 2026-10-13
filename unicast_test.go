package zeroconf

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const testService = "_demo._tcp"
const testDomain = "example.test."
const testInstance = "Demo._demo._tcp.example.test."
const testHost = "host.example.test."

type dnsTestServer struct {
	mu         sync.Mutex
	records    map[string][]dns.RR
	rcode      int
	incomplete bool
	silent     bool
	truncate   bool
	rejectEDNS bool
	tcpQueries int
	queries    []dns.Question
	address    string
}

func recordKey(name string, kind uint16) string {
	return strings.ToLower(dns.Fqdn(name)) + fmt.Sprint(kind)
}
func rr(t *testing.T, text string) dns.RR {
	t.Helper()
	r, err := dns.NewRR(text)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func startDNSServer(t *testing.T) *dnsTestServer {
	t.Helper()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp", udp.LocalAddr().String())
	if err != nil {
		udp.Close()
		t.Fatal(err)
	}
	s := &dnsTestServer{records: map[string][]dns.RR{}, address: udp.LocalAddr().String()}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.queries = append(s.queries, r.Question...)
		_, isTCP := w.RemoteAddr().(*net.TCPAddr)
		if isTCP {
			s.tcpQueries++
		}
		if s.silent {
			return
		}
		response := new(dns.Msg)
		response.SetReply(r)
		response.Authoritative = true
		response.Rcode = s.rcode
		if s.rejectEDNS && r.IsEdns0() != nil {
			response.Rcode = dns.RcodeFormatError
			w.WriteMsg(response)
			return
		}
		if s.truncate && !isTCP {
			response.Truncated = true
			w.WriteMsg(response)
			return
		}
		for _, question := range r.Question {
			response.Answer = append(response.Answer, s.records[recordKey(question.Name, question.Qtype)]...)
		}
		if len(response.Answer) == 0 && !s.incomplete && (s.rcode == dns.RcodeSuccess || s.rcode == dns.RcodeNameError) {
			response.Ns = []dns.RR{rr(t, "example.test. 2 IN SOA ns.example.test. admin.example.test. 1 10 10 10 1")}
		}
		w.WriteMsg(response)
	})
	servers := []*dns.Server{{PacketConn: udp, Handler: handler}, {Listener: tcp, Handler: handler}}
	for _, server := range servers {
		server := server
		ready := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		go func(server *dns.Server) {
			if err := server.ActivateAndServe(); err != nil {
				t.Log(err)
			}
		}(server)
		<-ready
		t.Cleanup(func() { server.Shutdown() })
	}
	return s
}

func (s *dnsTestServer) set(t *testing.T, name string, kind uint16, values ...string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[recordKey(name, kind)] = nil
	for _, value := range values {
		s.records[recordKey(name, kind)] = append(s.records[recordKey(name, kind)], rr(t, value))
	}
}

func (s *dnsTestServer) service(t *testing.T, ttl int) {
	s.set(t, testService+"."+testDomain, dns.TypePTR, fmt.Sprintf("%s.%s %d IN PTR %s", testService, testDomain, ttl, testInstance))
	s.set(t, testInstance, dns.TypeSRV, fmt.Sprintf("%s %d IN SRV 0 0 8080 %s", testInstance, ttl, testHost))
	s.set(t, testInstance, dns.TypeTXT, fmt.Sprintf("%s %d IN TXT \"region=west\" \"opaque=a=b\" \"\"", testInstance, ttl))
	s.set(t, testHost, dns.TypeA, fmt.Sprintf("%s %d IN A 192.0.2.1", testHost, ttl))
}

func lookupTest(t *testing.T, s *dnsTestServer) *ServiceEntry {
	t.Helper()
	entries := make(chan *ServiceEntry, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := Lookup(ctx, "Demo", testService, testDomain, entries, UnicastDNS(s.address)); err != nil {
		t.Fatal(err)
	}
	entry, ok := <-entries
	if !ok || entry == nil {
		t.Fatal("missing result")
	}
	if _, ok := <-entries; ok {
		t.Fatal("lookup did not close channel")
	}
	return entry
}

func TestUnicastLookupAddressFamilies(t *testing.T) {
	for _, family := range []string{"ipv4", "ipv6", "dual"} {
		t.Run(family, func(t *testing.T) {
			s := startDNSServer(t)
			s.service(t, 10)
			if family == "ipv6" {
				s.set(t, testHost, dns.TypeA)
			}
			if family != "ipv4" {
				s.set(t, testHost, dns.TypeAAAA, testHost+" 10 IN AAAA 2001:db8::1")
			}
			entry := lookupTest(t, s)
			if len(entry.AddrIPv4) != boolInt(family != "ipv6") || len(entry.AddrIPv6) != boolInt(family != "ipv4") {
				t.Fatalf("families: %+v", entry)
			}
			if !reflect.DeepEqual(entry.Text, []string{"region=west", "opaque=a=b", ""}) {
				t.Fatalf("TXT: %#v", entry.Text)
			}
			if entry.Instance != "Demo" || entry.Service != testService || entry.Domain != testDomain || entry.HostName != testHost || entry.Port != 8080 {
				t.Fatalf("entry: %+v", entry)
			}
		})
	}
}
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func TestUnicastAllSRVCandidatesAndTCP(t *testing.T) {
	s := startDNSServer(t)
	s.service(t, 10)
	s.mu.Lock()
	s.truncate = true
	s.mu.Unlock()
	s.set(t, testInstance, dns.TypeSRV,
		testInstance+" 10 IN SRV 20 0 9000 backup.example.test.",
		testInstance+" 10 IN SRV 10 1 8080 a.example.test.",
		testInstance+" 10 IN SRV 10 8 8081 a.example.test.",
		testInstance+" 10 IN SRV 10 0 8082 b.example.test.",
		testInstance+" 10 IN SRV 30 2 9001 unresolved.example.test.")
	for _, host := range []string{"a", "b", "backup"} {
		s.set(t, host+".example.test.", dns.TypeA, host+".example.test. 10 IN A 192.0.2.4")
	}
	entry := lookupTest(t, s)
	if len(entry.SRVCandidates) != 5 {
		t.Fatalf("candidates: %+v", entry.SRVCandidates)
	}
	want := [][3]int{{10, 1, 8080}, {10, 8, 8081}, {10, 0, 8082}, {20, 0, 9000}, {30, 2, 9001}}
	for i, candidate := range entry.SRVCandidates {
		if [3]int{int(candidate.Priority), int(candidate.Weight), candidate.Port} != want[i] {
			t.Fatalf("candidate %d: %+v", i, candidate)
		}
	}
	if len(entry.SRVCandidates[4].AddrIPv4) != 0 {
		t.Fatal("unresolved candidate was given addresses")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tcpQueries == 0 {
		t.Fatal("no TCP retry")
	}
	for _, q := range s.queries {
		if !strings.HasSuffix(q.Name, "example.test.") {
			t.Fatalf("unexpected query: %+v", q)
		}
	}
}

func TestUnicastBrowseMultipleAndSubtype(t *testing.T) {
	s := startDNSServer(t)
	s.service(t, 10)
	second := "Other._demo._tcp.example.test."
	s.set(t, "_fast._sub._demo._tcp.example.test.", dns.TypePTR,
		"_fast._sub._demo._tcp.example.test. 10 IN PTR "+testInstance,
		"_fast._sub._demo._tcp.example.test. 10 IN PTR "+second)
	s.set(t, second, dns.TypeSRV, second+" 10 IN SRV 0 0 8081 "+testHost)
	s.set(t, second, dns.TypeTXT, second+" 10 IN TXT \"other=yes\"")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entries := make(chan *ServiceEntry, 4)
	done := make(chan error, 1)
	go func() { done <- Browse(ctx, testService+",_fast", testDomain, entries, UnicastDNS(s.address)) }()
	names := map[string]bool{}
	for len(names) < 2 {
		names[nextEntry(t, entries).Instance] = true
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !names["Demo"] || !names["Other"] {
		t.Fatal(names)
	}
}

func nextEntry(t *testing.T, entries <-chan *ServiceEntry) *ServiceEntry {
	t.Helper()
	select {
	case entry, ok := <-entries:
		if !ok {
			t.Fatal("channel closed")
		}
		return entry
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for entry")
		return nil
	}
}

func TestUnicastRefreshChangesNoDuplicatesAndRemoval(t *testing.T) {
	s := startDNSServer(t)
	s.service(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entries := make(chan *ServiceEntry, 8)
	done := make(chan error, 1)
	go func() {
		done <- Browse(ctx, testService, testDomain, entries, UnicastDNS(s.address), Unannouncements())
	}()
	initial := nextEntry(t, entries)
	expiry := initial.Expiry
	// Several TTL renewals must not duplicate unchanged data or mutate an old event.
	select {
	case entry := <-entries:
		t.Fatalf("duplicate result: %+v", entry)
	case <-time.After(1800 * time.Millisecond):
	}
	if initial.Expiry != expiry {
		t.Fatal("previous event mutated")
	}
	s.set(t, testInstance, dns.TypeTXT, testInstance+" 1 IN TXT \"region=east\"")
	s.set(t, testInstance, dns.TypeSRV, testInstance+" 1 IN SRV 2 3 9090 new.example.test.")
	s.set(t, "new.example.test.", dns.TypeAAAA, "new.example.test. 1 IN AAAA 2001:db8::7")
	var changed *ServiceEntry
	for {
		changed = nextEntry(t, entries)
		if changed.Port == 9090 && reflect.DeepEqual(changed.Text, []string{"region=east"}) {
			break
		}
	}
	if changed.HostName != "new.example.test." || len(changed.AddrIPv6) != 1 || changed.SRVCandidates[0].Priority != 2 || changed.SRVCandidates[0].Weight != 3 {
		t.Fatalf("change: %+v", changed)
	}
	s.set(t, "new.example.test.", dns.TypeAAAA, "new.example.test. 1 IN AAAA 2001:db8::8")
	for {
		changed = nextEntry(t, entries)
		if changed.AddrIPv6[0].String() == "2001:db8::8" {
			break
		}
	}
	// SERVFAIL is not evidence of disappearance, even after prior TTLs expire.
	s.mu.Lock()
	s.rcode = dns.RcodeServerFailure
	s.mu.Unlock()
	select {
	case entry := <-entries:
		t.Fatalf("transient failure produced event: %+v", entry)
	case <-time.After(1500 * time.Millisecond):
	}
	s.mu.Lock()
	s.rcode = dns.RcodeNameError
	s.records = map[string][]dns.RR{}
	s.mu.Unlock()
	removed := nextEntry(t, entries)
	if !removed.Removed || removed.Expiry.After(time.Now()) {
		t.Fatalf("removal: %+v", removed)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestUnicastIncompleteAndDelayedAddress(t *testing.T) {
	s := startDNSServer(t)
	s.service(t, 1)
	s.set(t, testHost, dns.TypeA)
	s.mu.Lock()
	s.incomplete = true
	s.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entries := make(chan *ServiceEntry, 2)
	done := make(chan error, 1)
	go func() {
		done <- Browse(ctx, testService, testDomain, entries, UnicastDNS(s.address), Unannouncements())
	}()
	select {
	case entry := <-entries:
		t.Fatalf("unresolved result: %+v", entry)
	case <-time.After(200 * time.Millisecond):
	}
	s.set(t, testHost, dns.TypeA, testHost+" 1 IN A 192.0.2.9")
	entry := nextEntry(t, entries)
	if entry.AddrIPv4[0].String() != "192.0.2.9" {
		t.Fatal(entry)
	}
	// Empty answers with no SOA must not clear the old service.
	s.mu.Lock()
	s.records = map[string][]dns.RR{}
	s.mu.Unlock()
	select {
	case entry := <-entries:
		t.Fatalf("incomplete answer removed entry: %+v", entry)
	case <-time.After(1300 * time.Millisecond):
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestUnicastCancellationAndDeadline(t *testing.T) {
	for _, method := range []string{"cancel", "deadline"} {
		t.Run(method, func(t *testing.T) {
			s := startDNSServer(t)
			s.mu.Lock()
			s.silent = true
			s.mu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			entries := make(chan *ServiceEntry)
			started := time.Now()
			go func() { done <- Lookup(ctx, "Demo", testService, testDomain, entries, UnicastDNS(s.address)) }()
			if method == "cancel" {
				time.Sleep(30 * time.Millisecond)
				cancel()
			}
			select {
			case err := <-done:
				if err != ctx.Err() {
					t.Fatalf("error: %v, want %v", err, ctx.Err())
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatal("cancellation did not interrupt query")
			}
			if time.Since(started) > 500*time.Millisecond {
				t.Fatal("slow cancellation")
			}
			if _, ok := <-entries; ok {
				t.Fatal("channel not closed")
			}
		})
	}
	// An unread results channel must not prevent cancellation.
	s := startDNSServer(t)
	s.service(t, 10)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Browse(ctx, testService, testDomain, make(chan *ServiceEntry), UnicastDNS(s.address)) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked result send")
	}
}

func TestDNSNegativeTTLAndIncompleteResponses(t *testing.T) {
	q := dns.Question{Name: testHost, Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
	now := time.Now()
	for _, rcode := range []int{dns.RcodeSuccess, dns.RcodeNameError} {
		m := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: rcode}, Ns: []dns.RR{rr(t, "example.test. 120 IN SOA ns.example.test. admin.example.test. 1 10 10 10 30")}}
		a, err := parseDNSAnswer(m, q, now)
		if err != nil || !a.negative || a.expiry.Sub(now) != 30*time.Second {
			t.Fatalf("negative answer: %+v %v", a, err)
		}
	}
	for _, m := range []*dns.Msg{{}, {MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}}, {MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}} {
		if _, err := parseDNSAnswer(m, q, now); err == nil {
			t.Fatalf("accepted incomplete response: %+v", m)
		}
	}
	m := &dns.Msg{Answer: []dns.RR{rr(t, testHost+" 0 IN A 192.0.2.1")}}
	q.Qtype = dns.TypeA
	a, err := parseDNSAnswer(m, q, now)
	if err != nil || a.negative || a.expiry != now {
		t.Fatalf("TTL zero: %+v %v", a, err)
	}
}

func TestUnicastOptionsValidateBeforeMulticast(t *testing.T) {
	for _, address := range []string{"224.0.0.251:5353", "[ff02::fb]:5353", "bad", "0.0.0.0"} {
		if err := Browse(context.Background(), testService, testDomain, make(chan *ServiceEntry), UnicastDNS(address)); err == nil {
			t.Fatalf("accepted %s", address)
		}
	}
	if err := Browse(context.Background(), testService, "", make(chan *ServiceEntry), UnicastDNS("127.0.0.1")); err == nil {
		t.Fatal("missing domain accepted")
	}
	if applyOpts().unicast {
		t.Fatal("default is not multicast")
	}
}

func TestUnicastTXTRecordBoundariesAndTTLZero(t *testing.T) {
	s := startDNSServer(t)
	s.service(t, 0)
	s.set(t, testInstance, dns.TypeTXT, testInstance+" 0 IN TXT \"region=west\" \"variant=a\"", testInstance+" 0 IN TXT \"region=east\" \"variant=b\"")
	entry := lookupTest(t, s)
	if entry.Removed || len(entry.TXTRecords) != 2 || !reflect.DeepEqual(entry.Text, []string{"region=east", "variant=b"}) {
		t.Fatalf("TXT variants: %+v", entry)
	}
}

func TestUnicastSRVUnavailableTarget(t *testing.T) {
	s := startDNSServer(t)
	s.service(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entries := make(chan *ServiceEntry, 4)
	done := make(chan error, 1)
	go func() {
		done <- Browse(ctx, testService, testDomain, entries, UnicastDNS(s.address), Unannouncements())
	}()
	nextEntry(t, entries)
	s.set(t, testInstance, dns.TypeSRV, testInstance+" 1 IN SRV 0 0 0 .")
	if entry := nextEntry(t, entries); !entry.Removed {
		t.Fatalf("unavailable target: %+v", entry)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestUnicastTimeoutRetainsExpiredRecords(t *testing.T) {
	s := startDNSServer(t)
	s.service(t, 1)
	c := &unicastClient{servers: func(string) []string { return []string{s.address} }, cache: map[dns.Question]*dnsAnswer{}, used: map[dns.Question]bool{}, cycle: time.Now()}
	initial := c.query(context.Background(), testHost, dns.TypeA)
	initial.expiry = time.Now().Add(-time.Second)
	initial.refresh = initial.expiry
	expiry := initial.expiry
	s.mu.Lock()
	s.silent = true
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	after := c.query(ctx, testHost, dns.TypeA)
	if after != initial || after.expiry != expiry || after.negative || len(after.records) != 1 {
		t.Fatalf("timeout discarded or renewed data: %+v", after)
	}
}

func TestUnicastRecordOrderDoesNotChangeResult(t *testing.T) {
	s := startDNSServer(t)
	s.service(t, 10)
	records := []string{testInstance + " 10 IN SRV 1 2 8080 b.example.test.", testInstance + " 10 IN SRV 1 3 8081 a.example.test."}
	s.set(t, testInstance, dns.TypeSRV, records...)
	for _, host := range []string{"a.example.test.", "b.example.test."} {
		s.set(t, host, dns.TypeA, host+" 10 IN A 192.0.2.2", host+" 10 IN A 192.0.2.1")
	}
	first := lookupTest(t, s)
	s.set(t, testInstance, dns.TypeSRV, records[1], records[0])
	for _, host := range []string{"a.example.test.", "b.example.test."} {
		s.set(t, host, dns.TypeA, host+" 10 IN A 192.0.2.1", host+" 10 IN A 192.0.2.2")
	}
	second := lookupTest(t, s)
	if !sameService(first, second) {
		t.Fatalf("record order changed result:\n%+v\n%+v", first, second)
	}
}

func TestUnicastResolverWithoutEDNS(t *testing.T) {
	s := startDNSServer(t)
	s.service(t, 10)
	s.mu.Lock()
	s.rejectEDNS = true
	s.mu.Unlock()
	if entry := lookupTest(t, s); entry.Port != 8080 {
		t.Fatal(entry)
	}
}
