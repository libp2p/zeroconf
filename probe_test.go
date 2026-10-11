package zeroconf

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func testProbeServer(instance, host string, port int) *Server {
	entry := newServiceEntry(instance, mdnsService, mdnsDomain)
	entry.HostName = host
	entry.Port = port
	entry.Text = []string{"txtv=0"}

	s := &Server{
		service:     entry,
		ttl:         defaultTTL,
		probeResult: make(chan probeResult, 1),
	}
	s.probeState.Store(s.newProbeState())
	return s
}

func probeMessage(t *testing.T, s *Server) *dns.Msg {
	t.Helper()

	q := new(dns.Msg)
	q.SetQuestion(s.service.ServiceInstanceName(), dns.TypeANY)
	q.Ns = s.newProbeState().records
	return roundTrip(t, q)
}

func responseMessage(t *testing.T, s *Server) *dns.Msg {
	t.Helper()

	resp := new(dns.Msg)
	resp.Response = true
	s.composeLookupAnswers(resp, s.ttl, 0, true)
	return roundTrip(t, resp)
}

// roundTrip packs and unpacks msg like a message received from the network.
func roundTrip(t *testing.T, msg *dns.Msg) *dns.Msg {
	t.Helper()

	buf, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	var res dns.Msg
	if err := res.Unpack(buf); err != nil {
		t.Fatal(err)
	}
	return &res
}

func probeOutcome(s *Server, msg *dns.Msg) (probeResult, bool) {
	s.handleProbeMessage(msg)
	select {
	case res := <-s.probeResult:
		return res, true
	default:
		return 0, false
	}
}

func TestProbeConflict(t *testing.T) {
	const name = "test service (1)" // needs escaping in presentation format

	own := testProbeServer(name, "own.local.", mdnsPort)

	for _, tc := range []struct {
		desc string
		msg  *dns.Msg
		want probeResult
		ok   bool
	}{
		{"response for other name", responseMessage(t, testProbeServer("other", "other.local.", mdnsPort)), 0, false},
		{"response with own records", responseMessage(t, testProbeServer(name, "own.local.", mdnsPort)), probeConflict, true},
		{"response from other host", responseMessage(t, testProbeServer(name, "other.local.", mdnsPort)), probeConflict, true},
		{"own probe", probeMessage(t, own), 0, false},
		{"probe with earlier data", probeMessage(t, testProbeServer(name, "own.local.", mdnsPort-1)), 0, false},
		{"probe with later data", probeMessage(t, testProbeServer(name, "own.local.", mdnsPort+1)), probeLost, true},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			res, ok := probeOutcome(own, tc.msg)
			if ok != tc.ok || res != tc.want {
				t.Fatalf("expected %v/%v, got %v/%v", tc.want, tc.ok, res, ok)
			}
		})
	}
}

func TestCompareRecords(t *testing.T) {
	a := testProbeServer(mdnsName, "a.local.", mdnsPort).newProbeState().records
	b := testProbeServer(mdnsName, "b.local.", mdnsPort).newProbeState().records

	if c := compareRecords(a, a); c != 0 {
		t.Fatalf("expected identical records to compare equal, got %d", c)
	}
	if c := compareRecords(a, b); c >= 0 {
		t.Fatalf("expected a < b, got %d", c)
	}
	if c := compareRecords(b, a); c <= 0 {
		t.Fatalf("expected b > a, got %d", c)
	}
	// TXT sorts before SRV
	if c := compareRecords([]dns.RR{a[1]}, a); c >= 0 {
		t.Fatalf("expected subset to compare earlier, got %d", c)
	}
}

func TestNameConflict(t *testing.T) {
	for _, tc := range []struct {
		desc  string
		delay time.Duration
	}{
		{"sequential", 2 * time.Second}, // first server already claimed the name
		{"simultaneous", 0},             // both servers probe at the same time
	} {
		t.Run(tc.desc, func(t *testing.T) {
			first, err := RegisterProxy(mdnsName, mdnsService, mdnsDomain, mdnsPort, "first", []string{"192.0.2.1"}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(first.Shutdown)

			time.Sleep(tc.delay)

			second, err := RegisterProxy(mdnsName, mdnsService, mdnsDomain, mdnsPort, "second", []string{"192.0.2.2"}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(second.Shutdown)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			entries := make(chan *ServiceEntry, 100)
			if err := Browse(ctx, mdnsService, mdnsDomain, entries); err != nil {
				t.Fatalf("Expected browse success, but got %v", err)
			}

			hosts := make(map[string]string)
			for e := range entries {
				hosts[e.Instance] = e.HostName
			}

			// browse results contain instance names in escaped presentation format
			renamed := mdnsName + `\ \(2\)`
			if len(hosts) != 2 || hosts[mdnsName] == "" || hosts[renamed] == "" || hosts[mdnsName] == hosts[renamed] {
				t.Fatalf("expected instances %s and %s on different hosts, got %v", mdnsName, renamed, hosts)
			}
			if tc.delay > 0 && hosts[mdnsName] != "first.local." {
				t.Fatalf("expected first server to keep %s, got %v", mdnsName, hosts)
			}
		})
	}
}
