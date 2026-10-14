package zeroconf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestTentativeRegistrationDoesNotAnswer(t *testing.T) {
	e := newServiceEntry("test", "_test._tcp", "local.")
	e.HostName = "test.local."
	e.Port = 8000
	s := &Server{service: e, ttl: 120}
	q := dns.Question{Name: e.ServiceInstanceName(), Qtype: dns.TypeANY, Qclass: dns.ClassINET}
	var reply dns.Msg
	if err := s.handleQuestion(q, &reply, &dns.Msg{}, 1); err != nil {
		t.Fatal(err)
	}
	if len(reply.Answer)+len(reply.Extra) != 0 {
		t.Fatal("tentative registration answered before establishing uniqueness")
	}
}

func protocolServer(t *testing.T) (*Server, *[]dns.Msg) {
	t.Helper()
	e := newServiceEntry("probe", "_test._tcp", "local.")
	e.HostName = "probe-host.local."
	e.Port = 8000
	e.Text = []string{"v=1"}
	e.AddrIPv4 = []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("192.0.2.11")}
	s := &Server{service: e, ttl: 120, ifaces: []net.Interface{{Index: 1}},
		ready: make(chan struct{}), done: make(chan struct{}), wake: make(chan struct{}, 1), shouldShutdown: make(chan struct{})}
	s.unicastProbes = true
	s.initProbes()
	packets := &[]dns.Msg{}
	s.send = func(m *dns.Msg, _ int) error { *packets = append(*packets, *m.Copy()); return nil }
	s.probes[1].next = time.Unix(1, 0)
	t.Cleanup(s.Shutdown)
	return s, packets
}

func establish(s *Server) {
	for n := 0; n < 4; n++ {
		s.stepProbes(time.Unix(1, 0).Add(time.Duration(n) * 250 * time.Millisecond))
	}
}

func response(rr dns.RR) *dns.Msg {
	return &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}, Answer: []dns.RR{rr}}
}

func conflicting(s *Server) dns.RR {
	rr := dns.Copy(s.proposedRecords(1)[0]).(*dns.SRV)
	rr.Port++
	return rr
}

func TestProbeStartupPacketsAndTiming(t *testing.T) {
	s, packets := protocolServer(t)
	start := time.Unix(1, 0)
	s.stepProbes(start.Add(-time.Nanosecond))
	if len(*packets) != 0 {
		t.Fatal("sent before random startup delay")
	}
	for n := 0; n < 3; n++ {
		now := start.Add(time.Duration(n) * 250 * time.Millisecond)
		s.stepProbes(now)
		if len(*packets) != n+1 {
			t.Fatal("incorrect probe count")
		}
		m := (*packets)[n]
		if m.Response || m.Id != 0 || m.RecursionDesired || len(m.Question) != 2 || len(m.Ns) != 4 {
			t.Fatalf("invalid probe: %v", m)
		}
		for _, q := range m.Question {
			if q.Qtype != dns.TypeANY || q.Qclass != dns.ClassINET|qClassCacheFlush {
				t.Fatal(q)
			}
		}
		for _, rr := range m.Ns {
			if rr.Header().Class != dns.ClassINET {
				t.Fatal("cache flush in probe")
			}
		}
		s.stepProbes(now.Add(249 * time.Millisecond))
		if len(*packets) != n+1 {
			t.Fatal("sent too early")
		}
	}
	s.stepProbes(start.Add(750 * time.Millisecond))
	if !s.probes[1].established || len(*packets) != 4 {
		t.Fatal("not established after three probes")
	}
	if err := s.WaitForReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	m := (*packets)[3]
	if !m.Response || !m.Authoritative {
		t.Fatal("announcement flags")
	}
	s.stepProbes(start.Add(1749 * time.Millisecond))
	if len(*packets) != 4 {
		t.Fatal("second announcement too early")
	}
	s.stepProbes(start.Add(1750 * time.Millisecond))
	if len(*packets) != 5 {
		t.Fatal("missing second announcement")
	}
	s.stepProbes(start.Add(time.Hour))
	if len(*packets) != 5 {
		t.Fatal("periodic unsolicited announcement")
	}
}

func TestProbeInitialConflictAndCooperation(t *testing.T) {
	for _, section := range []string{"answer", "authority", "additional"} {
		t.Run(section, func(t *testing.T) {
			s, _ := protocolServer(t)
			p := s.probes[1]
			m := response(conflicting(s))
			if section == "authority" {
				m.Ns, m.Answer = m.Answer, nil
			}
			if section == "additional" {
				m.Extra, m.Answer = m.Answer, nil
			}
			if err := s.observeResponse(m, 1, p, time.Unix(1, 0)); err != nil {
				t.Fatal("conflict before first probe")
			}
			s.stepProbes(time.Unix(1, 0))
			if err := s.observeResponse(response(dns.Copy(s.proposedRecords(1)[0])), 1, p, time.Unix(1, 0)); err != nil {
				t.Fatal("identical record treated as conflict")
			}
			err := s.observeResponse(m, 1, p, time.Unix(1, 0))
			var collision *ConflictError
			if !errors.As(err, &collision) || collision.InterfaceIndex != 1 {
				t.Fatalf("missing conflict: %v", err)
			}
			if !errors.As(s.WaitForReady(context.Background()), &collision) {
				t.Fatal("readiness did not report conflict")
			}
			<-s.Done()
			if s.Err() != err {
				t.Fatal("terminal error not retained")
			}
		})
	}
}

func TestSimultaneousProbes(t *testing.T) {
	for _, test := range []struct {
		name  string
		delta int
		lose  bool
	}{{"winning", -1, false}, {"losing", 1, true}, {"equal", 0, false}} {
		t.Run(test.name, func(t *testing.T) {
			s, _ := protocolServer(t)
			s.stepProbes(time.Unix(1, 0))
			msg := s.probeMessage(1).Copy()
			for _, rr := range msg.Ns {
				if a, ok := rr.(*dns.A); ok {
					a.A = append(net.IP(nil), a.A...)
					a.A[len(a.A)-1] = byte(int(a.A[len(a.A)-1]) + test.delta)
				}
			}
			s.observeProbe(msg, 1, s.probes[1], time.Unix(2, 0))
			if (s.probes[1].sent == 0) != test.lose {
				t.Fatal("incorrect tiebreak result")
			}
			if test.lose && !s.probes[1].next.Equal(time.Unix(3, 0)) {
				t.Fatal("loser must wait one second")
			}
		})
	}
}

func TestProbeRecordSetOrderingAndDeduplication(t *testing.T) {
	s, _ := protocolServer(t)
	records := s.proposedRecords(1)
	a, err := recordSet(records, s.service.ServiceInstanceName())
	if err != nil {
		t.Fatal(err)
	}
	reversed := []dns.RR{dns.Copy(records[1]), dns.Copy(records[0]), dns.Copy(records[0])}
	for _, rr := range reversed {
		rr.Header().Name = strings.ToUpper(rr.Header().Name)
		rr.Header().Class |= qClassCacheFlush
	}
	b, err := recordSet(reversed, s.service.ServiceInstanceName())
	if err != nil {
		t.Fatal(err)
	}
	if compareRecordSets(a, b) != 0 {
		t.Fatal("order, case or duplicates changed RRset")
	}
	if binary.BigEndian.Uint16(a[0][2:4]) != dns.TypeTXT {
		t.Fatal("type ordering must put TXT before SRV")
	}
	if compareRecordSets(a, a[:1]) <= 0 {
		t.Fatal("longer equal prefix should win")
	}
	srv := records[0].(*dns.SRV)
	key, err := rrKey(srv)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(key[10:], []byte{0xc0}) {
		t.Fatal("compressed domain name in RDATA")
	}
}

func TestEstablishedConflictReprobesBeforeFailing(t *testing.T) {
	s, packets := protocolServer(t)
	establish(s)
	before := len(*packets)
	msg := response(conflicting(s))
	if err := s.observeResponse(msg, 1, s.probes[1], time.Unix(3, 0)); err != nil {
		t.Fatal(err)
	}
	if s.probes[1].established || s.isShutdown {
		t.Fatal("must return to probing before deciding conflict")
	}
	s.stepProbes(time.Unix(3, 0))
	if len(*packets) != before+1 || (*packets)[before].Response {
		t.Fatal("missing reprobe")
	}
	if err := s.observeResponse(msg, 1, s.probes[1], time.Unix(3, 0)); err == nil {
		t.Fatal("reprobe conflict did not terminate")
	}
	<-s.Done()
	if err := s.WaitForReady(context.Background()); err != nil {
		t.Fatal("initial success should remain stable")
	}
	if s.Err() == nil {
		t.Fatal("later failure unavailable")
	}
}

func TestEstablishedReprobeCanRecover(t *testing.T) {
	s, _ := protocolServer(t)
	establish(s)
	s.observeResponse(response(conflicting(s)), 1, s.probes[1], time.Unix(3, 0))
	for n := 0; n < 4; n++ {
		s.stepProbes(time.Unix(3, 0).Add(time.Duration(n) * 250 * time.Millisecond))
	}
	if !s.probes[1].established || s.Err() != nil {
		t.Fatal("reprobe did not recover")
	}
}

func TestCooperatingGoodbyeRefresh(t *testing.T) {
	for _, kind := range []uint16{dns.TypeA, dns.TypePTR, dns.TypeSRV} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			s, packets := protocolServer(t)
			establish(s)
			var msg dns.Msg
			s.composeLookupAnswers(&msg, 120, 1, true)
			var rr dns.RR
			for _, r := range msg.Answer {
				if r.Header().Rrtype == kind {
					rr = dns.Copy(r)
					break
				}
			}
			rr.Header().Ttl = 0
			before := len(*packets)
			if err := s.observeResponse(response(rr), 1, s.probes[1], time.Unix(3, 0)); err != nil {
				t.Fatal(err)
			}
			if len(*packets) != before+1 || !s.probes[1].established {
				t.Fatal("matching goodbye did not refresh")
			}
			rr.Header().Name = "irrelevant.local."
			s.observeResponse(response(rr), 1, s.probes[1], time.Unix(3, 0))
			if len(*packets) != before+1 {
				t.Fatal("irrelevant goodbye refreshed")
			}
		})
	}
}

func TestProbeConflictRateLimit(t *testing.T) {
	p := &interfaceProbe{}
	now := time.Unix(1, 0)
	for n := 0; n < 15; n++ {
		p.restart(now, time.Second)
	}
	if p.next.Sub(now) != 5*time.Second {
		t.Fatal("15 conflicts must enforce five second delay")
	}
	p.restart(now.Add(11*time.Second), time.Second)
	if len(p.conflicts) != 1 || p.next.Sub(now.Add(11*time.Second)) != time.Second {
		t.Fatal("conflict history did not expire")
	}
}

func TestPerInterfaceProbeAndAddresses(t *testing.T) {
	s, _ := protocolServer(t)
	s.probes[2] = &interfaceProbe{next: time.Unix(2, 0)}
	s.interfaceAddrs = map[int][]net.IP{1: {net.ParseIP("192.0.2.1")}, 2: {net.ParseIP("192.0.2.2")}}
	establish(s)
	select {
	case <-s.ready:
		t.Fatal("ready before every interface established")
	default:
	}
	if _, p := s.probeForInterface(0); p != nil {
		t.Fatal("ambiguous interface accepted")
	}
	for index, want := range map[int]string{1: "192.0.2.1", 2: "192.0.2.2"} {
		for _, rr := range s.proposedRecords(index) {
			if a, ok := rr.(*dns.A); ok && a.A.String() != want {
				t.Fatal("address crossed interfaces")
			}
		}
	}

}

func TestCancellationAndStartupShutdown(t *testing.T) {
	s, packets := protocolServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.WaitForReady(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if s.isShutdown {
		t.Fatal("wait cancellation stopped registration")
	}
	s.Shutdown()
	if len(*packets) != 0 {
		t.Fatal("tentative shutdown advertised goodbye")
	}
	if !errors.Is(s.WaitForReady(context.Background()), ErrServerClosed) {
		t.Fatal("missing startup cancellation result")
	}
	if s.Err() != nil {
		t.Fatal("normal shutdown reported failure")
	}
}

func TestProbeSendFailureIsReported(t *testing.T) {
	s, _ := protocolServer(t)
	failure := errors.New("send failed")
	s.send = func(*dns.Msg, int) error { return failure }
	s.stepProbes(time.Unix(1, 0))
	if !errors.Is(s.WaitForReady(context.Background()), failure) {
		t.Fatal("send failure not reported")
	}
	<-s.Done()
}

func TestMalformedAndIrrelevantPackets(t *testing.T) {
	s, _ := protocolServer(t)
	if err := s.parsePacket([]byte{0xff}, 1, &net.UDPAddr{}); err == nil {
		t.Fatal("malformed packet accepted")
	}
	for _, m := range []*dns.Msg{{MsgHdr: dns.MsgHdr{Opcode: dns.OpcodeUpdate}}, {MsgHdr: dns.MsgHdr{Response: true, Truncated: true}}, response(conflicting(s))} {
		s.handleQuery(m, 99, &net.UDPAddr{})
	}
	if s.isShutdown || s.probes[1].sent != 0 {
		t.Fatal("irrelevant packet affected startup")
	}
}

func TestProbeRequestsMulticastWhenPortIsShared(t *testing.T) {
	s, _ := protocolServer(t)
	s.unicastProbes = false
	for _, q := range s.probeMessage(1).Question {
		if q.Qclass != dns.ClassINET {
			t.Fatal("shared host requested unicast probe defence")
		}
	}
}

func TestEstablishedAnswersAndTextUpdate(t *testing.T) {
	s, packets := protocolServer(t)
	establish(s)
	q := dns.Question{Name: strings.ToUpper(s.service.HostName), Qtype: dns.TypeA, Qclass: dns.ClassINET}
	var reply dns.Msg
	if err := s.handleQuestion(q, &reply, &dns.Msg{}, 1); err != nil {
		t.Fatal(err)
	}
	addresses := 0
	for _, rr := range reply.Answer {
		if rr.Header().Rrtype == dns.TypeA {
			addresses++
		}
	}
	if addresses != 2 {
		t.Fatal("established address response missing")
	}
	before := len(*packets)
	s.SetText([]string{"v=2"})
	if len(*packets) != before+1 {
		t.Fatal("text update not announced")
	}
	s.observeResponse(response(conflicting(s)), 1, s.probes[1], time.Unix(3, 0))
	before = len(*packets)
	s.SetText([]string{"v=3"})
	if len(*packets) != before {
		t.Fatal("text update announced tentative records")
	}
}

func TestConcurrentLifecycleMethods(t *testing.T) {
	s, _ := protocolServer(t)
	establish(s)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			if n%3 == 0 {
				s.SetText([]string{"v=2"})
			} else if n%3 == 1 {
				s.Shutdown()
			} else {
				s.WaitForReady(context.Background())
				s.Err()
			}
		}(i)
	}
	wg.Wait()
	<-s.Done()
}

func TestSimultaneousProbeIgnoresAuthorityOutsideQuestionClass(t *testing.T) {
	s, _ := protocolServer(t)
	s.stepProbes(time.Unix(1, 0))
	peer := s.probeMessage(1).Copy()
	for _, rr := range peer.Ns {
		rr.Header().Class = dns.ClassCHAOS
	}
	s.observeProbe(peer, 1, s.probes[1], time.Unix(2, 0))
	if s.probes[1].sent != 1 {
		t.Fatal("authority records outside the question class changed probe state")
	}
}

func TestSimultaneousProbeHandlesSpecificRecordQuestion(t *testing.T) {
	s, _ := protocolServer(t)
	s.stepProbes(time.Unix(1, 0))
	peer := s.probeMessage(1).Copy()
	peer.Question = []dns.Question{{Name: s.service.ServiceInstanceName(), Qtype: dns.TypeSRV, Qclass: dns.ClassINET}}
	for _, rr := range peer.Ns {
		if srv, ok := rr.(*dns.SRV); ok {
			srv.Port++
		}
	}
	s.observeProbe(peer, 1, s.probes[1], time.Unix(2, 0))
	if s.probes[1].sent != 0 || !s.probes[1].next.Equal(time.Unix(3, 0)) {
		t.Fatal("valid SRV probe did not trigger one-second tiebreak retry")
	}
}

func TestProbeIgnoresResponseFromNonMDNSSourcePort(t *testing.T) {
	s, _ := protocolServer(t)
	s.stepProbes(time.Unix(1, 0))
	wire, err := response(conflicting(s)).Pack()
	if err != nil {
		t.Fatal(err)
	}
	from := &net.UDPAddr{IP: net.ParseIP("192.0.2.99"), Port: mdnsWildcardAddrIPv4.Port + 1}
	if err := s.parsePacket(wire, 1, from); err != nil {
		t.Fatal(err)
	}
	if s.isShutdown {
		t.Fatal("response from an unrelated source port terminated registration")
	}
	from.Port = mdnsWildcardAddrIPv4.Port
	var conflict *ConflictError
	if err := s.parsePacket(wire, 1, from); !errors.As(err, &conflict) {
		t.Fatalf("valid mDNS conflict was not reported: %v", err)
	}
}

func TestInitialConflictWithdrawsAlreadyEstablishedOtherLink(t *testing.T) {
	s, _ := protocolServer(t)
	s.ifaces = append(s.ifaces, net.Interface{Index: 2})
	s.probes[2] = &interfaceProbe{sent: 1, next: time.Unix(4, 0)}
	establish(s)
	var withdrawn []int
	s.send = func(msg *dns.Msg, index int) error {
		if msg.Response && len(msg.Answer) > 0 && msg.Answer[0].Header().Ttl == 0 {
			withdrawn = append(withdrawn, index)
		}
		return nil
	}
	err := s.observeResponse(response(conflicting(s)), 2, s.probes[2], time.Unix(3, 0))
	if err == nil {
		t.Fatal("missing initial conflict on second link")
	}
	<-s.Done()
	if len(withdrawn) != 1 || withdrawn[0] != 1 {
		t.Fatalf("withdrawn links = %v, want established link 1 only", withdrawn)
	}
}

func TestShutdownDuringTiebreakRetry(t *testing.T) {
	s, packets := protocolServer(t)
	s.stepProbes(time.Unix(1, 0))
	s.probes[1].restart(time.Unix(2, 0), time.Second)
	count := len(*packets)
	s.Shutdown()
	s.stepProbes(time.Unix(3, 0))
	if len(*packets) != count {
		t.Fatal("canceled retry sent more packets")
	}
	if !errors.Is(s.WaitForReady(context.Background()), ErrServerClosed) {
		t.Fatal("canceled retry did not release initial readiness wait")
	}
}

func TestTextUpdatePreservesConflictRetryDelay(t *testing.T) {
	for _, conflicts := range []int{1, 15} {
		t.Run(fmt.Sprintf("conflicts-%d", conflicts), func(t *testing.T) {
			s, packets := protocolServer(t)
			p := s.probes[1]
			now := time.Now().Add(time.Minute)
			for n := 0; n < conflicts; n++ {
				p.restart(now, time.Second)
			}
			retry := p.next
			s.SetText([]string{"v=2"})
			if !p.next.Equal(retry) {
				t.Fatalf("TXT update shortened conflict retry: got %v, want %v", p.next, retry)
			}
			s.stepProbes(retry.Add(-time.Nanosecond))
			if len(*packets) != 0 {
				t.Fatal("TXT update sent a probe before the conflict delay expired")
			}
			s.stepProbes(retry)
			if len(*packets) != 1 {
				t.Fatal("retry did not resume at its scheduled time")
			}
		})
	}
}

func TestSharedPortProbeWaitsForDelayedDefence(t *testing.T) {
	s, packets := protocolServer(t)
	s.unicastProbes = false
	start := time.Unix(1, 0)
	for n := 0; n < 5; n++ {
		s.stepProbes(start.Add(time.Duration(n) * 250 * time.Millisecond))
		if s.probes[1].established || (*packets)[n].Response {
			t.Fatal("shared-port registration announced before delayed defence window")
		}
	}
	err := s.observeResponse(response(conflicting(s)), 1, s.probes[1], start.Add(1001*time.Millisecond))
	if err == nil {
		t.Fatal("delayed native defence did not prevent false readiness")
	}
	if s.WaitForReady(context.Background()) == nil {
		t.Fatal("delayed conflict reported successful readiness")
	}
}

func TestSharedPortProbeCompletesWithoutDefence(t *testing.T) {
	s, packets := protocolServer(t)
	s.unicastProbes = false
	start := time.Unix(1, 0)
	for n := 0; n < 5; n++ {
		s.stepProbes(start.Add(time.Duration(n) * 250 * time.Millisecond))
	}
	s.stepProbes(start.Add(1249 * time.Millisecond))
	if len(*packets) != 5 || s.probes[1].established {
		t.Fatal("shared-port registration ended probing too early")
	}
	s.stepProbes(start.Add(1250 * time.Millisecond))
	if len(*packets) != 6 || !(*packets)[5].Response {
		t.Fatal("shared-port registration did not announce after extended probing")
	}
	if err := s.WaitForReady(context.Background()); err != nil {
		t.Fatal(err)
	}
}
