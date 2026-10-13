package zeroconf

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func hostnameServer(t *testing.T, ips ...string) (*Server, *[]dns.Msg) {
	t.Helper()
	s, packets := protocolServer(t)
	host, err := newHostnameRegistration("hostname-test.local", ips)
	if err != nil {
		t.Fatal(err)
	}
	s.hostname, s.service = host, nil
	return s, packets
}

func assertHostnameRecords(t *testing.T, msg *dns.Msg, host string, ttl uint32) {
	t.Helper()
	for _, rr := range append(append(append([]dns.RR{}, msg.Answer...), msg.Ns...), msg.Extra...) {
		if rr.Header().Name != host {
			t.Fatalf("unexpected record owner: %s", rr)
		}
		switch rr.Header().Rrtype {
		case dns.TypeA, dns.TypeAAAA, dns.TypeNSEC:
		default:
			t.Fatalf("fabricated service record: %s", rr)
		}
		if rr.Header().Ttl != ttl {
			t.Fatalf("unexpected TTL: %s", rr)
		}
	}
}

func TestHostnameValidation(t *testing.T) {
	for _, host := range []string{"", "local", ".", "bad..local", "host.local.."} {
		if _, err := RegisterHostname(host, []string{"192.0.2.1"}, nil); err == nil {
			t.Fatalf("accepted invalid hostname %q", host)
		}
	}
	if _, err := RegisterHostname("valid.local", []string{"not-an-IP"}, nil); err == nil {
		t.Fatal("accepted invalid IP")
	}
	for _, host := range []string{"host.local", "host.local.", "HOST.example.com."} {
		h, err := newHostnameRegistration(host, []string{"192.0.2.1"})
		if err != nil || h.name != dns.Fqdn(host) {
			t.Fatalf("hostname normalization: %v %v", h, err)
		}
	}
}

func TestHostnamePacketsAndFamilies(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ips   []string
		types []uint16
	}{
		{"IPv4", []string{"192.0.2.1"}, []uint16{dns.TypeA, dns.TypeNSEC}},
		{"IPv6", []string{"2001:db8::1"}, []uint16{dns.TypeAAAA, dns.TypeNSEC}},
		{"dual", []string{"192.0.2.1", "2001:db8::1"}, []uint16{dns.TypeA, dns.TypeAAAA}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, packets := hostnameServer(t, tc.ips...)
			probe := s.probeMessage(1)
			if len(probe.Question) != 1 || probe.Question[0].Name != s.hostname.name || probe.Question[0].Qtype != dns.TypeANY {
				t.Fatalf("incorrect hostname probe: %v", probe)
			}
			assertHostnameRecords(t, probe, s.hostname.name, 120)
			for _, rr := range probe.Ns {
				if rr.Header().Rrtype == dns.TypeNSEC {
					t.Fatal("derived NSEC included in probe proposal")
				}
			}
			establish(s)
			if err := s.WaitForReady(context.Background()); err != nil {
				t.Fatal(err)
			}
			announcement := &(*packets)[len(*packets)-1]
			assertHostnameRecords(t, announcement, s.hostname.name, 120)
			if len(announcement.Answer) != len(tc.types) {
				t.Fatalf("unexpected family records: %v", announcement)
			}
			for i, rr := range announcement.Answer {
				if rr.Header().Rrtype != tc.types[i] {
					t.Fatalf("unexpected family: %s", rr)
				}
			}
			count := len(*packets)
			s.SetText([]string{"ignored=1"})
			if len(*packets) != count {
				t.Fatal("hostname-only SetText sent a packet")
			}
			s.Shutdown()
			if len(*packets) != count+1 {
				t.Fatal("missing address withdrawal")
			}
			assertHostnameRecords(t, &(*packets)[count], s.hostname.name, 0)
		})
	}
}

func TestHostnameQuestionsAndTentativeState(t *testing.T) {
	s, _ := hostnameServer(t, "192.0.2.1")
	q := dns.Question{Name: "HOSTNAME-TEST.LOCAL", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	var msg dns.Msg
	s.handleQuestion(q, &msg, &dns.Msg{}, 1)
	if len(msg.Answer) != 0 {
		t.Fatal("tentative hostname answered")
	}
	establish(s)
	for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeANY} {
		q.Qtype = typ
		msg = dns.Msg{}
		s.handleQuestion(q, &msg, &dns.Msg{}, 1)
		assertHostnameRecords(t, &msg, s.hostname.name, 120)
		if len(msg.Answer) == 0 {
			t.Fatal("missing answer or NSEC")
		}
		if typ == dns.TypeAAAA {
			if len(msg.Answer) != 1 || msg.Answer[0].Header().Rrtype != dns.TypeNSEC {
				t.Fatal("absent IPv6 family did not return NSEC")
			}
		}
	}
	q.Name = "_services._dns-sd._udp.local."
	msg = dns.Msg{}
	s.handleQuestion(q, &msg, &dns.Msg{}, 1)
	if len(msg.Answer)+len(msg.Extra) != 0 {
		t.Fatal("hostname registration fabricated service enumeration")
	}
}

func TestHostnameSelectedInterfaceRecords(t *testing.T) {
	s, _ := hostnameServer(t, "192.0.2.1")
	s.interfaceAddrs = map[int][]net.IP{1: {net.ParseIP("192.0.2.11")}, 2: {net.ParseIP("2001:db8::22")}}
	for _, index := range []int{1, 2} {
		rrs := s.proposedRecords(index)
		if len(rrs) != 1 {
			t.Fatalf("mixed interface addresses: %v", rrs)
		}
		if index == 1 && rrs[0].(*dns.A).A.String() != "192.0.2.11" {
			t.Fatal("incorrect IPv4 interface address")
		}
		if index == 2 && rrs[0].(*dns.AAAA).AAAA.String() != "2001:db8::22" {
			t.Fatal("incorrect IPv6 interface address")
		}
	}
}

func TestHostnameConflictAndCancellation(t *testing.T) {
	s, _ := hostnameServer(t, "192.0.2.1")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.WaitForReady(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("wait cancellation: %v", err)
	}
	s.stepProbes(time.Unix(1, 0))
	rr := dns.Copy(s.proposedRecords(1)[0]).(*dns.A)
	rr.A = net.ParseIP("192.0.2.99")
	if err := s.observeResponse(response(rr), 1, s.probes[1], time.Unix(1, 0)); err == nil {
		t.Fatal("hostname collision accepted")
	} else {
		s.mu.Lock()
		s.stopLocked(err)
		s.mu.Unlock()
	}
	var conflict *ConflictError
	if err := s.WaitForReady(context.Background()); !errors.As(err, &conflict) || conflict.Name != s.hostname.name {
		t.Fatalf("hostname readiness conflict: %v", err)
	}
	<-s.Done()
	if !errors.As(s.Err(), &conflict) {
		t.Fatal("terminal conflict unavailable")
	}
}

func TestHostnameAPIRegistration(t *testing.T) {
	ifaces := testMulticastIfaces(t)
	s, err := RegisterHostname("standalone-api-test.local", []string{"192.0.2.1"}, ifaces)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Shutdown)
	if s.service != nil {
		t.Fatal("standalone registration fabricated service data")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.WaitForReady(ctx); err != nil {
		t.Fatal(err)
	}
	s.Shutdown()
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestHostnameAutomaticAddressSelection(t *testing.T) {
	ifaces := testMulticastIfaces(t)
	v4, v6, perInterface := addressesForInterfaces(ifaces)
	if len(v4)+len(v6) == 0 {
		t.Skip("selected test interface has no publishable addresses")
	}
	s, err := RegisterHostname("automatic-hostname-test.local", nil, ifaces)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Shutdown)
	if len(s.hostname.v4) != len(v4) || len(s.hostname.v6) != len(v6) {
		t.Fatal("automatic registration selected different address families")
	}
	for _, iface := range ifaces {
		records := s.proposedRecords(iface.Index)
		if len(records) != len(perInterface[iface.Index]) {
			t.Fatal("automatic registration mixed interface addresses")
		}
	}
	s.Shutdown()
	if err := s.Err(); err != nil {
		t.Fatalf("automatic registration shutdown: %v", err)
	}
}

func TestHostnameShutdownBeforeReady(t *testing.T) {
	s, packets := hostnameServer(t, "192.0.2.1")
	s.Shutdown()
	if err := s.WaitForReady(context.Background()); !errors.Is(err, ErrServerClosed) {
		t.Fatalf("shutdown during startup: %v", err)
	}
	if len(*packets) != 0 {
		t.Fatal("tentative shutdown sent an address announcement or goodbye")
	}
}

func TestHostnameSimultaneousProbes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		local  string
		remote string
		loses  bool
	}{
		{"losing", "192.0.2.1", "192.0.2.99", true},
		{"winning", "192.0.2.99", "192.0.2.1", false},
		{"equal", "192.0.2.1", "192.0.2.1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := hostnameServer(t, tc.local)
			now := time.Unix(1, 0)
			s.stepProbes(now)
			msg := s.probeMessage(1).Copy()
			msg.Ns[0].(*dns.A).A = net.ParseIP(tc.remote)
			s.observeProbe(msg, 1, s.probes[1], now)
			p := s.probes[1]
			if tc.loses {
				if p.sent != 0 || !p.next.Equal(now.Add(time.Second)) {
					t.Fatal("losing hostname proposal did not use the shared retry lifecycle")
				}
			} else if p.sent != 1 {
				t.Fatal("winning or identical proposal restarted probing")
			}
		})
	}
}

func TestHostnameEstablishedConflict(t *testing.T) {
	s, _ := hostnameServer(t, "192.0.2.1")
	establish(s)
	rr := dns.Copy(s.proposedRecords(1)[0]).(*dns.A)
	rr.A = net.ParseIP("192.0.2.99")
	now := time.Unix(3, 0)
	if err := s.observeResponse(response(rr), 1, s.probes[1], now); err != nil {
		t.Fatalf("established conflict skipped reprobe: %v", err)
	}
	if s.probes[1].established {
		t.Fatal("conflicting hostname remained established")
	}
	s.stepProbes(now)
	if err := s.observeResponse(response(rr), 1, s.probes[1], now); err == nil {
		t.Fatal("conflicting response during reprobe did not stop registration")
	}
	<-s.Done()
	var conflict *ConflictError
	if !errors.As(s.Err(), &conflict) || conflict.InterfaceIndex != 1 {
		t.Fatal("terminal hostname conflict lost interface identity")
	}
	if err := s.WaitForReady(context.Background()); err != nil {
		t.Fatal("later conflict changed the persistent initial success result")
	}
}

func TestHostnameCooperatingGoodbyeRefresh(t *testing.T) {
	s, packets := hostnameServer(t, "192.0.2.1")
	establish(s)
	rr := dns.Copy(s.proposedRecords(1)[0])
	count := len(*packets)
	if err := s.observeResponse(response(rr), 1, s.probes[1], time.Unix(3, 0)); err != nil {
		t.Fatal(err)
	}
	if !s.probes[1].established || len(*packets) != count {
		t.Fatal("identical cooperating hostname disturbed registration")
	}
	rr.Header().Ttl = 0
	if err := s.observeResponse(response(rr), 1, s.probes[1], time.Unix(3, 0)); err != nil {
		t.Fatal(err)
	}
	if len(*packets) != count+1 || !s.probes[1].established {
		t.Fatal("cooperating goodbye did not refresh the remaining hostname registration")
	}
	assertHostnameRecords(t, &(*packets)[count], s.hostname.name, 120)
}

func TestCombinedServicesKeepTargetAddresses(t *testing.T) {
	first, packets := protocolServer(t)
	second, secondPackets := protocolServer(t)
	second.service.Instance = "second"
	second.service.serviceInstanceName = "second._test._tcp.local."
	for _, s := range []*Server{first, second} {
		establish(s)
		var msg dns.Msg
		s.composeLookupAnswers(&msg, s.ttl, 1, true)
		counts := map[uint16]int{}
		for _, rr := range msg.Answer {
			counts[rr.Header().Rrtype]++
			if a, ok := rr.(*dns.A); ok && a.Hdr.Name != s.service.HostName {
				t.Fatal("service registration lost hostname address owner")
			}
		}
		if counts[dns.TypeSRV] != 1 || counts[dns.TypeTXT] != 1 || counts[dns.TypePTR] != 2 || counts[dns.TypeA] != 2 {
			t.Fatalf("combined service publication changed: %v", counts)
		}
	}
	before := len(*packets)
	beforeSecond := len(*secondPackets)
	first.Shutdown()
	withdrawal := &(*packets)[before]
	addressGoodbye := false
	for _, rr := range withdrawal.Answer {
		if rr.Header().Rrtype == dns.TypeA && rr.Header().Ttl == 0 {
			addressGoodbye = true
			if err := second.observeResponse(response(rr), 1, second.probes[1], time.Unix(3, 0)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !addressGoodbye || !second.probes[1].established || len(*secondPackets) != beforeSecond+2 {
		t.Fatal("independent service withdrawal behavior changed")
	}
}
