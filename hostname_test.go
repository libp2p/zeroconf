package zeroconf

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func newHostnameTestServer(ips ...string) *Server {
	entry := newServiceEntry("proxy", "_test--xxxx._tcp", "local")
	entry.HostName = "proxyhost.local."
	entry.Port = 8888
	for _, ip := range ips {
		addr := net.ParseIP(ip)
		if v4 := addr.To4(); v4 != nil {
			entry.AddrIPv4 = append(entry.AddrIPv4, addr)
		} else {
			entry.AddrIPv6 = append(entry.AddrIPv6, addr)
		}
	}
	return &Server{service: entry, ttl: defaultTTL}
}

func askHostname(t *testing.T, s *Server, name string, qtype uint16) []dns.RR {
	t.Helper()
	query := new(dns.Msg)
	query.SetQuestion(name, qtype)
	resp := dns.Msg{}
	if err := s.handleQuestion(query.Question[0], &resp, query, 0); err != nil {
		t.Fatalf("handleQuestion: %v", err)
	}
	return resp.Answer
}

func TestHostnameAQueryIsAnswered(t *testing.T) {
	s := newHostnameTestServer("192.168.1.10", "fd00::10")

	answer := askHostname(t, s, "proxyhost.local.", dns.TypeA)

	if len(answer) != 1 {
		t.Fatalf("expected 1 answer, got %d: %v", len(answer), answer)
	}
	a, ok := answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected an A record, got %T", answer[0])
	}
	if a.Hdr.Name != "proxyhost.local." || !a.A.Equal(net.ParseIP("192.168.1.10")) {
		t.Fatalf("unexpected A record: %v", a)
	}
	if a.Hdr.Ttl != 120 {
		t.Fatalf("expected the RFC 6762 host TTL of 120, got %d", a.Hdr.Ttl)
	}
}

func TestHostnameAAAAQueryGetsOnlyIPv6(t *testing.T) {
	s := newHostnameTestServer("192.168.1.10", "fd00::10")

	answer := askHostname(t, s, "proxyhost.local.", dns.TypeAAAA)

	if len(answer) != 1 {
		t.Fatalf("expected 1 answer, got %d: %v", len(answer), answer)
	}
	aaaa, ok := answer[0].(*dns.AAAA)
	if !ok || !aaaa.AAAA.Equal(net.ParseIP("fd00::10")) {
		t.Fatalf("expected AAAA fd00::10, got %v", answer[0])
	}
}

func TestHostnameANYQueryGetsBothFamilies(t *testing.T) {
	s := newHostnameTestServer("192.168.1.10", "fd00::10")

	answer := askHostname(t, s, "proxyhost.local.", dns.TypeANY)

	if len(answer) != 2 {
		t.Fatalf("expected an A and an AAAA answer, got %d: %v", len(answer), answer)
	}
}

func TestHostnameAQueryWithoutIPv4IsNotAnswered(t *testing.T) {
	s := newHostnameTestServer("fd00::10")

	if answer := askHostname(t, s, "proxyhost.local.", dns.TypeA); len(answer) != 0 {
		t.Fatalf("expected no answer, got %v", answer)
	}
}

func TestOtherHostnameIsNotAnswered(t *testing.T) {
	s := newHostnameTestServer("192.168.1.10")

	if answer := askHostname(t, s, "otherhost.local.", dns.TypeA); len(answer) != 0 {
		t.Fatalf("expected no answer, got %v", answer)
	}
}
