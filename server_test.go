package zeroconf

import (
	"net"
	"reflect"
	"testing"

	"github.com/miekg/dns"
)

func testProxyServer(v4, v6 []string) *Server {
	entry := newServiceEntry("API", "_https._tcp", "local")
	entry.HostName = "api.example.local."
	for _, address := range v4 {
		entry.AddrIPv4 = append(entry.AddrIPv4, net.ParseIP(address))
	}
	for _, address := range v6 {
		entry.AddrIPv6 = append(entry.AddrIPv6, net.ParseIP(address))
	}
	return &Server{service: entry, ttl: 10, probes: map[int]*interfaceProbe{1: {established: true}}}
}

func directHostnameResponse(t *testing.T, server *Server, qtype uint16) *dns.Msg {
	t.Helper()
	query := new(dns.Msg)
	query.SetQuestion("API.EXAMPLE.LOCAL", qtype)
	response := new(dns.Msg)
	response.SetReply(query)
	if err := server.handleQuestion(query.Question[0], response, query, 1); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestProxyAnswersDirectHostnameAddressQueries(t *testing.T) {
	server := testProxyServer([]string{"192.0.2.10"}, []string{"2001:db8::10"})
	for _, test := range []struct {
		name  string
		qtype uint16
		want  []uint16
	}{
		{name: "A", qtype: dns.TypeA, want: []uint16{dns.TypeA}},
		{name: "AAAA", qtype: dns.TypeAAAA, want: []uint16{dns.TypeAAAA}},
		{name: "ANY", qtype: dns.TypeANY, want: []uint16{dns.TypeA, dns.TypeAAAA}},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := directHostnameResponse(t, server, test.qtype)
			got := make([]uint16, 0, len(response.Answer))
			for _, record := range response.Answer {
				got = append(got, record.Header().Rrtype)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("answer types = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestProxyAnswersIPv4OnlyAAAAWithNegativeNSEC(t *testing.T) {
	server := testProxyServer([]string{"192.0.2.10"}, nil)
	response := directHostnameResponse(t, server, dns.TypeAAAA)
	if len(response.Answer) != 1 {
		t.Fatalf("answer count = %d, want one NSEC", len(response.Answer))
	}
	negative, ok := response.Answer[0].(*dns.NSEC)
	if !ok {
		t.Fatalf("answer = %T, want NSEC", response.Answer[0])
	}
	if negative.Hdr.Name != server.service.HostName || negative.NextDomain != server.service.HostName {
		t.Fatalf("NSEC names = %q, %q, want %q", negative.Hdr.Name, negative.NextDomain, server.service.HostName)
	}
	if !reflect.DeepEqual(negative.TypeBitMap, []uint16{dns.TypeA}) {
		t.Fatalf("NSEC types = %#v, want A", negative.TypeBitMap)
	}
	if negative.Hdr.Ttl != 120 {
		t.Fatalf("NSEC TTL = %d, want 120", negative.Hdr.Ttl)
	}
}

func TestProxyIncludesNegativeNSECWithServiceAdditionalRecords(t *testing.T) {
	server := testProxyServer([]string{"192.0.2.10"}, nil)
	response := new(dns.Msg)
	query := new(dns.Msg)
	query.SetQuestion(server.service.ServiceName(), dns.TypePTR)
	response.SetReply(query)
	if err := server.handleQuestion(query.Question[0], response, query, 1); err != nil {
		t.Fatal(err)
	}
	var negative *dns.NSEC
	for _, record := range response.Extra {
		if candidate, ok := record.(*dns.NSEC); ok {
			negative = candidate
		}
	}
	if negative == nil {
		t.Fatalf("additional records = %#v, want NSEC", response.Extra)
	}
	if !reflect.DeepEqual(negative.TypeBitMap, []uint16{dns.TypeA}) {
		t.Fatalf("additional NSEC types = %#v, want A", negative.TypeBitMap)
	}
}
