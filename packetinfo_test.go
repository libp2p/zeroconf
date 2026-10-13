package zeroconf

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
)

func TestWindowsPacketInterfaceABI(t *testing.T) {
	for _, test := range []struct {
		name  string
		word  int
		ipv6  bool
		wire  string
		index int
	}{
		{"ipv4-32", 4, false, "140000000000000013000000e00000fb04000000", 4},
		{"ipv4-64", 8, false, "18000000000000000000000013000000e00000fb04000000", 4},
		{"ipv6-32", 4, true, "200000002900000013000000ff0200000000000000000000000000fb11000000", 17},
		{"ipv6-64", 8, true, "24000000000000002900000013000000ff0200000000000000000000000000fb1100000000000000", 17},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire, err := hex.DecodeString(test.wire)
			if err != nil {
				t.Fatal(err)
			}
			index, err := windowsPacketInterface(wire, test.word, test.ipv6)
			if err != nil || index != test.index {
				t.Fatalf("index=%d, error=%v; want %d", index, err, test.index)
			}
		})
	}
}

func TestWindowsOutgoingPacketControlABI(t *testing.T) {
	for _, test := range []struct {
		word   int
		ipv6   bool
		source net.IP
		wire   string
	}{
		{4, false, net.ParseIP("192.0.2.10"), "140000000000000013000000c000020a04000000"},
		{8, false, net.ParseIP("192.0.2.10"), "18000000000000000000000013000000c000020a04000000"},
		{4, true, net.ParseIP("2001:db8::10"), "20000000290000001300000020010db800000000000000000000001004000000"},
		{8, true, net.ParseIP("2001:db8::10"), "2400000000000000290000001300000020010db80000000000000000000000100400000000000000"},
	} {
		expected, err := hex.DecodeString(test.wire)
		if err != nil {
			t.Fatal(err)
		}
		if got := windowsPacketControl(4, test.word, test.ipv6, test.source); !bytes.Equal(got, expected) {
			t.Fatalf("word=%d ipv6=%v: got %x want %x", test.word, test.ipv6, got, expected)
		}
	}
}

func TestWindowsPacketControlRejectsMissingOrInvalidMetadata(t *testing.T) {
	valid, _ := hex.DecodeString("18000000000000000000000013000000e00000fb04000000")
	for _, wire := range []string{
		"", "1800", "080000000000000000000000130000000000000004000000",
		"ffffffffffffffff00000000130000000000000004000000",
		"10000000000000000000000013000000",
		"18000000000000000000000013000000e00000fb00000000",
		"18000000000000000000000042000000e00000fb04000000",
	} {
		data, err := hex.DecodeString(wire)
		if err != nil {
			t.Fatal(err)
		}
		if index, err := windowsPacketInterface(data, 8, false); err == nil {
			t.Fatalf("invalid metadata %x accepted as index %d", data, index)
		}
	}
	if _, err := windowsPacketInterface(valid, 8, true); err == nil {
		t.Fatal("IPv4 metadata used for an IPv6 packet")
	}
	if _, err := windowsPacketInterface(valid, 2, false); err == nil {
		t.Fatal("invalid ABI word size accepted")
	}
	other := append([]byte(nil), valid...)
	other[len(other)-4] = 5
	if _, err := windowsPacketInterface(append(append([]byte{}, valid...), other...), 8, false); err == nil {
		t.Fatal("contradictory interface metadata accepted")
	}
	unknown, _ := hex.DecodeString("14000000000000000000000007000000ff00000000000000")
	index, err := windowsPacketInterface(append(unknown, valid...), 8, false)
	if err != nil || index != 4 {
		t.Fatalf("unrelated padded control object: index=%d err=%v", index, err)
	}
}

func TestWindowsIPv6IndexMapping(t *testing.T) {
	ifaces := []net.Interface{{Index: 3, Name: "first"}, {Index: 8, Name: "second"}}
	indexes := map[int]int{3: 42, 8: 81}
	selected, err := selectIPv6Interfaces(ifaces, indexes)
	if err != nil {
		t.Fatal(err)
	}
	if selected[0].Index != 42 || selected[1].Index != 81 || ifaces[0].Index != 3 || selected[0].Name != "first" {
		t.Fatal("native IPv6 selection modified canonical interfaces or selected the wrong adapter")
	}
	if canonicalIPv6Index(42, indexes) != 3 || canonicalIPv6Index(81, indexes) != 8 || canonicalIPv6Index(99, indexes) != -1 {
		t.Fatal("incoming native IPv6 index mapped to the wrong registration link")
	}
	if _, err := selectIPv6Interfaces(ifaces, map[int]int{3: 42}); err == nil {
		t.Fatal("missing native IPv6 adapter index silently selected the default interface")
	}
}

func TestWindowsIPv6DestinationScopeUsesNativeIndex(t *testing.T) {
	for _, address := range []string{"ff02::fb", "fe80::1234"} {
		original := &net.UDPAddr{IP: net.ParseIP(address), Port: 5353, Zone: "canonical-adapter"}
		destination := windowsScopedDestination(original, 42)
		if destination.Zone != "42" || original.Zone != "canonical-adapter" || destination.Port != 5353 {
			t.Fatal("native IPv6 scope did not preserve the caller's destination or selected native adapter")
		}
	}
	global := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 5353}
	if windowsScopedDestination(global, 42).Zone != "" {
		t.Fatal("global IPv6 address assigned a link scope")
	}
}

func TestInterfaceTransportFamiliesIncludeLinkLocal(t *testing.T) {
	for _, test := range []struct {
		addresses []net.Addr
		v4, v6    bool
	}{
		{nil, false, false},
		{[]net.Addr{&net.IPAddr{IP: net.ParseIP("169.254.10.20")}}, true, false},
		{[]net.Addr{&net.IPNet{IP: net.ParseIP("fe80::1234")}}, false, true},
		{[]net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.1")}, &net.IPAddr{IP: net.ParseIP("2001:db8::1")}}, true, true},
	} {
		v4, v6 := interfaceFamilies(test.addresses)
		if v4 != test.v4 || v6 != test.v6 {
			t.Fatalf("transport families=%v,%v want %v,%v", v4, v6, test.v4, test.v6)
		}
	}
}

func TestMulticastDoesNotUseWrongAddressFamily(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	s := &Server{
		ipv4conn:   ipv4.NewPacketConn(conn),
		ipv4Ifaces: []net.Interface{{Index: 1}},
		ipv6Ifaces: []net.Interface{{Index: 1 << 29}},
	}
	msg := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}}
	if err := s.multicastResponse(msg, 1<<29); err != nil {
		t.Fatalf("IPv6-only link attempted to send through the IPv4 socket: %v", err)
	}
}
