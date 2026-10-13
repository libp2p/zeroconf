//go:build interop

package zeroconf

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
)

// This diagnostic compares native defence paths immediately after an observed
// announcement. It does not register a library service or turn a failed
// collision experiment into an accepted outcome.
func TestBonjourDefenceTiming(t *testing.T) {
	if runtime.GOOS != "darwin" || os.Getenv("ZEROCONF_INTEROP_INTERFACE") == "" {
		t.Skip("controlled macOS Bonjour diagnostic")
	}
	iface, err := net.InterfaceByName(os.Getenv("ZEROCONF_INTEROP_INTERFACE"))
	if err != nil {
		t.Fatal(err)
	}
	recordInteropPackets(t, iface)
	conn, err := net.ListenMulticastUDP("udp4", iface, ipv4Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	packets := ipv4.NewPacketConn(conn)
	if err := packets.SetMulticastLoopback(true); err != nil {
		t.Fatal(err)
	}
	if err := packets.SetMulticastTTL(255); err != nil {
		t.Fatal(err)
	}
	instance := fmt.Sprintf("tv410-defence-%d", time.Now().UnixNano())
	name := instance + "._tv410probe._tcp.local."
	host := instance + ".local."
	publisher := exec.Command("dns-sd", "-P", instance, "_tv410probe._tcp", "local.", "9001", host, "192.0.2.20", "tv410=2")
	out := &lockedBuffer{}
	publisher.Stdout, publisher.Stderr = out, out
	if err := publisher.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { publisher.Process.Kill(); publisher.Wait() })
	buf := make([]byte, 65536)
	readNative := func(until time.Time) (time.Time, error) {
		conn.SetReadDeadline(until)
		for {
			n, _, _, err := packets.ReadFrom(buf)
			if err != nil {
				return time.Time{}, err
			}
			var msg dns.Msg
			if msg.Unpack(buf[:n]) != nil || !msg.Response {
				continue
			}
			for _, rr := range msg.Answer {
				if srv, ok := rr.(*dns.SRV); ok && sameMDNSName(srv.Hdr.Name, name) && srv.Port == 9001 && srv.Hdr.Ttl > 0 {
					return time.Now(), nil
				}
			}
		}
	}
	first, err := readNative(time.Now().Add(5 * time.Second))
	if err != nil {
		t.Fatalf("native first announcement: %v; publisher: %s", err, out.String())
	}
	var second time.Time
	for second.Sub(first) < 800*time.Millisecond {
		second, err = readNative(first.Add(4 * time.Second))
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("native announcement interval: %v", second.Sub(first))
	question := dns.Question{Name: name, Qtype: dns.TypeANY, Qclass: dns.ClassINET}
	proposal := &dns.Msg{Question: []dns.Question{question}, Ns: []dns.RR{
		&dns.SRV{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 120}, Port: 9002, Target: host},
		&dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 120}, Txt: []string{"tv410=3"}},
	}}
	wire, err := proposal.Pack()
	if err != nil {
		t.Fatal(err)
	}
	early := 0
	for n := 0; n < 3; n++ {
		if _, err := packets.WriteTo(wire, &ipv4.ControlMessage{IfIndex: iface.Index}, ipv4Addr); err != nil {
			t.Fatal(err)
		}
		deadline := second.Add(time.Duration(n+1) * 250 * time.Millisecond)
		for {
			at, err := readNative(deadline)
			if err != nil {
				if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
					t.Fatal(err)
				}
				break
			}
			early++
			t.Logf("early QM defence at %v after announcement", at.Sub(second))
		}
	}
	t.Logf("defences to three early QM probes: %d", early)

	// A legacy query has its own return socket, so the first port-5353 binder
	// cannot consume its unicast reply before this diagnostic sees it.
	legacy, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	legacyPackets := ipv4.NewPacketConn(legacy)
	if err := legacyPackets.SetMulticastLoopback(true); err != nil {
		t.Fatal(err)
	}
	if err := legacyPackets.SetMulticastTTL(255); err != nil {
		t.Fatal(err)
	}
	query := &dns.Msg{MsgHdr: dns.MsgHdr{Id: 410}, Question: []dns.Question{question}}
	queryWire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacyPackets.WriteTo(queryWire, &ipv4.ControlMessage{IfIndex: iface.Index}, ipv4Addr); err != nil {
		t.Fatal(err)
	}
	legacy.SetReadDeadline(second.Add(time.Second))
	n, source, err := legacy.ReadFromUDP(buf)
	if err != nil {
		if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
			t.Fatal(err)
		}
		t.Logf("no early legacy defence before one second after announcement")
	} else {
		var reply dns.Msg
		if err := reply.Unpack(buf[:n]); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, rr := range reply.Answer {
			if srv, ok := rr.(*dns.SRV); ok && sameMDNSName(srv.Hdr.Name, name) && srv.Port == 9001 {
				found = true
			}
		}
		if !reply.Response || reply.Id != 410 || !found {
			t.Fatalf("unexpected legacy reply: %s", &reply)
		}
		t.Logf("early legacy defence from %s at %v after announcement", source, time.Since(second))
	}
	time.Sleep(1100 * time.Millisecond)
	if _, err := packets.WriteTo(wire, &ipv4.ControlMessage{IfIndex: iface.Index}, ipv4Addr); err != nil {
		t.Fatal(err)
	}
	late, err := readNative(time.Now().Add(500 * time.Millisecond))
	if err != nil {
		t.Fatalf("later QM defence: %v", err)
	}
	t.Logf("later QM defence at %v after announcement", late.Sub(second))
}
