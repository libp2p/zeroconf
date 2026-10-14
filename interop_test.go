//go:build interop

package zeroconf

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// This opt-in test advertises synthetic names on the explicitly selected link.
// It is never part of the default private-multicast regression suite.
func TestNativeInterop(t *testing.T) {
	ifaceName := os.Getenv("ZEROCONF_INTEROP_INTERFACE")
	if ifaceName == "" {
		t.Skip("set ZEROCONF_INTEROP_INTERFACE for controlled native responder testing")
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		t.Fatal(err)
	}
	versionCmd := exec.Command("avahi-daemon", "--version")
	if runtime.GOOS == "darwin" {
		versionCmd = exec.Command("dns-sd", "-V")
	}
	version, err := versionCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("native responder unavailable: %s: %v", version, err)
	}
	t.Logf("native responder: %s", version)
	recordInteropPackets(t, iface)
	instance := fmt.Sprintf("tv410-%d-%d", os.Getpid(), time.Now().UnixNano())
	host := instance + ".local."
	typ := "_tv410probe._tcp"

	// Native responders must discover the library's announcement and answer a
	// lookup after startup. Shutdown must remove the synthetic registration.
	own, err := RegisterProxy(instance, typ, "local", 9000, host, []string{"192.0.2.10"}, []string{"tv410=1"}, []net.Interface{*iface})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(own.Shutdown)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := own.WaitForReady(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	var browse *exec.Cmd
	if runtime.GOOS == "darwin" {
		browse = exec.Command("dns-sd", "-B", typ, "local.")
	} else {
		browse = exec.Command("avahi-browse", "-p", typ)
	}
	out := &lockedBuffer{}
	browse.Stdout = out
	browse.Stderr = out
	if err := browse.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(out.String(), instance) {
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(out.String(), instance) {
		browse.Process.Kill()
		browse.Wait()
		t.Fatalf("native browse missed registration: %s", out.String())
	}
	t.Logf("native browse saw registration: %s", out.String())
	// Query after the unsolicited announcements have finished. A native
	// browser seeing cached data alone does not prove continued response.
	time.Sleep(2 * time.Second)
	checkInteropResponse(t, iface, own.service.ServiceInstanceName(), own.service.Port)
	own.Shutdown()
	marker := "Rmv"
	if runtime.GOOS != "darwin" {
		marker = "-;"
	}
	deadline = time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(out.String(), marker) {
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(out.String(), marker) {
		t.Errorf("native browse did not report withdrawal: %s", out.String())
	}
	browse.Process.Kill()
	browse.Wait()

	// Establish a record in the native daemon first. The library must defer and
	// report the collision instead of announcing incompatible records.
	instance += "-collision"
	var publisher *exec.Cmd
	if runtime.GOOS == "darwin" {
		publisher = exec.Command("dns-sd", "-P", instance, typ, "local.", "9001", instance+".local.", "192.0.2.20", "tv410=2")
	} else {
		publisher = exec.Command("avahi-publish-service", instance, typ, "9001", "tv410=2")
	}
	pubOut := &lockedBuffer{}
	publisher.Stdout = pubOut
	publisher.Stderr = pubOut
	if err := publisher.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { publisher.Process.Kill(); publisher.Wait() })
	// Start during the native announcement sequence to exercise the
	// collision timing that previously reported false readiness.
	time.Sleep(2 * time.Second)
	collision, err := RegisterProxy(instance, typ, "local", 9002, instance+".local.", []string{"192.0.2.30"}, []string{"tv410=3"}, []net.Interface{*iface})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(collision.Shutdown)
	wait, cancelWait := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelWait()
	err = collision.WaitForReady(wait)
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("expected native collision: %v; publisher: %s", err, pubOut.String())
	}
	t.Logf("native collision: %v; publisher: %s", err, pubOut.String())
}

// Verify a fresh multicast query is answered after startup announcements stop.
func checkInteropResponse(t *testing.T, iface *net.Interface, name string, port int) {
	t.Helper()
	conn, err := net.ListenMulticastUDP("udp4", iface, &net.UDPAddr{IP: mdnsGroupIPv4, Port: mdnsWildcardAddrIPv4.Port})
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
	query := &dns.Msg{Question: []dns.Question{{Name: name, Qtype: dns.TypeSRV, Qclass: dns.ClassINET}}}
	wire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := packets.WriteTo(wire, &ipv4.ControlMessage{IfIndex: iface.Index}, ipv4Addr); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65536)
	for {
		n, _, source, err := packets.ReadFrom(buf)
		if err != nil {
			t.Fatalf("no continued response to SRV query: %v", err)
		}
		var response dns.Msg
		if response.Unpack(buf[:n]) != nil || !response.Response {
			continue
		}
		for _, rr := range response.Answer {
			if srv, ok := rr.(*dns.SRV); ok && sameMDNSName(srv.Hdr.Name, name) && srv.Port == uint16(port) && srv.Hdr.Ttl > 0 {
				t.Logf("continued SRV response from %s: %s", source, srv.String())
				return
			}
		}
	}
}

type lockedBuffer struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.Write(p)
}
func (b *lockedBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.data.String() }

// Record only this test's DNS packets through an ordinary multicast listener.
// This records original DNS wire bytes and interface/source metadata without BPF.
func recordInteropPackets(t *testing.T, iface *net.Interface) {
	path := os.Getenv("ZEROCONF_INTEROP_CAPTURE")
	if path == "" {
		return
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenMulticastUDP("udp4", iface, &net.UDPAddr{IP: mdnsGroupIPv4, Port: mdnsWildcardAddrIPv4.Port})
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	packets := ipv4.NewPacketConn(conn)
	packets.SetControlMessage(ipv4.FlagInterface, true)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65536)
		for {
			n, cm, src, err := packets.ReadFrom(buf)
			if err != nil {
				return
			}
			var msg dns.Msg
			if msg.Unpack(buf[:n]) != nil {
				continue
			}
			relevant := false
			for _, q := range msg.Question {
				if strings.Contains(q.Name, "tv410") {
					relevant = true
				}
			}
			for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
				for _, rr := range section {
					if strings.Contains(rr.Header().Name, "tv410") {
						relevant = true
					}
				}
			}
			if !relevant {
				continue
			}
			index := 0
			if cm != nil {
				index = cm.IfIndex
			}
			json.NewEncoder(file).Encode(struct {
				Time      string
				Source    string
				Interface int
				Wire      string
				Message   string
			}{time.Now().UTC().Format(time.RFC3339Nano), src.String(), index, hex.EncodeToString(buf[:n]), msg.String()})
		}
	}()
	t.Cleanup(func() { packets.Close(); <-done; file.Close() })
}

// The native Bonjour daemon runs on the host while this test runs on a separate
// VM link. Same-host native-loopback behavior is recorded separately.
func TestBonjourRemotePeer(t *testing.T) {
	instance := os.Getenv("ZEROCONF_INTEROP_INSTANCE")
	if instance == "" {
		t.Skip("external Bonjour publisher required")
	}
	iface, err := net.InterfaceByName(os.Getenv("ZEROCONF_INTEROP_INTERFACE"))
	if err != nil {
		t.Fatal(err)
	}
	recordInteropPackets(t, iface)
	s, err := RegisterProxy(instance, "_tv410probe._tcp", "local", 9002, instance+".local.", []string{"192.0.2.30"}, []string{"tv410=3"}, []net.Interface{*iface})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = s.WaitForReady(ctx)
	var collision *ConflictError
	if !errors.As(err, &collision) {
		t.Fatalf("expected remote Bonjour collision: %v", err)
	}
	t.Logf("remote Bonjour collision: %v", err)
}
