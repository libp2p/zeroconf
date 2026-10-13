package zeroconf

import (
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"testing"
	"time"
)

// Multicast integration tests use the standard mDNS groups and a test port on
// interface, and never claim the computer's hostname.
func testMulticastIfaces(t *testing.T) []net.Interface {
	t.Helper()
	// GitHub-hosted macOS runners cannot route mDNS multicast, so these tests
	// cannot exercise the standard multicast groups there.
	if runtime.GOOS == "darwin" && os.Getenv("RUNNER_ENVIRONMENT") == "github-hosted" {
		t.Skip("GitHub-hosted macOS runners have no route to the standard mDNS multicast group")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagMulticast != 0 {
			addresses, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, address := range addresses {
				if ipnet, ok := address.(*net.IPNet); ok && ipnet.IP.To4() != nil && ipnet.IP.IsGlobalUnicast() {
					return []net.Interface{iface}
				}
			}
		}
	}
	t.Skip("no active IPv4 multicast interface")
	return nil
}

func registerTestService(t *testing.T, instance, service, domain string, port int, text []string) (*Server, error) {
	t.Helper()
	host := fmt.Sprintf("zeroconf-test-%d-%d.local.", os.Getpid(), time.Now().UnixNano())
	return RegisterProxy(instance, service, domain, port, host, []string{"127.0.0.1"}, text, testMulticastIfaces(t))
}

// Use the standard mDNS groups with a test port, never the system mDNS port.
// The protocol processing remains unchanged.
func TestMain(m *testing.M) {
	if os.Getenv("ZEROCONF_INTEROP_INTERFACE") != "" {
		flag.Parse()
		run := flag.Lookup("test.run").Value.String()
		if run != "^TestNativeInterop$" && run != "^TestBonjourRemotePeer$" && run != "^TestBonjourDefenceTiming$" {
			fmt.Fprintln(os.Stderr, "interop requires an exact test name; refusing default tests on native mDNS")
			os.Exit(2)
		}
		os.Exit(m.Run())
	}
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	port := listener.LocalAddr().(*net.UDPAddr).Port
	listener.Close()
	mdnsGroupIPv4 = net.ParseIP("224.0.0.251")
	mdnsGroupIPv6 = net.ParseIP("ff02::fb")
	mdnsWildcardAddrIPv4 = &net.UDPAddr{IP: mdnsGroupIPv4, Port: port}
	mdnsWildcardAddrIPv6 = &net.UDPAddr{IP: net.ParseIP("ff02::"), Port: port}
	ipv4Addr = &net.UDPAddr{IP: mdnsGroupIPv4, Port: port}
	ipv6Addr = &net.UDPAddr{IP: mdnsGroupIPv6, Port: port}
	os.Exit(m.Run())
}
