package zeroconf

import (
	"fmt"
	"log"
	"net"
	"runtime"
	"sync"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var (
	// Multicast groups used by mDNS
	mdnsGroupIPv4 = net.IPv4(224, 0, 0, 251)
	mdnsGroupIPv6 = net.ParseIP("ff02::fb")

	// mDNS wildcard addresses
	mdnsWildcardAddrIPv4 = &net.UDPAddr{
		IP:   net.ParseIP("224.0.0.0"),
		Port: 5353,
	}
	mdnsWildcardAddrIPv6 = &net.UDPAddr{
		IP: net.ParseIP("ff02::"),
		// IP:   net.ParseIP("fd00::12d3:26e7:48db:e7d"),
		Port: 5353,
	}

	// mDNS endpoint addresses
	ipv4Addr = &net.UDPAddr{
		IP:   mdnsGroupIPv4,
		Port: 5353,
	}
	ipv6Addr = &net.UDPAddr{
		IP:   mdnsGroupIPv6,
		Port: 5353,
	}
)

// writeTo4 sends buf to the IPv4 mDNS group on the interface ifIndex names.
// On Linux the interface is named in the packet's control message. Elsewhere
// it is set on the socket instead: Windows does not implement control
// messages (see https://pkg.go.dev/golang.org/x/net/ipv4#pkg-note-BUG), and
// macOS refuses one naming an interface with no route to the group, as the
// loopback interface has none ("sendmsg: network is unreachable"). mu
// serialises setting the socket's interface and writing, so that concurrent
// sends do not go out on each other's interface.
func writeTo4(c *ipv4.PacketConn, mu *sync.Mutex, buf []byte, ifIndex int) {
	if runtime.GOOS == "linux" {
		_, _ = c.WriteTo(buf, &ipv4.ControlMessage{IfIndex: ifIndex}, ipv4Addr)
		return
	}
	iface, err := net.InterfaceByIndex(ifIndex)
	if err != nil {
		log.Printf("[WARN] mdns: Failed to find interface %d: %v", ifIndex, err)
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if err := c.SetMulticastInterface(iface); err != nil {
		log.Printf("[WARN] mdns: Failed to set multicast interface: %v", err)
	}
	_, _ = c.WriteTo(buf, nil, ipv4Addr)
}

func joinUdp6Multicast(interfaces []net.Interface) (*ipv6.PacketConn, error) {
	udpConn, err := net.ListenUDP("udp6", mdnsWildcardAddrIPv6)
	if err != nil {
		return nil, err
	}

	// Join multicast groups to receive announcements
	pkConn := ipv6.NewPacketConn(udpConn)
	pkConn.SetControlMessage(ipv6.FlagInterface, true)

	if len(interfaces) == 0 {
		interfaces = listMulticastInterfaces()
	}
	// log.Println("Using multicast interfaces: ", interfaces)

	var failedJoins int
	for _, iface := range interfaces {
		if err := pkConn.JoinGroup(&iface, &net.UDPAddr{IP: mdnsGroupIPv6}); err != nil {
			// log.Println("Udp6 JoinGroup failed for iface ", iface)
			failedJoins++
		}
	}
	if failedJoins == len(interfaces) {
		pkConn.Close()
		return nil, fmt.Errorf("udp6: failed to join any of these interfaces: %v", interfaces)
	}

	_ = pkConn.SetMulticastHopLimit(255)

	return pkConn, nil
}

func joinUdp4Multicast(interfaces []net.Interface) (*ipv4.PacketConn, error) {
	udpConn, err := net.ListenUDP("udp4", mdnsWildcardAddrIPv4)
	if err != nil {
		// log.Printf("[ERR] bonjour: Failed to bind to udp4 mutlicast: %v", err)
		return nil, err
	}

	// Join multicast groups to receive announcements
	pkConn := ipv4.NewPacketConn(udpConn)
	pkConn.SetControlMessage(ipv4.FlagInterface, true)

	if len(interfaces) == 0 {
		interfaces = listMulticastInterfaces()
	}
	// log.Println("Using multicast interfaces: ", interfaces)

	var failedJoins int
	for _, iface := range interfaces {
		if err := pkConn.JoinGroup(&iface, &net.UDPAddr{IP: mdnsGroupIPv4}); err != nil {
			// log.Println("Udp4 JoinGroup failed for iface ", iface)
			failedJoins++
		}
	}
	if failedJoins == len(interfaces) {
		pkConn.Close()
		return nil, fmt.Errorf("udp4: failed to join any of these interfaces: %v", interfaces)
	}

	_ = pkConn.SetMulticastTTL(255)

	return pkConn, nil
}

func listMulticastInterfaces() []net.Interface {
	var interfaces []net.Interface
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifi := range ifaces {
		if (ifi.Flags & net.FlagUp) == 0 {
			continue
		}
		if (ifi.Flags & net.FlagMulticast) > 0 {
			interfaces = append(interfaces, ifi)
		}
	}

	return interfaces
}
