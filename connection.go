package zeroconf

import (
	"fmt"
	"net"
	"sync"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Serialize socket creation with the temporary exclusive bind used for QU detection.
var multicastSocketMu sync.Mutex

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

func joinUdp6Multicast(interfaces []net.Interface, requireAll ...bool) (*ipv6.PacketConn, error) {
	multicastSocketMu.Lock()
	defer multicastSocketMu.Unlock()
	return joinUdp6MulticastLocked(interfaces, requireAll...)
}

func joinUdp6MulticastLocked(interfaces []net.Interface, requireAll ...bool) (*ipv6.PacketConn, error) {
	var udpConn *net.UDPConn
	var err error
	firstJoined := false
	if len(requireAll) > 0 && requireAll[0] && len(interfaces) > 0 {
		udpConn, err = net.ListenMulticastUDP("udp6", &interfaces[0], &net.UDPAddr{IP: mdnsGroupIPv6, Port: mdnsWildcardAddrIPv6.Port})
		firstJoined = true
	} else {
		udpConn, err = net.ListenUDP("udp6", mdnsWildcardAddrIPv6)
	}
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
	for index, iface := range interfaces {
		if index == 0 && firstJoined {
			continue
		}
		if err := pkConn.JoinGroup(&iface, &net.UDPAddr{IP: mdnsGroupIPv6}); err != nil {
			// log.Println("Udp6 JoinGroup failed for iface ", iface)
			failedJoins++
		}
	}
	if failedJoins == len(interfaces) || (len(requireAll) > 0 && requireAll[0] && failedJoins > 0) {
		pkConn.Close()
		return nil, fmt.Errorf("udp6: failed to join any of these interfaces: %v", interfaces)
	}

	_ = pkConn.SetMulticastLoopback(true)
	_ = pkConn.SetMulticastHopLimit(255)

	return pkConn, nil
}

func joinUdp4Multicast(interfaces []net.Interface, requireAll ...bool) (*ipv4.PacketConn, error) {
	multicastSocketMu.Lock()
	defer multicastSocketMu.Unlock()
	return joinUdp4MulticastLocked(interfaces, requireAll...)
}

func joinUdp4MulticastLocked(interfaces []net.Interface, requireAll ...bool) (*ipv4.PacketConn, error) {
	var udpConn *net.UDPConn
	var err error
	firstJoined := false
	if len(requireAll) > 0 && requireAll[0] && len(interfaces) > 0 {
		udpConn, err = net.ListenMulticastUDP("udp4", &interfaces[0], &net.UDPAddr{IP: mdnsGroupIPv4, Port: mdnsWildcardAddrIPv4.Port})
		firstJoined = true
	} else {
		udpConn, err = net.ListenUDP("udp4", mdnsWildcardAddrIPv4)
	}
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
	for index, iface := range interfaces {
		if index == 0 && firstJoined {
			continue
		}
		if err := pkConn.JoinGroup(&iface, &net.UDPAddr{IP: mdnsGroupIPv4}); err != nil {
			// log.Println("Udp4 JoinGroup failed for iface ", iface)
			failedJoins++
		}
	}
	if failedJoins == len(interfaces) || (len(requireAll) > 0 && requireAll[0] && failedJoins > 0) {
		pkConn.Close()
		return nil, fmt.Errorf("udp4: failed to join any of these interfaces: %v", interfaces)
	}

	_ = pkConn.SetMulticastLoopback(true)
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
