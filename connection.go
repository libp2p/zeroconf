package zeroconf

import (
	"fmt"
	"net"

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

func joinUdp6Multicast(interfaces []*NetInterface) (*ipv6.PacketConn, error) {
	if len(interfaces) == 0 {
		return nil, fmt.Errorf("no interfaces to join multicast on")
	}

	udpConn, err := net.ListenUDP("udp6", mdnsWildcardAddrIPv6)
	if err != nil {
		return nil, err
	}

	// Join multicast groups to receive announcements
	pkConn := ipv6.NewPacketConn(udpConn)
	pkConn.SetControlMessage(ipv6.FlagInterface, true)

	// log.Println("Using multicast interfaces: ", interfaces)
	var anySucceeded bool
	for _, iface := range interfaces {
		if err := pkConn.JoinGroup(&iface.Interface, &net.UDPAddr{IP: mdnsGroupIPv6}); err == nil {
			iface.SetFlag(NetInterfaceScopeIPv6, NetInterfaceStateFlagMulticastJoined)
			anySucceeded = true
		}
	}
	if !anySucceeded {
		pkConn.Close()
		return nil, fmt.Errorf("udp6: failed to join any of these interfaces: %v", interfaces)
	}

	_ = pkConn.SetMulticastHopLimit(255)

	return pkConn, nil
}

func joinUdp4Multicast(interfaces []*NetInterface) (*ipv4.PacketConn, error) {
	if len(interfaces) == 0 {
		return nil, fmt.Errorf("no interfaces to join multicast on")
	}

	udpConn, err := net.ListenUDP("udp4", mdnsWildcardAddrIPv4)
	if err != nil {
		// log.Printf("[ERR] bonjour: Failed to bind to udp4 mutlicast: %v", err)
		return nil, err
	}

	// Join multicast groups to receive announcements
	pkConn := ipv4.NewPacketConn(udpConn)
	pkConn.SetControlMessage(ipv4.FlagInterface, true)

	// log.Println("Using multicast interfaces: ", interfaces)
	var anySucceed bool

	for _, iface := range interfaces {
		if err := pkConn.JoinGroup(&iface.Interface, &net.UDPAddr{IP: mdnsGroupIPv4}); err == nil {
			anySucceed = true
			iface.SetFlag(NetInterfaceScopeIPv4, NetInterfaceStateFlagMulticastJoined)
		}
	}
	if !anySucceed {
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
