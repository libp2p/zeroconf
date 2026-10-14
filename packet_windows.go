//go:build windows

package zeroconf

import (
	"fmt"
	"net"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/windows"
)

func enableWindowsPacketInfo(c net.PacketConn, level int) error {
	raw, err := c.(*net.UDPConn).SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		optionErr = syscall.SetsockoptInt(syscall.Handle(fd), level, 19, 1)
	}); err != nil {
		return err
	}
	return optionErr
}
func preparePacket4(c *ipv4.PacketConn) error {
	return enableWindowsPacketInfo(c.PacketConn, syscall.IPPROTO_IP)
}
func preparePacket6(c *ipv6.PacketConn) error {
	return enableWindowsPacketInfo(c.PacketConn, syscall.IPPROTO_IPV6)
}

func nativeIPv6Interfaces(ifaces []net.Interface) ([]net.Interface, map[int]int, error) {
	var size uint32
	err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0, nil, &size)
	if err != windows.ERROR_BUFFER_OVERFLOW || size == 0 {
		return nil, nil, fmt.Errorf("get Windows adapter buffer size: %v (size %d)", err, size)
	}
	for {
		buffer := make([]byte, size)
		adapters := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err = windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0, adapters, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW && int(size) > len(buffer) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		indexes := make(map[int]int)
		for adapter := adapters; adapter != nil; adapter = adapter.Next {
			canonical := adapter.IfIndex
			if canonical == 0 {
				canonical = adapter.Ipv6IfIndex
			}
			indexes[int(canonical)] = int(adapter.Ipv6IfIndex)
		}
		result, err := selectIPv6Interfaces(ifaces, indexes)
		if err != nil {
			return nil, nil, err
		}
		return result, indexes, nil
	}
}

func readWindowsPacket(c net.PacketConn, b []byte, ipv6 bool) (int, int, net.Addr, error) {
	var control [64]byte
	n, cn, flags, source, err := c.(*net.UDPConn).ReadMsgUDP(b, control[:])
	if err != nil {
		return 0, 0, nil, err
	}
	if flags&(windows.MSG_TRUNC|windows.MSG_CTRUNC) != 0 {
		return 0, 0, nil, fmt.Errorf("truncated Windows packet or control data")
	}
	index, err := windowsPacketInterface(control[:cn], strconv.IntSize/8, ipv6)
	return n, index, source, err
}
func (s *Server) readPacket4(c *ipv4.PacketConn, b []byte) (int, *ipv4.ControlMessage, net.Addr, error) {
	n, index, source, err := readWindowsPacket(c.PacketConn, b, false)
	return n, &ipv4.ControlMessage{IfIndex: index}, source, err
}
func (s *Server) readPacket6(c *ipv6.PacketConn, b []byte) (int, *ipv6.ControlMessage, net.Addr, error) {
	n, index, source, err := readWindowsPacket(c.PacketConn, b, true)
	canonical := canonicalIPv6Index(index, s.ipv6IfIndexes)
	return n, &ipv6.ControlMessage{IfIndex: canonical}, source, err
}
func (s *Server) writePacket4(b []byte, cm *ipv4.ControlMessage, to net.Addr) (int, error) {
	index := 0
	var source net.IP
	if cm != nil {
		index = cm.IfIndex
		if index != 0 {
			iface, err := net.InterfaceByIndex(index)
			if err != nil {
				return 0, err
			}
			source, err = windowsInterfaceAddress(iface, false, to.(*net.UDPAddr).IP)
			if err != nil {
				return 0, err
			}
		}
	}
	return writeWindowsPacket(s.ipv4conn.PacketConn, b, index, false, to, source)
}
func (s *Server) writePacket6(b []byte, cm *ipv6.ControlMessage, to net.Addr) (int, error) {
	index := 0
	var source net.IP
	if cm != nil && cm.IfIndex != 0 {
		canonicalIndex := cm.IfIndex
		index = s.ipv6IfIndexes[canonicalIndex]
		if index == 0 {
			return 0, fmt.Errorf("no native IPv6 index for interface %d", cm.IfIndex)
		}
		iface, err := net.InterfaceByIndex(canonicalIndex)
		if err != nil {
			return 0, err
		}
		source, err = windowsInterfaceAddress(iface, true, to.(*net.UDPAddr).IP)
		if err != nil {
			return 0, err
		}
	}
	return writeWindowsPacket(s.ipv6conn.PacketConn, b, index, true, to, source)
}
func writeWindowsPacket(c net.PacketConn, b []byte, index int, ipv6 bool, to net.Addr, source net.IP) (int, error) {
	var control []byte
	if index != 0 {
		if source == nil {
			return 0, fmt.Errorf("missing source address for interface %d", index)
		}
		control = windowsPacketControl(index, strconv.IntSize/8, ipv6, source)
	}
	destination := to.(*net.UDPAddr)
	if ipv6 {
		destination = windowsScopedDestination(destination, index)
	}
	n, _, err := c.(*net.UDPConn).WriteMsgUDP(b, control, destination)
	return n, err
}

func windowsInterfaceAddress(iface *net.Interface, ipv6 bool, destination net.IP) (net.IP, error) {
	addresses, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	preferLinkLocal := destination.IsLinkLocalMulticast() || destination.IsLinkLocalUnicast()
	var fallback net.IP
	for _, address := range addresses {
		var ip net.IP
		switch address := address.(type) {
		case *net.IPNet:
			ip = address.IP
		case *net.IPAddr:
			ip = address.IP
		}
		if ipv6 {
			if ip.To4() != nil || ip.To16() == nil {
				continue
			}
		} else {
			ip = ip.To4()
			if ip == nil {
				continue
			}
		}
		if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
			continue
		}
		if fallback == nil {
			fallback = append(net.IP(nil), ip...)
		}
		if ip.IsLinkLocalUnicast() == preferLinkLocal {
			return append(net.IP(nil), ip...), nil
		}
	}
	if fallback != nil {
		return fallback, nil
	}
	family := "IPv4"
	if ipv6 {
		family = "IPv6"
	}
	return nil, fmt.Errorf("no %s source address on interface %s (%d)", family, iface.Name, iface.Index)
}
