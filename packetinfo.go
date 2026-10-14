package zeroconf

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

// Windows WSACMSGHDR uses SIZE_T followed by two 32-bit integers. Packet-info
// data is an address followed by a 32-bit interface index. All supported Windows
// architectures are little-endian; control objects align to the pointer width.
func windowsPacketInterface(control []byte, wordSize int, ipv6 bool) (int, error) {
	if wordSize != 4 && wordSize != 8 {
		return 0, fmt.Errorf("invalid Windows control word size %d", wordSize)
	}
	header := wordSize + 8
	level, addressSize := uint32(0), 4
	if ipv6 {
		level, addressSize = 41, 16
	}
	index := 0
	for len(control) > 0 {
		if len(control) < header {
			return 0, fmt.Errorf("short Windows control header")
		}
		length := uint64(binary.LittleEndian.Uint32(control))
		if wordSize == 8 {
			length = binary.LittleEndian.Uint64(control)
		}
		if length < uint64(header) || length > uint64(len(control)) {
			return 0, fmt.Errorf("invalid Windows control length %d", length)
		}
		if binary.LittleEndian.Uint32(control[wordSize:]) == level && binary.LittleEndian.Uint32(control[wordSize+4:]) == 19 {
			if length < uint64(header+addressSize+4) {
				return 0, fmt.Errorf("short Windows packet information")
			}
			nextIndex := int(binary.LittleEndian.Uint32(control[header+addressSize:]))
			if nextIndex <= 0 || (index != 0 && index != nextIndex) {
				return 0, fmt.Errorf("invalid Windows packet interface %d", nextIndex)
			}
			index = nextIndex
		}
		next := (int(length) + wordSize - 1) & ^(wordSize - 1)
		if next >= len(control) {
			break
		}
		control = control[next:]
	}
	if index == 0 {
		return 0, fmt.Errorf("windows packet information missing")
	}
	return index, nil
}

func windowsPacketControl(index, wordSize int, ipv6 bool, source net.IP) []byte {
	header := wordSize + 8
	level, addressSize := uint32(0), 4
	address := source.To4()
	if ipv6 {
		level, addressSize = 41, 16
		address = source.To16()
	}
	length := header + addressSize + 4
	control := make([]byte, (length+wordSize-1) & ^(wordSize-1))
	if wordSize == 8 {
		binary.LittleEndian.PutUint64(control, uint64(length))
	} else {
		binary.LittleEndian.PutUint32(control, uint32(length))
	}
	binary.LittleEndian.PutUint32(control[wordSize:], level)
	binary.LittleEndian.PutUint32(control[wordSize+4:], 19)
	copy(control[header:header+addressSize], address)
	binary.LittleEndian.PutUint32(control[header+addressSize:], uint32(index))
	return control
}

// Go's Windows Interface.Index uses the IPv4 index, falling back to IPv6 on
// IPv6-only adapters. Keep the native IPv6 index for socket operations.
func selectIPv6Interfaces(ifaces []net.Interface, indexes map[int]int) ([]net.Interface, error) {
	selected := append([]net.Interface(nil), ifaces...)
	for i, iface := range ifaces {
		index := indexes[iface.Index]
		if index == 0 {
			return nil, fmt.Errorf("no native IPv6 index for interface %d", iface.Index)
		}
		selected[i].Index = index
	}
	return selected, nil
}

func canonicalIPv6Index(index int, indexes map[int]int) int {
	for canonical, native := range indexes {
		if native == index {
			return canonical
		}
	}
	return -1 // An unselected interface must not affect any registration state.
}

func windowsScopedDestination(to *net.UDPAddr, index int) *net.UDPAddr {
	if index == 0 || (!to.IP.IsLinkLocalUnicast() && !to.IP.IsLinkLocalMulticast()) {
		return to
	}
	copy := *to
	copy.Zone = strconv.Itoa(index)
	return &copy
}

func hasInterface(ifaces []net.Interface, index int) bool {
	for _, iface := range ifaces {
		if iface.Index == index {
			return true
		}
	}
	return false
}

// Transport eligibility includes link-local addresses even when registration
// address selection prefers a different address for its advertised records.
func interfaceFamilies(addresses []net.Addr) (ipv4, ipv6 bool) {
	for _, address := range addresses {
		var ip net.IP
		switch address := address.(type) {
		case *net.IPNet:
			ip = address.IP
		case *net.IPAddr:
			ip = address.IP
		}
		if ip.To4() != nil {
			ipv4 = true
		} else if ip.To16() != nil {
			ipv6 = true
		}
	}
	return
}
