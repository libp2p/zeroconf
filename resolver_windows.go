package zeroconf

import (
	"context"
	"golang.org/x/sys/windows"
	"net"
	"unsafe"
)

func systemResolvers(ctx context.Context) (func(string) []string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	size := uint32(15000)
	var buffer []byte
	var first *windows.IpAdapterAddresses
	for {
		buffer = make([]byte, size)
		first = (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0, first, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil, err
		}
		break
	}
	var addresses []string
	for adapter := first; adapter != nil; adapter = adapter.Next {
		if adapter.OperStatus != windows.IfOperStatusUp {
			continue
		}
		for server := adapter.FirstDnsServerAddress; server != nil; server = server.Next {
			if server.Address.Sockaddr == nil {
				continue
			}
			raw := (*windows.RawSockaddrAny)(unsafe.Pointer(server.Address.Sockaddr))
			sockaddr, err := raw.Sockaddr()
			if err != nil {
				continue
			}
			switch value := sockaddr.(type) {
			case *windows.SockaddrInet4:
				addresses = append(addresses, net.IP(value.Addr[:]).String())
			case *windows.SockaddrInet6:
				addresses = append(addresses, scopedIPv6(net.IP(value.Addr[:]), value.ZoneId))
			}
		}
	}
	return fixedResolvers(addresses)
}
