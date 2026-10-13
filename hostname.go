package zeroconf

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
)

type hostnameRegistration struct {
	name string
	v4   []net.IP
	v6   []net.IP
}

// RegisterHostname publishes hostname addresses through multicast DNS without
// registering a service. host must be fully qualified; its final dot is optional.
// Explicit ips select the published address families. With no ips, addresses are
// discovered on ifaces. Empty ifaces selects the multicast-capable interfaces.
// Registration is nonblocking. Use WaitForReady to observe initial establishment,
// Done and Err for subsequent failure, and Shutdown to withdraw the addresses.
func RegisterHostname(host string, ips []string, ifaces []net.Interface, opts ...ServerOption) (*Server, error) {
	h, err := newHostnameRegistration(host, ips)
	if err != nil {
		return nil, err
	}
	if len(ifaces) == 0 {
		ifaces = listMulticastInterfaces()
	}
	var addresses map[int][]net.IP
	if len(ips) == 0 {
		h.v4, h.v6, addresses = addressesForInterfaces(ifaces)
		for _, iface := range ifaces {
			if len(addresses[iface.Index]) == 0 {
				return nil, fmt.Errorf("no hostname addresses on selected interface %s (%d)", iface.Name, iface.Index)
			}
		}
	}
	if len(h.v4)+len(h.v6) == 0 {
		return nil, fmt.Errorf("could not determine host IP addresses")
	}
	s, err := newServer(ifaces, applyServerOpts(opts...))
	if err != nil {
		return nil, err
	}
	s.hostname = h
	s.interfaceAddrs = addresses
	s.start()
	return s, nil
}

func newHostnameRegistration(host string, ips []string) (*hostnameRegistration, error) {
	if _, valid := dns.IsDomainName(host); !valid || len(dns.SplitDomainName(host)) < 2 {
		return nil, fmt.Errorf("hostname must be fully qualified: %q", host)
	}
	h := &hostnameRegistration{name: dns.Fqdn(host)}
	for _, text := range ips {
		ip := net.ParseIP(text)
		if ip == nil {
			return nil, fmt.Errorf("failed to parse given IP: %v", text)
		}
		if ip.To4() != nil {
			h.v4 = append(h.v4, ip)
		} else {
			h.v6 = append(h.v6, ip)
		}
	}
	return h, nil
}

func addressesForInterfaces(ifaces []net.Interface) (v4, v6 []net.IP, addresses map[int][]net.IP) {
	addresses = make(map[int][]net.IP)
	for _, iface := range ifaces {
		a4, a6 := addrsForInterface(&iface)
		v4 = append(v4, a4...)
		v6 = append(v6, a6...)
		addresses[iface.Index] = append(a4, a6...)
	}
	return
}

// Combined registrations retain their existing service entry. Both paths use
// the same address builders without inventing a service for a hostname.
func (s *Server) hostnameData() hostnameRegistration {
	if s.hostname != nil {
		return *s.hostname
	}
	if s.service != nil {
		return hostnameRegistration{name: s.service.HostName, v4: s.service.AddrIPv4, v6: s.service.AddrIPv6}
	}
	return hostnameRegistration{}
}
