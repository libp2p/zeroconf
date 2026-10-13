//go:build !windows

package zeroconf

import (
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func preparePacket4(c *ipv4.PacketConn) error { return c.SetControlMessage(ipv4.FlagInterface, true) }
func preparePacket6(c *ipv6.PacketConn) error { return c.SetControlMessage(ipv6.FlagInterface, true) }
func nativeIPv6Interfaces(ifaces []net.Interface) ([]net.Interface, map[int]int, error) {
	return ifaces, nil, nil
}
func (s *Server) readPacket4(c *ipv4.PacketConn, b []byte) (int, *ipv4.ControlMessage, net.Addr, error) {
	return c.ReadFrom(b)
}
func (s *Server) readPacket6(c *ipv6.PacketConn, b []byte) (int, *ipv6.ControlMessage, net.Addr, error) {
	return c.ReadFrom(b)
}
func (s *Server) writePacket4(b []byte, cm *ipv4.ControlMessage, to net.Addr) (int, error) {
	return s.ipv4conn.WriteTo(b, cm, to)
}
func (s *Server) writePacket6(b []byte, cm *ipv6.ControlMessage, to net.Addr) (int, error) {
	return s.ipv6conn.WriteTo(b, cm, to)
}
