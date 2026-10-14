package zeroconf

import (
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	// Number of Multicast responses sent for a query message (default: 1 < x < 9)
	multicastRepetitions = 2
)

var defaultTTL uint32 = 3200

type serverOpts struct {
	ttl uint32
}

func applyServerOpts(options ...ServerOption) serverOpts {
	// Apply default configuration and load supplied options.
	var conf = serverOpts{
		ttl: defaultTTL,
	}
	for _, o := range options {
		if o != nil {
			o(&conf)
		}
	}
	return conf
}

// ServerOption fills the option struct.
type ServerOption func(*serverOpts)

// TTL sets the TTL for DNS replies.
func TTL(ttl uint32) ServerOption {
	return func(o *serverOpts) {
		o.ttl = ttl
	}
}

// Register a service by given arguments. This call will take the system's hostname
// and lookup IP by that hostname.
func Register(instance, service, domain string, port int, text []string, ifaces []net.Interface, opts ...ServerOption) (*Server, error) {
	entry := newServiceEntry(instance, service, domain)
	entry.Port = port
	entry.Text = text

	if entry.Instance == "" {
		return nil, fmt.Errorf("missing service instance name")
	}
	if entry.Service == "" {
		return nil, fmt.Errorf("missing service name")
	}
	if entry.Domain == "" {
		entry.Domain = "local."
	}
	if entry.Port == 0 {
		return nil, fmt.Errorf("missing port")
	}

	var err error
	if entry.HostName == "" {
		entry.HostName, err = os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("could not determine host")
		}
	}

	if !strings.HasSuffix(trimDot(entry.HostName), entry.Domain) {
		entry.HostName = fmt.Sprintf("%s.%s.", trimDot(entry.HostName), trimDot(entry.Domain))
	}

	if len(ifaces) == 0 {
		ifaces = listMulticastInterfaces()
	}

	for _, iface := range ifaces {
		v4, v6 := addrsForInterface(&iface)
		entry.AddrIPv4 = append(entry.AddrIPv4, v4...)
		entry.AddrIPv6 = append(entry.AddrIPv6, v6...)
	}

	if entry.AddrIPv4 == nil && entry.AddrIPv6 == nil {
		return nil, fmt.Errorf("could not determine host IP addresses")
	}

	s, err := newServer(ifaces, applyServerOpts(opts...))
	if err != nil {
		return nil, err
	}

	s.service = entry
	s.interfaceAddrs = make(map[int][]net.IP)
	for _, iface := range ifaces {
		v4, v6 := addrsForInterface(&iface)
		s.interfaceAddrs[iface.Index] = append(v4, v6...)
	}
	s.start()

	return s, nil
}

// RegisterProxy registers a service proxy. This call will skip the hostname/IP lookup and
// will use the provided values.
func RegisterProxy(instance, service, domain string, port int, host string, ips []string, text []string, ifaces []net.Interface, opts ...ServerOption) (*Server, error) {
	entry := newServiceEntry(instance, service, domain)
	entry.Port = port
	entry.Text = text
	entry.HostName = host

	if entry.Instance == "" {
		return nil, fmt.Errorf("missing service instance name")
	}
	if entry.Service == "" {
		return nil, fmt.Errorf("missing service name")
	}
	if entry.HostName == "" {
		return nil, fmt.Errorf("missing host name")
	}
	if entry.Domain == "" {
		entry.Domain = "local"
	}
	if entry.Port == 0 {
		return nil, fmt.Errorf("missing port")
	}

	if !strings.HasSuffix(trimDot(entry.HostName), entry.Domain) {
		entry.HostName = fmt.Sprintf("%s.%s.", trimDot(entry.HostName), trimDot(entry.Domain))
	}

	for _, ip := range ips {
		ipAddr := net.ParseIP(ip)
		if ipAddr == nil {
			return nil, fmt.Errorf("failed to parse given IP: %v", ip)
		} else if ipv4 := ipAddr.To4(); ipv4 != nil {
			entry.AddrIPv4 = append(entry.AddrIPv4, ipAddr)
		} else if ipv6 := ipAddr.To16(); ipv6 != nil {
			entry.AddrIPv6 = append(entry.AddrIPv6, ipAddr)
		} else {
			return nil, fmt.Errorf("the IP is neither IPv4 nor IPv6: %#v", ipAddr)
		}
	}

	if len(ifaces) == 0 {
		ifaces = listMulticastInterfaces()
	}

	s, err := newServer(ifaces, applyServerOpts(opts...))
	if err != nil {
		return nil, err
	}

	s.service = entry
	s.start()

	return s, nil
}

const (
	qClassCacheFlush uint16 = 1 << 15
)

// Server structure encapsulates both IPv4/IPv6 UDP connections
type Server struct {
	service    *ServiceEntry
	ipv4conn   *ipv4.PacketConn
	ipv6conn   *ipv6.PacketConn
	ifaces     []net.Interface
	ipv4Ifaces []net.Interface
	ipv6Ifaces []net.Interface

	shouldShutdown chan struct{}
	refCount       sync.WaitGroup
	isShutdown     bool
	ttl            uint32

	mu             sync.Mutex
	interfaceAddrs map[int][]net.IP
	probes         map[int]*interfaceProbe
	ready          chan struct{}
	done           chan struct{}
	wake           chan struct{}
	readySet       bool
	readyErr       error
	terminalErr    error
	send           func(*dns.Msg, int) error
	unicastProbes  bool
	ipv6IfIndexes  map[int]int
}

// Constructs server structure
func newServer(ifaces []net.Interface, opts serverOpts) (*Server, error) {
	if len(ifaces) == 0 {
		return nil, fmt.Errorf("no selected multicast interface")
	}
	var ifaces4, ifaces6 []net.Interface
	for _, iface := range ifaces {
		addresses, _ := iface.Addrs()
		v4, v6 := interfaceFamilies(addresses)
		if v4 {
			ifaces4 = append(ifaces4, iface)
		}
		if v6 {
			ifaces6 = append(ifaces6, iface)
		}
	}
	multicastSocketMu.Lock()
	defer multicastSocketMu.Unlock()
	unicastProbes := canReceiveUnicastProbes()
	var ipv4conn *ipv4.PacketConn
	err4 := fmt.Errorf("no IPv4 addresses on selected interfaces")
	if len(ifaces4) > 0 {
		ipv4conn, err4 = joinUdp4MulticastLocked(ifaces4, true)
	}
	if err4 == nil {
		if err4 = preparePacket4(ipv4conn); err4 != nil {
			ipv4conn.Close()
			ipv4conn = nil
		}
	}
	if err4 != nil {
		log.Printf("[zeroconf] no suitable IPv4 interface: %s", err4.Error())
	}
	var ipv6conn *ipv6.PacketConn
	var ipv6Indexes map[int]int
	err6 := fmt.Errorf("no IPv6 addresses on selected interfaces")
	if len(ifaces6) > 0 {
		var nativeIfaces []net.Interface
		nativeIfaces, ipv6Indexes, err6 = nativeIPv6Interfaces(ifaces6)
		if err6 == nil {
			ipv6conn, err6 = joinUdp6MulticastLocked(nativeIfaces, true)
		}
		if err6 == nil {
			if err6 = preparePacket6(ipv6conn); err6 != nil {
				ipv6conn.Close()
				ipv6conn = nil
			}
		}
	}
	if err6 != nil {
		log.Printf("[zeroconf] no suitable IPv6 interface: %s", err6.Error())
	}
	for _, iface := range ifaces {
		if (ipv4conn == nil || !hasInterface(ifaces4, iface.Index)) && (ipv6conn == nil || !hasInterface(ifaces6, iface.Index)) {
			if ipv4conn != nil {
				ipv4conn.Close()
			}
			if ipv6conn != nil {
				ipv6conn.Close()
			}
			return nil, fmt.Errorf("no usable mDNS transport for required interface %s (%d)", iface.Name, iface.Index)
		}
	}

	s := &Server{
		ipv4conn:       ipv4conn,
		unicastProbes:  unicastProbes,
		ipv6conn:       ipv6conn,
		ipv6IfIndexes:  ipv6Indexes,
		ifaces:         ifaces,
		ipv4Ifaces:     ifaces4,
		ipv6Ifaces:     ifaces6,
		ttl:            opts.ttl,
		shouldShutdown: make(chan struct{}),
		ready:          make(chan struct{}),
		done:           make(chan struct{}),
		wake:           make(chan struct{}, 1),
	}

	return s, nil
}

func (s *Server) start() {
	s.initProbes()
	workers := 1
	if s.ipv4conn != nil {
		workers++
	}
	if s.ipv6conn != nil {
		workers++
	}
	s.refCount.Add(workers)
	if s.ipv4conn != nil {
		go s.recv4(s.ipv4conn)
	}
	if s.ipv6conn != nil {
		go s.recv6(s.ipv6conn)
	}
	go s.probe()
}

// SetText updates the TXT records. Tentative records are updated without an
// announcement; established records are announced on their established links.
func (s *Server) SetText(text []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isShutdown {
		return
	}
	s.service.Text = append([]string(nil), text...)
	for index, state := range s.probes {
		if state.established {
			if err := s.announce(index, s.ttl); err != nil {
				s.stopLocked(err)
				return
			}
		} else {
			// Restart with the new data without shortening a pending
			// startup delay or conflict retry.
			state.sent = 0
		}
	}
	s.notifyProbe()
}

// TTL sets the TTL for DNS replies
//
// Deprecated: This method is racy. Use the TTL server option instead.
func (s *Server) TTL(ttl uint32) {
	s.ttl = ttl
}

// Shutdown closes all udp connections and unregisters the service
func (s *Server) Shutdown() {
	s.mu.Lock()
	if !s.isShutdown {
		s.withdrawEstablished()
		s.stopLocked(nil)
	}
	done := s.done
	s.mu.Unlock()
	if done != nil {
		<-done
	}
}

// Caller holds mu. A failed registration must also withdraw records already
// established on other links, without sending a goodbye on a tentative link.
func (s *Server) withdrawEstablished() {
	for index, state := range s.probes {
		if state.established {
			if err := s.announce(index, 0); err != nil {
				log.Printf("failed to unregister: %s", err)
			}
		}
	}
}

// recv4 is a long running routine to receive packets from an interface
func (s *Server) recv4(c *ipv4.PacketConn) {
	defer s.refCount.Done()
	if c == nil {
		return
	}
	buf := make([]byte, 65536)
	for {
		select {
		case <-s.shouldShutdown:
			return
		default:
			var ifIndex int
			n, cm, from, err := s.readPacket4(c, buf)
			if err != nil {
				s.mu.Lock()
				if !s.isShutdown {
					s.stopLocked(err)
				}
				s.mu.Unlock()
				return
			}
			if cm != nil {
				ifIndex = cm.IfIndex
			}
			_ = s.parsePacket(buf[:n], ifIndex, from)
		}
	}
}

// recv6 is a long running routine to receive packets from an interface
func (s *Server) recv6(c *ipv6.PacketConn) {
	defer s.refCount.Done()
	if c == nil {
		return
	}
	buf := make([]byte, 65536)
	for {
		select {
		case <-s.shouldShutdown:
			return
		default:
			var ifIndex int
			n, cm, from, err := s.readPacket6(c, buf)
			if err != nil {
				s.mu.Lock()
				if !s.isShutdown {
					s.stopLocked(err)
				}
				s.mu.Unlock()
				return
			}
			if cm != nil {
				ifIndex = cm.IfIndex
			}
			_ = s.parsePacket(buf[:n], ifIndex, from)
		}
	}
}

// parsePacket is used to parse an incoming packet
func (s *Server) parsePacket(packet []byte, ifIndex int, from net.Addr) error {
	var msg dns.Msg
	if err := msg.Unpack(packet); err != nil {
		// log.Printf("[ERR] zeroconf: Failed to unpack packet: %v", err)
		return err
	}
	// mDNS responses must originate from the mDNS port. Queries from
	// ephemeral ports remain valid legacy queries (RFC 6762 section 6).
	if msg.Response {
		source, ok := from.(*net.UDPAddr)
		if !ok || source == nil {
			return nil
		}
		port := ipv4Addr.Port
		if source.IP.To4() == nil {
			port = ipv6Addr.Port
		}
		if source.Port != port {
			return nil
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.handleQuery(&msg, ifIndex, from)
}

// handleQuery is used to handle an incoming query
func (s *Server) handleQuery(query *dns.Msg, ifIndex int, from net.Addr) error {
	if s.isShutdown || query.Opcode != dns.OpcodeQuery || query.Rcode != dns.RcodeSuccess || query.Truncated {
		return nil
	}
	index, state := s.probeForInterface(ifIndex)
	if state == nil {
		return nil
	}
	if query.Response {
		return s.observeResponse(query, index, state, time.Now())
	}
	if !state.established {
		s.observeProbe(query, index, state, time.Now())
		return nil
	}
	ifIndex = index

	// Handle each question
	var err error
	for _, q := range query.Question {
		resp := dns.Msg{}
		resp.SetReply(query)
		resp.Compress = true
		resp.RecursionDesired = false
		resp.Authoritative = true
		resp.Question = nil // RFC6762 section 6 "responses MUST NOT contain any questions"
		resp.Answer = []dns.RR{}
		resp.Extra = []dns.RR{}
		if err = s.handleQuestion(q, &resp, query, ifIndex); err != nil {
			// log.Printf("[ERR] zeroconf: failed to handle question %v: %v", q, err)
			continue
		}
		// Check if there is an answer
		if len(resp.Answer) == 0 {
			continue
		}

		if isUnicastQuestion(q) {
			// Send unicast
			if e := s.unicastResponse(&resp, ifIndex, from); e != nil {
				s.stopLocked(e)
				return e
			}
		} else {
			// Send mulicast
			if e := s.sendMulticast(&resp, ifIndex); e != nil {
				s.stopLocked(e)
				return e
			}
		}
	}

	return err
}

// RFC6762 7.1. Known-Answer Suppression
func isKnownAnswer(resp *dns.Msg, query *dns.Msg) bool {
	if len(resp.Answer) == 0 || len(query.Answer) == 0 {
		return false
	}

	if resp.Answer[0].Header().Rrtype != dns.TypePTR {
		return false
	}
	answer := resp.Answer[0].(*dns.PTR)

	for _, known := range query.Answer {
		hdr := known.Header()
		if hdr.Rrtype != answer.Hdr.Rrtype {
			continue
		}
		ptr := known.(*dns.PTR)
		if ptr.Ptr == answer.Ptr && hdr.Ttl >= answer.Hdr.Ttl/2 {
			// log.Printf("skipping known answer: %v", ptr)
			return true
		}
	}

	return false
}

// handleQuestion is used to handle an incoming question
func (s *Server) handleQuestion(q dns.Question, resp *dns.Msg, query *dns.Msg, ifIndex int) error {
	if s.service == nil {
		return nil
	}

	_, state := s.probeForInterface(ifIndex)
	if state == nil || !state.established || s.isShutdown {
		return nil
	}
	if q.Qclass & ^qClassCacheFlush != dns.ClassINET && q.Qclass & ^qClassCacheFlush != dns.ClassANY {
		return nil
	}
	if sameMDNSName(q.Name, s.service.HostName) {
		resp.Answer = s.appendAddrsForType(resp.Answer, s.ttl, ifIndex, true, q.Qtype)
		return nil
	}

	switch {
	case sameMDNSName(q.Name, s.service.ServiceTypeName()):
		s.serviceTypeName(resp, s.ttl)
		if isKnownAnswer(resp, query) {
			resp.Answer = nil
		}

	case sameMDNSName(q.Name, s.service.ServiceName()):
		s.composeBrowsingAnswers(resp, ifIndex)
		if isKnownAnswer(resp, query) {
			resp.Answer = nil
		}

	case sameMDNSName(q.Name, s.service.ServiceInstanceName()):
		s.composeLookupAnswers(resp, s.ttl, ifIndex, false)
	default:
		// handle matching subtype query
		for _, subtype := range s.service.Subtypes {
			subtype = fmt.Sprintf("%s._sub.%s", subtype, s.service.ServiceName())
			if sameMDNSName(q.Name, subtype) {
				s.composeBrowsingAnswers(resp, ifIndex)
				if isKnownAnswer(resp, query) {
					resp.Answer = nil
				}
				break
			}
		}
	}

	return nil
}

func (s *Server) composeBrowsingAnswers(resp *dns.Msg, ifIndex int) {
	ptr := &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceName(),
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    s.ttl,
		},
		Ptr: s.service.ServiceInstanceName(),
	}
	resp.Answer = append(resp.Answer, ptr)

	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceInstanceName(),
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    s.ttl,
		},
		Txt: s.service.Text,
	}
	srv := &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceInstanceName(),
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET,
			Ttl:    s.ttl,
		},
		Priority: 0,
		Weight:   0,
		Port:     uint16(s.service.Port),
		Target:   s.service.HostName,
	}
	resp.Extra = append(resp.Extra, srv, txt)

	resp.Extra = s.appendAddrs(resp.Extra, s.ttl, ifIndex, false)
}

func (s *Server) composeLookupAnswers(resp *dns.Msg, ttl uint32, ifIndex int, flushCache bool) {
	// From RFC6762
	//    The most significant bit of the rrclass for a record in the Answer
	//    Section of a response message is the Multicast DNS cache-flush bit
	//    and is discussed in more detail below in Section 10.2, "Announcements
	//    to Flush Outdated Cache Entries".
	ptr := &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceName(),
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ptr: s.service.ServiceInstanceName(),
	}
	srv := &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceInstanceName(),
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET | qClassCacheFlush,
			Ttl:    ttl,
		},
		Priority: 0,
		Weight:   0,
		Port:     uint16(s.service.Port),
		Target:   s.service.HostName,
	}
	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceInstanceName(),
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET | qClassCacheFlush,
			Ttl:    ttl,
		},
		Txt: s.service.Text,
	}
	dnssd := &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceTypeName(),
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ptr: s.service.ServiceName(),
	}
	resp.Answer = append(resp.Answer, srv, txt, ptr, dnssd)

	for _, subtype := range s.service.Subtypes {
		resp.Answer = append(resp.Answer,
			&dns.PTR{
				Hdr: dns.RR_Header{
					Name:   subtype,
					Rrtype: dns.TypePTR,
					Class:  dns.ClassINET,
					Ttl:    ttl,
				},
				Ptr: s.service.ServiceInstanceName(),
			})
	}

	resp.Answer = s.appendAddrs(resp.Answer, ttl, ifIndex, flushCache)
}

func (s *Server) serviceTypeName(resp *dns.Msg, ttl uint32) {
	// From RFC6762
	// 9.  Service Type Enumeration
	//
	//    For this purpose, a special meta-query is defined.  A DNS query for
	//    PTR records with the name "_services._dns-sd._udp.<Domain>" yields a
	//    set of PTR records, where the rdata of each PTR record is the two-
	//    label <Service> name, plus the same domain, e.g.,
	//    "_http._tcp.<Domain>".
	dnssd := &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceTypeName(),
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ptr: s.service.ServiceName(),
	}
	resp.Answer = append(resp.Answer, dnssd)
}

func (s *Server) appendAddrs(list []dns.RR, ttl uint32, ifIndex int, flushCache bool) []dns.RR {
	return s.appendAddrsForType(list, ttl, ifIndex, flushCache, dns.TypeANY)
}

func (s *Server) appendAddrsForType(list []dns.RR, ttl uint32, ifIndex int, flushCache bool, qtype uint16) []dns.RR {
	v4 := s.service.AddrIPv4
	v6 := s.service.AddrIPv6
	if s.interfaceAddrs != nil {
		v4, v6 = nil, nil
		for _, ip := range s.interfaceAddrs[ifIndex] {
			if ip.To4() != nil {
				v4 = append(v4, ip)
			} else {
				v6 = append(v6, ip)
			}
		}
	}
	if len(v4) == 0 && len(v6) == 0 {
		iface, _ := net.InterfaceByIndex(ifIndex)
		if iface != nil {
			a4, a6 := addrsForInterface(iface)
			v4 = append(v4, a4...)
			v6 = append(v6, a6...)
		}
	}
	if ttl > 0 {
		// RFC6762 Section 10 recommends 120s for A/AAAA records so they
		// account for network interface and address changes.
		ttl = 120
	}
	var cacheFlushBit uint16
	if flushCache {
		cacheFlushBit = qClassCacheFlush
	}
	if qtype == dns.TypeA || qtype == dns.TypeANY {
		for _, ip := range v4 {
			list = append(list, &dns.A{
				Hdr: dns.RR_Header{Name: s.service.HostName, Rrtype: dns.TypeA, Class: dns.ClassINET | cacheFlushBit, Ttl: ttl},
				A:   ip,
			})
		}
	}
	if qtype == dns.TypeAAAA || qtype == dns.TypeANY {
		for _, ip := range v6 {
			list = append(list, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: s.service.HostName, Rrtype: dns.TypeAAAA, Class: dns.ClassINET | cacheFlushBit, Ttl: ttl},
				AAAA: ip,
			})
		}
	}
	if len(v4)+len(v6) > 0 && (len(v4) == 0 || len(v6) == 0) {
		list = append(list, &dns.NSEC{
			Hdr:        dns.RR_Header{Name: s.service.HostName, Rrtype: dns.TypeNSEC, Class: dns.ClassINET | cacheFlushBit, Ttl: ttl},
			NextDomain: s.service.HostName,
			TypeBitMap: addressTypeBitmap(v4, v6),
		})
	}
	return list
}

func addressTypeBitmap(v4, v6 []net.IP) []uint16 {
	types := make([]uint16, 0, 2)
	if len(v4) > 0 {
		types = append(types, dns.TypeA)
	}
	if len(v6) > 0 {
		types = append(types, dns.TypeAAAA)
	}
	return types
}

func addrsForInterface(iface *net.Interface) ([]net.IP, []net.IP) {
	var v4, v6, v6local []net.IP
	addrs, _ := iface.Addrs()
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				v4 = append(v4, ipnet.IP)
			} else {
				switch ip := ipnet.IP.To16(); ip != nil {
				case ip.IsGlobalUnicast():
					v6 = append(v6, ipnet.IP)
				case ip.IsLinkLocalUnicast():
					v6local = append(v6local, ipnet.IP)
				}
			}
		}
	}
	if len(v6) == 0 {
		v6 = v6local
	}
	return v4, v6
}

// unicastResponse is used to send a unicast response packet
func (s *Server) unicastResponse(resp *dns.Msg, ifIndex int, from net.Addr) error {
	buf, err := resp.Pack()
	if err != nil {
		return err
	}
	addr := from.(*net.UDPAddr)
	if addr.IP.To4() != nil {
		if ifIndex != 0 {
			var wcm ipv4.ControlMessage
			wcm.IfIndex = ifIndex
			_, err = s.writePacket4(buf, &wcm, addr)
		} else {
			_, err = s.writePacket4(buf, nil, addr)
		}
		return err
	} else {
		if ifIndex != 0 {
			var wcm ipv6.ControlMessage
			wcm.IfIndex = ifIndex
			_, err = s.writePacket6(buf, &wcm, addr)
		} else {
			_, err = s.writePacket6(buf, nil, addr)
		}
		return err
	}
}

// multicastResponse is used to send a multicast response packet
func (s *Server) multicastResponse(msg *dns.Msg, ifIndex int) error {
	buf, err := msg.Pack()
	if err != nil {
		return fmt.Errorf("failed to pack msg %v: %w", msg, err)
	}
	if s.ipv4conn != nil && (ifIndex == 0 || hasInterface(s.ipv4Ifaces, ifIndex)) {
		// Windows packet information is handled by the native message adapter.
		var wcm ipv4.ControlMessage
		if ifIndex != 0 {
			switch runtime.GOOS {
			case "darwin", "ios", "linux", "windows":
				wcm.IfIndex = ifIndex
			default:
				iface, _ := net.InterfaceByIndex(ifIndex)
				if err := s.ipv4conn.SetMulticastInterface(iface); err != nil {
					return fmt.Errorf("failed to set multicast interface: %w", err)
				}
			}
			if _, err := s.writePacket4(buf, &wcm, ipv4Addr); err != nil {
				return err
			}
		} else {
			for _, intf := range s.ipv4Ifaces {
				switch runtime.GOOS {
				case "darwin", "ios", "linux", "windows":
					wcm.IfIndex = intf.Index
				default:
					if err := s.ipv4conn.SetMulticastInterface(&intf); err != nil {
						return fmt.Errorf("failed to set multicast interface: %w", err)
					}
				}
				if _, err := s.writePacket4(buf, &wcm, ipv4Addr); err != nil {
					return err
				}
			}
		}
	}

	if s.ipv6conn != nil && (ifIndex == 0 || hasInterface(s.ipv6Ifaces, ifIndex)) {
		// Windows packet information is handled by the native message adapter.
		var wcm ipv6.ControlMessage
		if ifIndex != 0 {
			switch runtime.GOOS {
			case "darwin", "ios", "linux", "windows":
				wcm.IfIndex = ifIndex
			default:
				iface, _ := net.InterfaceByIndex(ifIndex)
				if err := s.ipv6conn.SetMulticastInterface(iface); err != nil {
					return fmt.Errorf("failed to set multicast interface: %w", err)
				}
			}
			if _, err := s.writePacket6(buf, &wcm, ipv6Addr); err != nil {
				return err
			}
		} else {
			for _, intf := range s.ipv6Ifaces {
				switch runtime.GOOS {
				case "darwin", "ios", "linux", "windows":
					wcm.IfIndex = intf.Index
				default:
					if err := s.ipv6conn.SetMulticastInterface(&intf); err != nil {
						return fmt.Errorf("failed to set multicast interface: %w", err)
					}
				}
				if _, err := s.writePacket6(buf, &wcm, ipv6Addr); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func isUnicastQuestion(q dns.Question) bool {
	// From RFC6762
	// 18.12.  Repurposing of Top Bit of qclass in Question Section
	//
	//    In the Question Section of a Multicast DNS query, the top bit of the
	//    qclass field is used to indicate that unicast responses are preferred
	//    for this particular question.  (See Section 5.4.)
	return q.Qclass&qClassCacheFlush != 0
}
