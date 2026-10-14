package zeroconf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ErrServerClosed is the initial establishment result when Shutdown is called
// before the registration becomes ready.
var ErrServerClosed = errors.New("zeroconf: server closed before registration established")

// ConflictError reports a registration that could not retain a unique name.
// InterfaceIndex identifies the link on which the conflict occurred.
type ConflictError struct {
	Name           string
	InterfaceIndex int
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("zeroconf: name %s conflicts on interface %d", e.Name, e.InterfaceIndex)
}

// WaitForReady waits for the initial registration result on all selected links.
// Register and RegisterProxy remain nonblocking. Canceling ctx cancels only this
// wait. After initial success, use Done and Err to observe subsequent failure.
func (s *Server) WaitForReady(ctx context.Context) error {
	select {
	case <-s.ready:
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.readyErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Done closes after shutdown or terminal failure has stopped the server workers.
func (s *Server) Done() <-chan struct{} { return s.done }

// Err returns the terminal failure, or nil before failure and after a normal
// Shutdown. It is safe to call concurrently with other Server methods.
func (s *Server) Err() error { s.mu.Lock(); defer s.mu.Unlock(); return s.terminalErr }

// Each interface has its own probe sequence and conflict history. A registration
// becomes ready only after all of its selected links have completed probing.
type interfaceProbe struct {
	sent          int
	established   bool
	next          time.Time
	announcements int
	conflicts     []time.Time
}

func (s *Server) initProbes() {
	s.probes = make(map[int]*interfaceProbe)
	now := time.Now()
	for _, iface := range s.ifaces {
		s.probes[iface.Index] = &interfaceProbe{next: now.Add(time.Duration(rand.Intn(251)) * time.Millisecond)}
	}
}

func (s *Server) probeForInterface(index int) (int, *interfaceProbe) {
	if index == 0 && len(s.probes) == 1 {
		for i, p := range s.probes {
			return i, p
		}
	}
	return index, s.probes[index]
}

func (s *Server) notifyProbe() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Server) setReadyLocked(err error) {
	if !s.readySet {
		s.readyErr = err
		s.readySet = true
		close(s.ready)
	}
}

// Caller holds mu. Cleanup waits in a separate goroutine because the caller may
// itself be a receiver or the probe worker.
func (s *Server) stopLocked(err error) {
	if s.isShutdown {
		return
	}
	if err != nil {
		s.withdrawEstablished()
	}
	s.isShutdown = true
	s.terminalErr = err
	if err != nil {
		s.setReadyLocked(err)
	} else {
		s.setReadyLocked(ErrServerClosed)
	}
	close(s.shouldShutdown)
	if s.ipv4conn != nil {
		s.ipv4conn.Close()
	}
	if s.ipv6conn != nil {
		s.ipv6conn.Close()
	}
	go func() { s.refCount.Wait(); close(s.done) }()
}

func (s *Server) sendMulticast(msg *dns.Msg, index int) error {
	if s.send != nil {
		return s.send(msg, index)
	}
	return s.multicastResponse(msg, index)
}

func sameMDNSName(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

// proposedRecords uses the same data as announcement/response construction.
// Shared PTR records and derived NSEC records are not probe proposals.
func (s *Server) proposedRecords(index int) []dns.RR {
	var msg dns.Msg
	s.composeLookupAnswers(&msg, s.ttl, index, false)
	var records []dns.RR
	for _, rr := range msg.Answer {
		switch rr.Header().Rrtype {
		case dns.TypeSRV, dns.TypeTXT, dns.TypeA, dns.TypeAAAA:
			rr.Header().Class &^= qClassCacheFlush
			records = append(records, rr)
		}
	}
	return records
}

// RFC 6762 section 15.1: on a host with another mDNS implementation,
// unicast replies may go exclusively to the first socket bound to port 5353.
// Ask for multicast defence unless this process can bind the port exclusively.
// The caller holds multicastSocketMu until its multicast sockets are open.
func canReceiveUnicastProbes() bool {
	c4, err := net.ListenUDP("udp4", &net.UDPAddr{Port: mdnsWildcardAddrIPv4.Port})
	if err != nil {
		return false
	}
	defer c4.Close()
	c6, err := net.ListenUDP("udp6", &net.UDPAddr{Port: mdnsWildcardAddrIPv6.Port})
	if err != nil {
		return false
	}
	c6.Close()
	return true
}

func (s *Server) probeMessage(index int) *dns.Msg {
	msg := &dns.Msg{Ns: s.proposedRecords(index)}
	class := uint16(dns.ClassINET)
	if s.unicastProbes {
		class |= qClassCacheFlush
	}
	for _, rr := range msg.Ns {
		found := false
		for _, q := range msg.Question {
			if sameMDNSName(q.Name, rr.Header().Name) {
				found = true
				break
			}
		}
		if !found {
			msg.Question = append(msg.Question, dns.Question{Name: rr.Header().Name, Qtype: dns.TypeANY, Qclass: class})
		}
	}
	return msg
}

func (s *Server) announce(index int, ttl uint32) error {
	msg := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Authoritative: true}, Compress: true}
	s.composeLookupAnswers(msg, ttl, index, true)
	return s.sendMulticast(msg, index)
}

// stepProbes performs due work using an explicit time, allowing packet and
// timing tests to run without wall-clock sleeps. Caller holds mu.
func (s *Server) stepProbes(now time.Time) time.Duration {
	delay := time.Hour
	if s.isShutdown {
		return delay
	}
	probeCount := 3
	// A shared port cannot reliably receive unicast defence. Multicast
	// defence may arrive late, so send the final probe a second after the first.
	if !s.unicastProbes {
		probeCount = 5
	}
	for index, p := range s.probes {
		if !p.next.IsZero() && !now.Before(p.next) {
			if !p.established {
				if p.sent < probeCount {
					if err := s.sendMulticast(s.probeMessage(index), index); err != nil {
						s.stopLocked(err)
						return delay
					}
					p.sent++
					p.next = now.Add(250 * time.Millisecond)
				} else {
					p.established = true
					p.announcements = 0
					if err := s.announce(index, s.ttl); err != nil {
						s.stopLocked(err)
						return delay
					}
					p.announcements++
					p.next = now.Add(time.Second)
				}
			} else {
				if err := s.announce(index, s.ttl); err != nil {
					s.stopLocked(err)
					return delay
				}
				p.announcements++
				if p.announcements >= multicastRepetitions {
					p.next = time.Time{}
				} else {
					p.next = now.Add(time.Second << (p.announcements - 1))
				}
			}
		}
		if !p.next.IsZero() && p.next.Sub(now) < delay {
			delay = p.next.Sub(now)
		}
	}
	ready := len(s.probes) > 0
	for _, p := range s.probes {
		ready = ready && p.established
	}
	if ready {
		s.setReadyLocked(nil)
	}
	return delay
}

func (s *Server) probe() {
	defer s.refCount.Done()
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-s.shouldShutdown:
			return
		case <-s.wake:
		case <-timer.C:
		}
		s.mu.Lock()
		delay := s.stepProbes(time.Now())
		stopped := s.isShutdown
		s.mu.Unlock()
		if stopped {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(delay)
	}
}

func (p *interfaceProbe) restart(now time.Time, delay time.Duration) {
	first := 0
	for first < len(p.conflicts) && now.Sub(p.conflicts[first]) >= 10*time.Second {
		first++
	}
	p.conflicts = append(p.conflicts[first:], now)
	if len(p.conflicts) >= 15 && delay < 5*time.Second {
		delay = 5 * time.Second
	}
	p.sent = 0
	p.established = false
	p.announcements = 0
	p.next = now.Add(delay)
}

// rrKey is class/type followed by uncompressed RDATA. Names in RDATA retain
// their octets for the RFC 6762 section 8.2 bytewise comparison.
func rrKey(rr dns.RR) ([]byte, error) {
	record := dns.Copy(rr)
	record.Header().Name = "."
	record.Header().Class &^= qClassCacheFlush
	buf := make([]byte, dns.Len(record)+1)
	n, err := dns.PackRR(record, buf, 0, nil, false)
	if err != nil {
		return nil, err
	}
	if n < 11 {
		return nil, errors.New("zeroconf: invalid resource record")
	}
	key := make([]byte, 4, n-7)
	binary.BigEndian.PutUint16(key[:2], record.Header().Class)
	binary.BigEndian.PutUint16(key[2:4], record.Header().Rrtype)
	return append(key, buf[11:n]...), nil
}

func recordSet(records []dns.RR, name string) ([][]byte, error) {
	var result [][]byte
	for _, rr := range records {
		if rr == nil || !sameMDNSName(rr.Header().Name, name) {
			continue
		}
		key, err := rrKey(rr)
		if err != nil {
			return nil, err
		}
		result = append(result, key)
	}
	sort.Slice(result, func(i, j int) bool { return bytes.Compare(result[i], result[j]) < 0 })
	unique := result[:0]
	for _, key := range result {
		if len(unique) == 0 || !bytes.Equal(unique[len(unique)-1], key) {
			unique = append(unique, key)
		}
	}
	return unique, nil
}

func compareRecordSets(a, b [][]byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := bytes.Compare(a[i], b[i]); c != 0 {
			return c
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}

func identicalRecord(a, b dns.RR) bool {
	if !sameMDNSName(a.Header().Name, b.Header().Name) {
		return false
	}
	// dns.IsDuplicate compares embedded domain names without regard to case.
	a = dns.Copy(a)
	b = dns.Copy(b)
	a.Header().Name = b.Header().Name
	a.Header().Class &^= qClassCacheFlush
	b.Header().Class &^= qClassCacheFlush
	return dns.IsDuplicate(a, b)
}

// Only authority records that answer the peer's question participate in its
// simultaneous probe. A different class or unrelated type is not a proposal
// for that question (RFC 6762 sections 6 and 8.2).
func probeAnswers(records []dns.RR, question dns.Question) []dns.RR {
	var answers []dns.RR
	class := question.Qclass & ^qClassCacheFlush
	for _, rr := range records {
		if rr == nil || !sameMDNSName(rr.Header().Name, question.Name) {
			continue
		}
		if class != dns.ClassANY && rr.Header().Class & ^qClassCacheFlush != class {
			continue
		}
		if question.Qtype != dns.TypeANY && rr.Header().Rrtype != question.Qtype && rr.Header().Rrtype != dns.TypeCNAME {
			continue
		}
		answers = append(answers, rr)
	}
	return answers
}

func (s *Server) observeProbe(msg *dns.Msg, index int, p *interfaceProbe, now time.Time) {
	if p.sent == 0 {
		return
	}
	proposed := s.proposedRecords(index)
	for _, q := range msg.Question {
		if q.Qclass & ^qClassCacheFlush != dns.ClassINET && q.Qclass & ^qClassCacheFlush != dns.ClassANY {
			continue
		}
		own, err := recordSet(probeAnswers(proposed, q), q.Name)
		if err != nil || len(own) == 0 {
			continue
		}
		other, err := recordSet(probeAnswers(msg.Ns, q), q.Name)
		if err != nil || len(other) == 0 {
			continue
		}
		if compareRecordSets(own, other) < 0 {
			p.restart(now, time.Second)
			s.notifyProbe()
			return
		}
	}
}

func (s *Server) observeResponse(msg *dns.Msg, index int, p *interfaceProbe, now time.Time) error {
	proposed := s.proposedRecords(index)
	var advertised dns.Msg
	s.composeLookupAnswers(&advertised, s.ttl, index, true)
	all := append(append(append([]dns.RR{}, msg.Answer...), msg.Ns...), msg.Extra...)
	refresh := false
	for _, remote := range all {
		if remote == nil || remote.Header().Class & ^qClassCacheFlush != dns.ClassINET {
			continue
		}
		h := remote.Header()
		identical := false
		relevant := false
		for _, own := range proposed {
			if !sameMDNSName(h.Name, own.Header().Name) {
				continue
			}
			if !p.established || h.Rrtype == own.Header().Rrtype {
				relevant = true
			}
			if identicalRecord(own, remote) {
				identical = true
				if p.established && h.Ttl > 0 && h.Ttl < own.Header().Ttl/2 {
					refresh = true
				}
				break
			}
		}
		if !identical {
			for _, own := range advertised.Answer {
				if identicalRecord(own, remote) {
					identical = true
					break
				}
			}
		}
		if h.Ttl == 0 {
			if p.established {
				for _, own := range advertised.Answer {
					if identicalRecord(own, remote) {
						refresh = true
						break
					}
				}
			}
			continue
		}
		if identical || !relevant || (!p.established && p.sent == 0) {
			continue
		}
		if p.established {
			p.restart(now, 0)
			s.notifyProbe()
			return nil
		}
		err := &ConflictError{Name: h.Name, InterfaceIndex: index}
		s.stopLocked(err)
		return err
	}
	if refresh {
		if err := s.announce(index, s.ttl); err != nil {
			s.stopLocked(err)
			return err
		}
	}
	return nil
}
