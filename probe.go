package zeroconf

import (
	"bytes"
	"cmp"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// probeResult is the outcome of a probing round.
type probeResult int

const (
	probeDone     probeResult = iota // name is unique
	probeConflict                    // another host answered for the name
	probeLost                        // another host probes the same name and wins the tie-break
	probeShutdown
)

const (
	probeInterval = 250 * time.Millisecond

	// RFC 6762 section 8.1: after 15 conflicts within 10 seconds a host MUST
	// wait at least five seconds before each successive additional probe.
	maxProbeConflicts  = 15
	probeConflictDelay = 5 * time.Second
)

// probeState is the name being probed together with the records claimed for it.
type probeState struct {
	name    string   // service instance name in canonical presentation format
	records []dns.RR // authority section of the probe
}

// claimName probes for the service instance name and renames the instance
// until no other host claims it (RFC 6762 section 8, RFC 6763 appendix D).
// It returns false if the server is shut down while probing.
func (s *Server) claimName(timer *time.Timer) bool {
	base := s.service.Instance

	for n, conflicts := 2, 0; ; {
		switch s.probeName(timer) {
		case probeDone:
			s.probing.Store(false)
			return true

		case probeShutdown:
			return false

		case probeLost:
			// RFC 6762 section 8.2: defer for one second, then probe again
			if !s.sleep(timer, time.Second) {
				return false
			}

		case probeConflict:
			name := fmt.Sprintf("%s (%d)", base, n)
			n++
			log.Printf("[INFO] zeroconf: name %q already in use, renaming to %q", s.service.Instance, name)
			s.service.setInstance(name)

			if conflicts++; conflicts >= maxProbeConflicts && !s.sleep(timer, probeConflictDelay) {
				return false
			}
		}
	}
}

// probeName sends three probes 250ms apart and reports whether another host
// claimed the name in the meantime.
func (s *Server) probeName(timer *time.Timer) probeResult {
	state := s.newProbeState()
	s.probeState.Store(state)

	// discard results for a previous name
	select {
	case <-s.probeResult:
	default:
	}

	q := new(dns.Msg)
	q.SetQuestion(s.service.ServiceInstanceName(), dns.TypeANY)
	q.RecursionDesired = false
	q.Ns = state.records

	for i := 0; i < 3; i++ {
		if err := s.multicastResponse(q, 0); err != nil {
			log.Println("[ERR] zeroconf: failed to send probe:", err.Error())
		}

		timer.Reset(probeInterval)
		select {
		case <-timer.C:
		case res := <-s.probeResult:
			if !timer.Stop() {
				<-timer.C
			}
			return res
		case <-s.shouldShutdown:
			return probeShutdown
		}
	}

	return probeDone
}

// sleep waits for d and returns false if the server is shut down meanwhile.
func (s *Server) sleep(timer *time.Timer, d time.Duration) bool {
	timer.Reset(d)
	select {
	case <-timer.C:
		return true
	case <-s.shouldShutdown:
		return false
	}
}

func (s *Server) newProbeState() *probeState {
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
	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceInstanceName(),
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    s.ttl,
		},
		Txt: s.service.Text,
	}

	return &probeState{
		name:    canonicalName(s.service.ServiceInstanceName()),
		records: []dns.RR{srv, txt},
	}
}

// handleProbeMessage checks a message received while probing for a conflict
// with the probed name.
func (s *Server) handleProbeMessage(msg *dns.Msg) {
	state := s.probeState.Load()
	if state == nil {
		return
	}

	var res probeResult
	if msg.Response {
		// RFC 6762 section 8.1: any response containing a record with the probed name is a conflict
		if len(state.named(msg.Answer)) == 0 && len(state.named(msg.Extra)) == 0 {
			return
		}
		res = probeConflict
	} else {
		// RFC 6762 section 8.2: simultaneous probes, the lexicographically later data wins
		theirs := state.named(msg.Ns)
		if len(theirs) == 0 || compareRecords(state.records, theirs) >= 0 {
			return
		}
		res = probeLost
	}

	select {
	case s.probeResult <- res:
	default:
	}
}

// named returns the records owned by the probed name.
func (p *probeState) named(rrs []dns.RR) []dns.RR {
	var res []dns.RR
	for _, rr := range rrs {
		if strings.EqualFold(rr.Header().Name, p.name) {
			res = append(res, rr)
		}
	}
	return res
}

// compareRecords compares two record sets as described in RFC 6762 section 8.2.
func compareRecords(a, b []dns.RR) int {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.SortFunc(a, compareRecord)
	slices.SortFunc(b, compareRecord)

	for i := 0; i < len(a) && i < len(b); i++ {
		if c := compareRecord(a[i], b[i]); c != 0 {
			return c
		}
	}
	return cmp.Compare(len(a), len(b))
}

// compareRecord orders records by class, type and raw rdata.
func compareRecord(a, b dns.RR) int {
	ha, hb := a.Header(), b.Header()
	if c := cmp.Compare(ha.Class&^qClassCacheFlush, hb.Class&^qClassCacheFlush); c != 0 {
		return c
	}
	if c := cmp.Compare(ha.Rrtype, hb.Rrtype); c != 0 {
		return c
	}
	return bytes.Compare(rdata(a), rdata(b))
}

// rdata returns the uncompressed wire format rdata of rr.
func rdata(rr dns.RR) []byte {
	// packing updates the header, the records are shared with the probe sender
	rr = dns.Copy(rr)

	buf := make([]byte, dns.Len(rr))
	off, err := dns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		return nil
	}

	// rdata follows the owner name and 10 bytes of type, class, ttl and rdlength
	name := make([]byte, 256)
	n, err := dns.PackDomainName(rr.Header().Name, name, 0, nil, false)
	if err != nil {
		return nil
	}

	return buf[n+10 : off]
}

// canonicalName returns name in the escaped presentation format of received messages.
func canonicalName(name string) string {
	buf := make([]byte, 256)
	off, err := dns.PackDomainName(name, buf, 0, nil, false)
	if err != nil {
		return name
	}
	res, _, err := dns.UnpackDomainName(buf[:off], 0)
	if err != nil {
		return name
	}
	return res
}
