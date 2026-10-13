package zeroconf

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// UnicastDNS explicitly selects ordinary DNS instead of multicast DNS.
// With no addresses, platform system resolvers are used. Addresses must be
// unicast IP literals, optionally with a port (default 53).
func UnicastDNS(resolvers ...string) ClientOption {
	addresses := append([]string(nil), resolvers...)
	return func(o *clientOpts) { o.unicast = true; o.resolvers = addresses }
}

type dnsAnswer struct {
	records  []dns.RR
	expiry   time.Time
	refresh  time.Time
	negative bool
	observed time.Time
}

type unicastClient struct {
	servers func(string) []string
	cache   map[dns.Question]*dnsAnswer
	used    map[dns.Question]bool
	cycle   time.Time
}

func resolverAddress(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host, port = address, "53"
	}
	zoneHost := strings.Split(host, "%")[0]
	ip := net.ParseIP(zoneHost)
	if ip == nil || ip.IsMulticast() || ip.IsUnspecified() {
		return "", fmt.Errorf("invalid unicast resolver IP: %q", address)
	}
	if _, err := net.LookupPort("udp", port); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, port), nil
}

func runUnicast(ctx context.Context, instance, service, domain string, entries chan<- *ServiceEntry, browsing bool, opts clientOpts) error {
	if domain == "" || entries == nil {
		return fmt.Errorf("unicast discovery requires a domain and results channel")
	}
	params := newLookupParams(instance, service, domain, browsing, entries)
	if _, ok := dns.IsDomainName(params.ServiceName()); !ok {
		return fmt.Errorf("invalid service name: %q", params.ServiceName())
	}
	var servers func(string) []string
	if len(opts.resolvers) > 0 {
		addresses := make([]string, 0, len(opts.resolvers))
		for _, address := range opts.resolvers {
			normalized, err := resolverAddress(address)
			if err != nil {
				return err
			}
			addresses = append(addresses, normalized)
		}
		servers = func(string) []string { return addresses }
	} else {
		var err error
		servers, err = systemResolvers(ctx)
		if err != nil {
			return err
		}
	}
	defer close(entries)
	c := &unicastClient{servers: servers, cache: make(map[dns.Question]*dnsAnswer)}
	sent := make(map[string]*ServiceEntry)
	for {
		if ctx.Err() != nil {
			return unicastContextError(ctx, browsing)
		}
		c.used = make(map[dns.Question]bool)
		c.cycle = time.Now()
		names := make(map[string]string)
		membershipKnown := false
		if browsing {
			name := params.ServiceName()
			if len(params.Subtypes) > 0 {
				name = params.Subtypes[0]
			}
			answer := c.query(ctx, name, dns.TypePTR)
			if answer != nil {
				membershipKnown = c.confirmed(answer)
				for _, record := range answer.records {
					ptr := record.(*dns.PTR)
					if dns.IsSubDomain(params.ServiceName(), ptr.Ptr) && !strings.EqualFold(ptr.Ptr, params.ServiceName()) {
						names[strings.ToLower(ptr.Ptr)] = ptr.Ptr
					}
				}
			}
		} else {
			names[strings.ToLower(params.ServiceInstanceName())] = params.ServiceInstanceName()
		}
		present := make(map[string]bool)
		for key, name := range names {
			entry, absent := c.resolve(ctx, name, params)
			if !absent {
				present[key] = true
			}
			if entry == nil {
				continue
			}
			if browsing {
				ptrName := params.ServiceName()
				if len(params.Subtypes) > 0 {
					ptrName = params.Subtypes[0]
				}
				if a := c.cache[dns.Question{Name: strings.ToLower(ptrName), Qtype: dns.TypePTR, Qclass: dns.ClassINET}]; a != nil {
					entry.Expiry = earlier(entry.Expiry, a.expiry)
				}
			}
			previous := sent[key]
			if previous == nil && len(entry.AddrIPv4)+len(entry.AddrIPv6) == 0 {
				continue
			}
			changed := previous == nil || !sameService(previous, entry)
			sent[key] = entry
			if changed {
				select {
				case entries <- entry:
				case <-ctx.Done():
					return unicastContextError(ctx, browsing)
				}
			}
			if !browsing {
				return nil
			}
		}
		now := time.Now()
		next := now.Add(time.Second)
		for key, previous := range sent {
			_, listed := names[key]
			confirmedAbsent := (listed && !present[key]) || (!listed && membershipKnown)
			if !confirmedAbsent {
				continue
			}
			if previous.Expiry.After(now) {
				if previous.Expiry.Before(next) {
					next = previous.Expiry
				}
				continue
			}
			delete(sent, key)
			if opts.unannouncements {
				removed := *previous
				removed.Removed = true
				removed.Expiry = now
				select {
				case entries <- &removed:
				case <-ctx.Done():
					return unicastContextError(ctx, browsing)
				}
			}
		}
		for q, a := range c.cache {
			if !c.used[q] {
				delete(c.cache, q)
				continue
			}
			if a.refresh.Before(next) {
				next = a.refresh
			}
		}
		delay := time.Until(next)
		if delay < 100*time.Millisecond {
			delay = 100 * time.Millisecond
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return unicastContextError(ctx, browsing)
		case <-timer.C:
		}
	}
}

func unicastContextError(ctx context.Context, browsing bool) error {
	if browsing {
		return nil
	}
	return ctx.Err()
}

func earlier(a, b time.Time) time.Time {
	if a.IsZero() || b.Before(a) {
		return b
	}
	return a
}

func sameService(a, b *ServiceEntry) bool {
	left, right := *a, *b
	left.Expiry, right.Expiry = time.Time{}, time.Time{}
	return reflect.DeepEqual(left, right)
}

// query retains old data on transient failures. It never extends that data's TTL.
func (c *unicastClient) query(ctx context.Context, name string, qtype uint16) *dnsAnswer {
	q := dns.Question{Name: strings.ToLower(dns.Fqdn(name)), Qtype: qtype, Qclass: dns.ClassINET}
	c.used[q] = true
	previous := c.cache[q]
	now := time.Now()
	if previous != nil && now.Before(previous.refresh) {
		return previous
	}
	for _, address := range c.servers(q.Name) {
		attempt, cancel := context.WithTimeout(ctx, 2*time.Second)
		m := new(dns.Msg)
		m.SetQuestion(q.Name, qtype)
		m.SetEdns0(1232, false)
		reply, err := exchangeDNS(attempt, m, address, "udp")
		if err == nil && reply != nil && (reply.Rcode == dns.RcodeFormatError || reply.Rcode == dns.RcodeNotImplemented || reply.Rcode == dns.RcodeBadVers) {
			// Some ordinary DNS resolvers do not support EDNS. Retry plain DNS.
			m.Extra = nil
			reply, err = exchangeDNS(attempt, m, address, "udp")
		}
		if err == nil && reply != nil && reply.Truncated {
			reply, err = exchangeDNS(attempt, m, address, "tcp")
		}
		cancel()
		if err != nil || reply == nil || reply.Truncated || !reply.Response || reply.Opcode != dns.OpcodeQuery || len(reply.Question) != 1 || reply.Question[0] != q {
			continue
		}
		answer, err := parseDNSAnswer(reply, q, time.Now())
		if err != nil {
			continue
		}
		c.cache[q] = answer
		return answer
	}
	if previous == nil {
		previous = &dnsAnswer{}
		c.cache[q] = previous
	}
	previous.refresh = time.Now().Add(time.Second)
	return previous
}

func parseDNSAnswer(m *dns.Msg, q dns.Question, now time.Time) (*dnsAnswer, error) {
	if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("DNS response: %s", dns.RcodeToString[m.Rcode])
	}
	a := &dnsAnswer{observed: now}
	var ttl uint32
	haveTTL := false
	for _, rr := range m.Answer {
		h := rr.Header()
		if h.Class != dns.ClassINET || h.Rrtype != q.Qtype || !strings.EqualFold(h.Name, q.Name) {
			continue
		}
		a.records = append(a.records, rr)
		if !haveTTL || h.Ttl < ttl {
			ttl = h.Ttl
			haveTTL = true
		}
	}
	if len(a.records) == 0 {
		// A CNAME is not proof of NODATA. SRV targets must not be aliases (RFC 2782).
		for _, rr := range m.Answer {
			if _, ok := rr.(*dns.CNAME); ok {
				return nil, fmt.Errorf("alias answer for %s", q.Name)
			}
		}
		for _, rr := range m.Ns {
			soa, ok := rr.(*dns.SOA)
			if !ok || soa.Hdr.Class != dns.ClassINET || !dns.IsSubDomain(soa.Hdr.Name, q.Name) {
				continue
			}
			ttl = soa.Hdr.Ttl
			if soa.Minttl < ttl {
				ttl = soa.Minttl
			}
			haveTTL = true
			a.negative = true
			break
		}
		if !haveTTL {
			return nil, fmt.Errorf("incomplete answer for %s", q.Name)
		}
	} else if m.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("records in negative answer for %s", q.Name)
	}
	a.expiry = now.Add(time.Duration(ttl) * time.Second)
	a.refresh = now.Add(time.Duration(ttl) * time.Second * 4 / 5)
	return a, nil
}

func (c *unicastClient) resolve(ctx context.Context, name string, params *lookupParams) (*ServiceEntry, bool) {
	srv := c.query(ctx, name, dns.TypeSRV)
	txt := c.query(ctx, name, dns.TypeTXT)
	if srv == nil || len(srv.records) == 0 {
		return nil, srv != nil && srv.negative && c.confirmed(srv)
	}
	instance := strings.TrimSuffix(name, ".")
	suffix := "." + strings.TrimSuffix(params.ServiceName(), ".")
	if len(instance) <= len(suffix) || !strings.EqualFold(instance[len(instance)-len(suffix):], suffix) {
		return nil, false
	}
	instance = instance[:len(instance)-len(suffix)]
	entry := newServiceEntry(instance, params.Service, params.Domain)
	entry.Expiry = srv.expiry
	if txt != nil {
		if len(txt.records) > 0 {
			// RFC 6763 section 6.8: a service normally has one TXT record.
			// Preserve each string without interpreting keys or values.
			for _, rr := range txt.records {
				entry.TXTRecords = append(entry.TXTRecords, append([]string(nil), rr.(*dns.TXT).Txt...))
			}
			sort.Slice(entry.TXTRecords, func(i, j int) bool {
				a, b := entry.TXTRecords[i], entry.TXTRecords[j]
				for k := 0; k < len(a) && k < len(b); k++ {
					if a[k] != b[k] {
						return a[k] < b[k]
					}
				}
				return len(a) < len(b)
			})
			entry.Text = append([]string(nil), entry.TXTRecords[0]...)
		}
		if !txt.expiry.IsZero() {
			entry.Expiry = earlier(entry.Expiry, txt.expiry)
		}
	}
	unavailable := true
	for _, rr := range srv.records {
		r := rr.(*dns.SRV)
		candidate := SRVCandidate{HostName: r.Target, Port: int(r.Port), Priority: r.Priority, Weight: r.Weight}
		if r.Target != "." {
			unavailable = false
			for _, family := range []uint16{dns.TypeA, dns.TypeAAAA} {
				answer := c.query(ctx, r.Target, family)
				if answer == nil {
					continue
				}
				for _, record := range answer.records {
					switch address := record.(type) {
					case *dns.A:
						candidate.AddrIPv4 = append(candidate.AddrIPv4, append(net.IP(nil), address.A...))
					case *dns.AAAA:
						candidate.AddrIPv6 = append(candidate.AddrIPv6, append(net.IP(nil), address.AAAA...))
					}
				}
				if len(answer.records) > 0 {
					entry.Expiry = earlier(entry.Expiry, answer.expiry)
				}
			}
		}
		sortIPs(candidate.AddrIPv4)
		sortIPs(candidate.AddrIPv6)
		entry.SRVCandidates = append(entry.SRVCandidates, candidate)
	}
	sort.Slice(entry.SRVCandidates, func(i, j int) bool {
		a, b := entry.SRVCandidates[i], entry.SRVCandidates[j]
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		if a.HostName != b.HostName {
			return a.HostName < b.HostName
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Weight < b.Weight
	})
	for _, candidate := range entry.SRVCandidates {
		if len(candidate.AddrIPv4)+len(candidate.AddrIPv6) == 0 {
			continue
		}
		entry.HostName, entry.Port = candidate.HostName, candidate.Port
		entry.AddrIPv4, entry.AddrIPv6 = candidate.AddrIPv4, candidate.AddrIPv6
		return entry, false
	}
	if unavailable {
		return nil, c.confirmed(srv)
	}
	if len(entry.SRVCandidates) > 0 {
		entry.HostName, entry.Port = entry.SRVCandidates[0].HostName, entry.SRVCandidates[0].Port
	}
	return entry, false
}

func sortIPs(addresses []net.IP) {
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].String() < addresses[j].String() })
}

// The pinned miekg/dns ExchangeContext only propagates deadlines, not cancellation.
func exchangeDNS(ctx context.Context, message *dns.Msg, address, network string) (*dns.Msg, error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			connection.Close()
		case <-done:
		}
	}()
	timeout := 2 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	response, _, err := (&dns.Client{Net: network, Timeout: timeout}).ExchangeWithConn(message, &dns.Conn{Conn: connection})
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return response, err
}

func (c *unicastClient) confirmed(answer *dnsAnswer) bool {
	return answer != nil && (time.Now().Before(answer.expiry) || !answer.observed.Before(c.cycle))
}
