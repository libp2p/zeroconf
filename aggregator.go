package zeroconf

import (
	"log"
	"math/rand"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// RFC6762 Section 6: In any case where there may be multiple responses,
	// each responder SHOULD delay its response by a random amount of time
	// selected with uniform random distribution in the range 20-120 ms.
	// RFC6762 Section 6.3: For query messages containing more than one
	// question, all (non-defensive) answers SHOULD be randomly delayed in
	// the range 20-120 ms.
	responseMinDelay = 20 * time.Millisecond
	responseMaxDelay = 120 * time.Millisecond

	// RFC6762 Section 6.4: Earlier responses may be delayed by up to an
	// additional 500ms to permit aggregation with other responses scheduled
	// to go out a little later.
	responseMaxAggregationDelay = 500 * time.Millisecond
)

// pendingResp holds a pending multicast response awaiting aggregated delivery.
type pendingResp struct {
	msg       *dns.Msg
	firstSeen time.Time
	ifIndex   int
	timer     *time.Timer
}

// responseAggregator implements RFC6762 Section 6.4 Response Aggregation.
//
// RFC6762 Section 6.4 requires that a responder, for the sake of network
// efficiency, aggregate as many responses as possible into a single Multicast
// DNS response message. Earlier responses SHOULD be delayed by up to an
// additional 500ms if that will permit them to be aggregated with other
// responses.
//
// This reduces network traffic when many nodes are present on the network.
type responseAggregator struct {
	mu      sync.Mutex
	pending map[int]*pendingResp // ifIndex -> pending aggregated response
	server  *Server
}

func newResponseAggregator(s *Server) *responseAggregator {
	return &responseAggregator{
		pending: make(map[int]*pendingResp),
		server:  s,
	}
}

// schedule schedules a multicast response for aggregated delivery.
//
// RFC6762 Section 6.4: If a response for this interface is already pending
// within the aggregation window (500ms), the new response is merged into it
// rather than sending a separate packet. Otherwise, a new response is
// scheduled with a random delay of 20-120ms (RFC6762 Section 6 / 6.3).
func (a *responseAggregator) schedule(msg *dns.Msg, ifIndex int) {
	a.mu.Lock()

	// If there is already a pending response for this interface, try to merge.
	if existing, ok := a.pending[ifIndex]; ok {
		mergeMsg(existing.msg, msg)

		// If the first-seen time has already exceeded the max aggregation delay,
		// flush immediately (same behavior as before).
		elapsed := time.Since(existing.firstSeen)
		if elapsed >= responseMaxAggregationDelay {
			// Max aggregation delay exceeded: flush the existing response now
			existing.timer.Stop()
			delete(a.pending, ifIndex)
			a.mu.Unlock()
			if len(existing.msg.Answer) > 0 {
				if err := a.server.multicastResponse(existing.msg, existing.ifIndex); err != nil {
					log.Printf("[ERR] zeroconf: failed to send aggregated response: %v", err)
				}
			}
			return
		}

		// Otherwise, reschedule delivery from *now* by a random delay of 20-120ms.
		// However, do not delay beyond the remaining aggregation window.
		delay := responseMinDelay + time.Duration(rand.Int63n(int64(responseMaxDelay-responseMinDelay)))
		remaining := responseMaxAggregationDelay - elapsed
		if delay > remaining {
			delay = remaining
		}

		// Stop the previous timer (best-effort) and replace it with a new one.
		existing.timer.Stop()
		existing.timer = time.AfterFunc(delay, func() {
			a.mu.Lock()
			cur, ok := a.pending[ifIndex]
			if !ok || cur != existing {
				// Already flushed or superseded.
				a.mu.Unlock()
				return
			}
			delete(a.pending, ifIndex)
			a.mu.Unlock()

			if len(existing.msg.Answer) > 0 {
				if err := a.server.multicastResponse(existing.msg, existing.ifIndex); err != nil {
					log.Printf("[ERR] zeroconf: failed to send aggregated response: %v", err)
				}
			}
		})

		a.mu.Unlock()
		return
	}

	// RFC6762 Section 6 / 6.3: delay response by a random amount in [20ms, 120ms].
	delay := responseMinDelay + time.Duration(rand.Int63n(int64(responseMaxDelay-responseMinDelay)))

	newPending := &pendingResp{
		msg:       msg.Copy(),
		firstSeen: time.Now(),
		ifIndex:   ifIndex,
	}
	newPending.timer = time.AfterFunc(delay, func() {
		a.mu.Lock()
		cur, ok := a.pending[ifIndex]
		if !ok || cur != newPending {
			// Already flushed by another path.
			a.mu.Unlock()
			return
		}
		delete(a.pending, ifIndex)
		a.mu.Unlock()

		if len(newPending.msg.Answer) > 0 {
			if err := a.server.multicastResponse(newPending.msg, newPending.ifIndex); err != nil {
				log.Printf("[ERR] zeroconf: failed to send aggregated response: %v", err)
			}
		}
	})
	a.pending[ifIndex] = newPending
	a.mu.Unlock()
}

// shutdown cancels all pending responses without sending them.
// Must be called before closing the network connections.
func (a *responseAggregator) shutdown() {
	a.mu.Lock()
	defer a.mu.Unlock()

	for ifIndex, pending := range a.pending {
		pending.timer.Stop()
		delete(a.pending, ifIndex)
	}
}

// mergeMsg merges records from src into dst, skipping duplicates.
// RFC6762 Section 6.4: aggregate as many responses as possible into a single message.
func mergeMsg(dst, src *dns.Msg) {
	for _, rr := range src.Answer {
		if !containsRR(dst.Answer, rr) {
			dst.Answer = append(dst.Answer, rr)
		}
	}
	for _, rr := range src.Extra {
		// Do not add to Extra if already present in Answer or Extra.
		if !containsRR(dst.Answer, rr) && !containsRR(dst.Extra, rr) {
			dst.Extra = append(dst.Extra, rr)
		}
	}
}

// containsRR reports whether list contains a record equivalent to rr.
func containsRR(list []dns.RR, rr dns.RR) bool {
	for _, r := range list {
		if dns.IsDuplicate(r, rr) {
			return true
		}
	}
	return false
}
