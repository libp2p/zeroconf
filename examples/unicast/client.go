package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"

	"github.com/libp2p/zeroconf/v2"
)

func main() {
	domain := flag.String("domain", "example.com.", "explicit DNS discovery domain")
	service := flag.String("service", "_http._tcp", "service type")
	resolver := flag.String("resolver", "", "optional DNS resolver IP, optionally with a port")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	entries := make(chan *zeroconf.ServiceEntry)
	opts := []zeroconf.ClientOption{zeroconf.UnicastDNS(), zeroconf.Unannouncements()}
	if *resolver != "" {
		opts[0] = zeroconf.UnicastDNS(*resolver)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for entry := range entries {
			if entry.Removed {
				log.Printf("removed %s", entry.ServiceInstanceName())
				continue
			}
			log.Printf("instance=%s TXT=%q", entry.Instance, entry.TXTRecords)
			for _, candidate := range entry.SRVCandidates {
				log.Printf("target=%s port=%d priority=%d weight=%d IPv4=%v IPv6=%v", candidate.HostName, candidate.Port, candidate.Priority, candidate.Weight, candidate.AddrIPv4, candidate.AddrIPv6)
			}
			// Apply RFC 2782 selection to this instance's candidates when connecting.
			// Discovery does not select a region or rebalance established connections.
		}
	}()
	if err := zeroconf.Browse(ctx, *service, *domain, entries, opts...); err != nil {
		log.Fatal(err)
	}
	<-done
}
