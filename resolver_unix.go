//go:build !windows && !darwin

package zeroconf

import (
	"context"
	"github.com/miekg/dns"
	"net"
)

func systemResolvers(ctx context.Context) (func(string) []string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	addresses := make([]string, 0, len(config.Servers))
	for _, server := range config.Servers {
		addresses = append(addresses, net.JoinHostPort(server, config.Port))
	}
	return fixedResolvers(addresses)
}
