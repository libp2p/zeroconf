package zeroconf

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type resolverGroup struct {
	domain    string
	addresses []string
	order     int
	mdns      bool
	scoped    bool
}

func selectResolvers(groups []resolverGroup, name string) []string {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	bestLength, bestOrder := -1, int(^uint(0)>>1)
	var addresses []string
	for _, group := range groups {
		domain := strings.TrimSuffix(strings.ToLower(group.domain), ".")
		if group.mdns || group.scoped || len(group.addresses) == 0 {
			continue
		}
		if domain != "" && name != domain && !strings.HasSuffix(name, "."+domain) {
			continue
		}
		if len(domain) > bestLength || (len(domain) == bestLength && group.order < bestOrder) {
			bestLength, bestOrder, addresses = len(domain), group.order, group.addresses
		}
	}
	return addresses
}

// parseDarwinResolvers reads scutil's unscoped DNS configuration, including
// supplemental domain resolvers. Search domains do not change absolute queries.
func parseDarwinResolvers(output string) []resolverGroup {
	var groups []resolverGroup
	var current *resolverGroup
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "DNS configuration (") {
			break
		}
		if strings.HasPrefix(line, "resolver #") {
			groups = append(groups, resolverGroup{})
			current = &groups[len(groups)-1]
			continue
		}
		if current == nil {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch {
		case key == "domain":
			current.domain = value
		case key == "order":
			current.order, _ = strconv.Atoi(value)
		case key == "options":
			current.mdns = strings.Contains(value, "mdns")
		case key == "flags":
			current.scoped = strings.Contains(value, "Scoped")
		case strings.HasPrefix(key, "nameserver["):
			if address, err := resolverAddress(value); err == nil {
				current.addresses = append(current.addresses, address)
			}
		}
	}
	return groups
}

func fixedResolvers(addresses []string) (func(string) []string, error) {
	var normalized []string
	for _, address := range addresses {
		value, err := resolverAddress(address)
		if err != nil {
			return nil, err
		}
		exists := false
		for _, previous := range normalized {
			if previous == value {
				exists = true
			}
		}
		if !exists {
			normalized = append(normalized, value)
		}
	}
	if len(normalized) == 0 {
		return nil, fmt.Errorf("no system unicast DNS resolvers configured")
	}
	return func(string) []string { return normalized }, nil
}

func scopedIPv6(ip net.IP, scope uint32) string {
	host := ip.String()
	if scope != 0 && ip.IsLinkLocalUnicast() {
		host += "%" + strconv.FormatUint(uint64(scope), 10)
	}
	return host
}
