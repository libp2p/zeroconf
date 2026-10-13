package zeroconf

import (
	"context"
	"fmt"
	"os/exec"
)

func systemResolvers(ctx context.Context) (func(string) []string, error) {
	output, err := exec.CommandContext(ctx, "/usr/sbin/scutil", "--dns").Output()
	if err != nil {
		return nil, fmt.Errorf("read macOS DNS configuration: %w", err)
	}
	groups := parseDarwinResolvers(string(output))
	usable := false
	for _, group := range groups {
		if !group.mdns && !group.scoped && len(group.addresses) > 0 {
			usable = true
		}
	}
	if !usable {
		return nil, fmt.Errorf("no system unicast DNS resolvers configured")
	}
	return func(name string) []string { return selectResolvers(groups, name) }, nil
}
