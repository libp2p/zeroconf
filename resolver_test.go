package zeroconf

import (
	"context"
	"net"
	"reflect"
	"runtime"
	"testing"
)

func TestDarwinResolverSelection(t *testing.T) {
	output := `DNS configuration
resolver #1
 nameserver[0] : 192.0.2.1
resolver #2
 domain : example.test
 nameserver[0] : 192.0.2.2
 order : 200
resolver #3
 domain : example.test
 nameserver[0] : 192.0.2.3
 order : 100
resolver #4
 domain : child.example.test
 nameserver[0] : 2001:db8::1
resolver #5
 domain : local
 options : mdns
 nameserver[0] : 224.0.0.251
DNS configuration (for scoped queries)
resolver #1
 nameserver[0] : 192.0.2.99
`
	groups := parseDarwinResolvers(output)
	for name, want := range map[string][]string{
		"other.test.":              {"192.0.2.1:53"},
		"HOST.EXAMPLE.TEST.":       {"192.0.2.3:53"},
		"host.child.example.test.": {"[2001:db8::1]:53"},
		"notexample.test.":         {"192.0.2.1:53"},
		"local.":                   {"192.0.2.1:53"},
	} {
		if got := selectResolvers(groups, name); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: %v, want %v", name, got, want)
		}
	}
}

func TestSystemResolverConfiguration(t *testing.T) {
	selectServers, err := systemResolvers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	servers := selectServers("example.test.")
	if len(servers) == 0 {
		t.Fatal("no resolvers")
	}
	for _, server := range servers {
		if _, err := resolverAddress(server); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("executed native %s resolver selection: %v", runtime.GOOS, servers)
}

func TestResolverAddressesAndWindowsScope(t *testing.T) {
	for address, want := range map[string]string{"192.0.2.1": "192.0.2.1:53", "2001:db8::1": "[2001:db8::1]:53", "[fe80::1%3]:53": "[fe80::1%3]:53", "127.0.0.1:1053": "127.0.0.1:1053"} {
		got, err := resolverAddress(address)
		if err != nil || got != want {
			t.Fatalf("%q: %q %v", address, got, err)
		}
	}
	if got := scopedIPv6(net.ParseIP("fe80::1"), 3); got != "fe80::1%3" {
		t.Fatal(got)
	}
	if _, err := fixedResolvers(nil); err == nil {
		t.Fatal("empty resolvers accepted")
	}
}
