# Unicast DNS-SD discovery

Unicast discovery uses the PTR, SRV and TXT structure in [RFC 6763](https://www.rfc-editor.org/rfc/rfc6763.html). DNS resolvers supply A and AAAA records for each SRV target. It uses ordinary recursive DNS queries, with UDP and TCP fallback for truncated replies. Resolvers rejecting EDNS are retried with plain DNS. It does not register records or implement DNS UPDATE, DNS Push, browse-domain enumeration or a multicast reflector.

## Explicit transport selection

Existing callers retain multicast behaviour, including callers using a domain other than `local`. Select unicast explicitly through `UnicastDNS` and supply a discovery domain. Queries use absolute names, so no OS search-domain configuration is needed.

```go
// Multicast on the local network, with the existing API.
err := zeroconf.Browse(ctx, "_http._tcp", "local.", entries)

// Unicast using system DNS configuration.
err = zeroconf.Browse(ctx, "_http._tcp", "example.com.", entries,
    zeroconf.UnicastDNS(), zeroconf.Unannouncements())

// Unicast through an explicit resolver, also useful for controlled DNS tests.
err = zeroconf.Lookup(ctx, "Example", "_http._tcp", "example.com.", entries,
    zeroconf.UnicastDNS("192.0.2.53:53"))
```

Use a separate results channel for each call. Browse blocks until cancellation. Lookup retries until a usable result arrives or its context ends, then returns one entry containing all SRV candidates. Both close the results channel after discovery begins. Configuration errors return before taking ownership of that channel. Browse returns nil on cancellation, consistent with existing multicast Browse; Lookup returns its context error when canceled before resolution. Reads, writes, DNS queries and blocked result delivery honor cancellation and deadlines. Each resolver attempt has a two-second maximum; transient failures retry after one second.

The executable [unicast example](examples/unicast/client.go) consumes results concurrently and prints each candidate's priority and weight.

## Resolver configuration

Explicit resolver arguments are IP literals, optionally with a port. IPv6 with a port uses bracket notation, such as `[2001:db8::53]:53`. The default port is 53. Multiple addresses are tried in supplied order on query failure. Multicast and unspecified addresses are rejected.

Without explicit addresses:

| Platform | Configuration source |
| --- | --- |
| Linux and other Unix platforms | `/etc/resolv.conf`, including a system resolver stub if configured there |
| macOS | Built-in `/usr/sbin/scutil --dns`; selects the longest matching unscoped resolver domain, then the lowest resolver order; excludes mDNS and interface-scoped entries |
| Windows | `GetAdaptersAddresses` through the existing `golang.org/x/sys/windows` dependency; DNS addresses from active adapters, preserving IPv6 link-local scope IDs |

Resolver configuration is captured when discovery starts. Restart discovery to pick up changed configuration. Windows adapter enumeration does not implement NRPT or interface-specific DNS policy. On systems requiring those policies, supply an explicit resolver. macOS uses its built-in configuration utility, not Bonjour APIs, a newly installed daemon, cgo, Avahi or another dependency. This is DNS resolver discovery, not a claim to reproduce every platform's native resolver policy.

## Results and candidate selection

`ServiceEntry` retains the instance, service type and domain. `SRVCandidates` retains every SRV record with its own `HostName`, `Port`, `Priority`, `Weight`, `AddrIPv4` and `AddrIPv6`, including candidates whose addresses are temporarily unresolved. A negative AAAA answer does not suppress a valid A answer, and a negative A answer does not suppress AAAA. The first result requires at least one resolved candidate. Later updates can contain no usable addresses if address records disappear while the service remains advertised.

The legacy `HostName`, `Port`, `AddrIPv4` and `AddrIPv6` describe the first resolved candidate in deterministic priority/name/port/weight order. If a later update has no resolved candidate, hostname and port describe the first candidate with empty address lists. This order is for compatibility and stable change detection, not weighted endpoint selection. Use `SRVCandidates` for connection selection.

```go
for _, candidate := range entry.SRVCandidates {
    fmt.Printf("%s:%d priority=%d weight=%d IPv4=%v IPv6=%v\n",
        candidate.HostName, candidate.Port, candidate.Priority, candidate.Weight,
        candidate.AddrIPv4, candidate.AddrIPv6)
}
```

[RFC 2782](https://www.rfc-editor.org/rfc/rfc2782.html) defines target selection within an SRV record set: try the lowest reachable numeric priority first. For equal priority, its algorithm puts zero-weight records first, computes cumulative weights, and draws a random integer from zero through the total weight, inclusive. Select the first cumulative weight at least as large as that integer, remove that candidate, and repeat. This gives zero-weight records a small chance when positive weights exist. When all weights are zero, the initial ordering determines which candidate is chosen first; a caller can randomize that ordering. This library preserves the inputs and does not run a selection algorithm. An SRV target of `.` means the service is unavailable. SRV targets must not be aliases under RFC 2782; alias answers are treated as incomplete and retried.

SRV priority and weight apply within one instance's record set. They do not rank independently named service instances. Region selection is application policy. TXT strings are preserved without interpreting keys, case or values: `TXTRecords` preserves boundaries between separate TXT records, as required for the variants described in RFC 6763 section 6.8. `Text` contains the first record in deterministic string order for compatibility. Most services publish one TXT record.

Discovery does not perform health checks, capacity management, failover, automatic region selection or traffic balancing. For long-lived connections, caller selection affects new connections and reconnects. It does not move an existing connection or balance individual messages.

## Refresh, expiry and removal

Treat delivered entries as read-only snapshots. Each queried record set is refreshed at 80 percent of its shortest TTL. For negative answers, the cache lifetime is the smaller of the SOA TTL and SOA MINIMUM, following [RFC 2308](https://www.rfc-editor.org/rfc/rfc2308.html). Zero-TTL responses are usable in the current query cycle but are not reused in a later cycle. A 100 ms minimum retry interval prevents a tight loop. Record-order changes are normalized for SRV, address and TXT record sets. Material TXT, target, port, priority, weight or address changes produce a new entry. TTL renewal alone produces no duplicate result and does not mutate an entry already delivered to the caller.

`Expiry` is the earliest expiry of the record sets used to construct that event. It describes that snapshot, not a renewable caller-side lease. The library maintains renewed TTLs internally. An old event's expired timestamp alone does not prove that a service has disappeared.

Add `Unannouncements()` to receive removal events on the same channel. They contain `Removed == true` and an expired `Expiry`. Use `Removed` to distinguish them from positive results with TTL zero. Without this option, disappearance is silent, matching the existing opt-in multicast goodbye contract.

Removal requires a complete PTR response that no longer contains an instance, a usable NXDOMAIN/NODATA response for its SRV records, or an SRV target of `.`. The previous snapshot must also have expired. Empty responses without an applicable SOA, alias responses, timeouts, SERVFAIL and other transient failures do not prove removal. During failures the library retains previously known information without extending its DNS TTL. That information can be stale; callers needing a fresh lease or connection health must enforce their own policy. New information from successful independent queries can still update part of an entry during another query's failure.

## Verification and carried multicast changes

The fork has no Makefile; its workflow uses Go tests. Its Go 1.21 module pins a 2021 `x/net` version that does not link with the installed Go 1.25 linker. On the current macOS host, Go 1.21's internal linker also produces executables rejected by the OS for a missing `LC_UUID`. Tests are run with:

```sh
GOTOOLCHAIN=go1.21.13 go test -ldflags=-linkmode=external ./... -count=1 -timeout 90s
```

The external linker is a test-toolchain workaround on this host, not a runtime library dependency. Cross-compilation is distinct from executed platform tests. Native macOS resolver selection and deterministic DNS-server tests run locally; Windows and Linux resolver API integration are cross-compiled, not runtime-verified on those platforms.

Multicast integration tests use unique test hostnames, the standard mDNS multicast groups (`224.0.0.251` and `ff02::fb`), an ephemeral test port and one explicitly selected active IPv4 multicast interface. They skip if no such interface exists. On GitHub-hosted macOS, they skip because the runner has no route to the standard mDNS multicast group; local macOS and other supported runners run the tests. They do not register the computer's own hostname or bind to the system mDNS port. Multicast delivery on loopback did not work on this macOS host, so these tests use a single active interface. The previous test setup used `Register` and triggered a macOS hostname conflict on the development host; it has been replaced with `RegisterProxy` test registrations.

The fork includes LinkCast's carried corrections for opt-in mDNS goodbye events, cache TTL renewal, case-insensitive server matching, direct hostname queries and address-type NSEC answers. Existing LinkCast vendored files and dependency pins remain unchanged. Upstream PRs [#31](https://github.com/libp2p/zeroconf/pull/31) and [#39](https://github.com/libp2p/zeroconf/pull/39) cover related goodbye/TTL changes and should be considered when reviewing the contribution. Adopting this fork in applications is a separate task.
