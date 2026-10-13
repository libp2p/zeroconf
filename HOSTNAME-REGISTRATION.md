# Standalone multicast hostname registration

RegisterHostname publishes a fully qualified hostname without registering a service.
The final dot is optional. The API does not infer a domain or the system hostname.

```go
server, err := zeroconf.RegisterHostname("device.local.", []string{"192.0.2.10"}, nil)
if err != nil {
    return err
}
defer server.Shutdown()
if err := server.WaitForReady(ctx); err != nil {
    return err
}
```

Explicit IP addresses select published IPv4, IPv6 or dual-stack records. With an
empty IP list, addresses are discovered on the selected interfaces using the same
selection as Register. Empty interfaces selects multicast-capable interfaces. Each
selected interface must have usable addresses when discovery is requested.

The registration answers hostname questions and announces A/AAAA records, with NSEC
when an address family is absent. It publishes no service PTR, SRV or TXT records.
Shutdown withdraws established hostname records. SetText does nothing for a
hostname-only registration.

Registration returns before probing completes. WaitForReady reports initial
establishment on all selected links. Canceling the wait does not stop registration;
call Shutdown to cancel it. Done and Err expose subsequent terminal failures.
ConflictError identifies the name and interface. Names are not renamed automatically.
Protocol and timing behavior is the same as combined service registration.

Register and RegisterProxy still publish services together with target addresses.
Registrations remain independent: withdrawing one sends its established records'
goodbyes even if another registration publishes the same hostname. A remaining
identical responder refreshes matching records through the shared protocol engine.
No cross-registration reference counting is introduced.

This API publishes through local multicast DNS. UnicastDNS is a separate discovery
client option; RegisterHostname does not create authoritative DNS records or perform
DNS UPDATE. Multicast unicast-response requests use the shared server.
