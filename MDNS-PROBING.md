# Registration establishment and conflicts

`Register` and `RegisterProxy` return after opening the transport and starting
registration. Their signatures and nonblocking behavior are unchanged. Use
`Server.WaitForReady(ctx)` to obtain the initial establishment result across all
selected interfaces. Canceling this wait does not cancel registration.

After initial success, monitor `Server.Done()` and inspect `Server.Err()` for a
terminal failure. The initial readiness result remains unchanged by later failure.
`ConflictError` identifies the contested name and interface. Normal `Shutdown`
leaves `Err()` nil; shutdown before readiness returns `ErrServerClosed` to waiters.
The library does not choose replacement names.

Each selected interface has independent probing and announcement state. Ordinary
registration uses that interface's addresses; proxy registration keeps its
explicit address data. A terminal failure on one required interface stops the
whole registration and withdraws records already established on other links.
During reprobes the affected interface suppresses responses
and TXT announcements. Text updates during initial probing restart that sequence without shortening
a pending startup delay or conflict retry.

Windows currently lacks receive-interface metadata in the pinned x/net version.
The current draft rejects multiple-interface registration there. This restriction
is not approved and remains under investigation. Windows exposes packet
information natively, and Go 1.21 supports receiving its control data through
UDPConn.ReadMsgUDP; preserving multiple-interface support is the intended result.
Socket/packet errors are reported through the lifecycle API. A family with no
usable interface address is not opened.

Default multicast integration tests use the standard mDNS groups on an ephemeral
test port. GitHub-hosted macOS runs skip these tests because the runner has no
route to the standard group; local macOS, self-hosted macOS, and other supported
runners run them when an active IPv4 multicast interface is available. Native
responder tests require `-tags interop`, a specific `ZEROCONF_INTEROP_INTERFACE`, and a
`-run` filter selecting only the interoperability test. They publish synthetic
names. `ZEROCONF_INTEROP_CAPTURE` optionally records only these test DNS wire
packets with source and interface metadata through an ordinary UDP listener.

## Protocol and reference mapping

The normative reference is [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762.html):

| Section | Implementation |
| --- | --- |
| 8.1 | Probe unique names with ANY questions and proposed data; delay startup and space probes by 250 ms. Use three with unicast defence, five when sharing the port. |
| 8.2 | Match authority records to question name/class/type, sort class/type/uncompressed RDATA, remove duplicates, and compare complete lists; the loser waits one second. |
| 8.1 | Fifteen conflicts within ten seconds impose at least five seconds between further attempts. |
| 9 | Established conflicts return to probing; a subsequent loss ends registration. |
| 6.6, 10.1 | Identical data cooperates; matching goodbyes refresh active records. |
| 6, 14 | Accept responses only from the mDNS source port; maintain link-specific state and addresses. |
| 15.1 | Avoid QU requests when another socket already occupies the multicast port. |

Avahi revision `3ed8102c8a881e6fe273bbf06f45e86dccf51e02` was inspected as
reference behavior. Its `announce.c` tracks group establishment and per-interface
announcers. Its `server.c` withdraws initial collisions, reprobes established
conflicts, and refreshes identical goodbye records. Its simultaneous-probe path
processes individual authority records, unlike the RFC's complete sorted-list
comparison. This implementation follows the RFC list comparison. No Avahi C
source is incorporated.

## Native interoperability evidence

Controlled tests use Avahi 0.8 (Debian package 0.8-10+deb12u1) and Bonjour
2881.160.4. They check native discovery, a fresh SRV query after unsolicited
announcements stop, withdrawal, and collision with an established native service.
The collision phase allows the native startup announcement sequence to finish.

The original same-host collision experiment failed when library probing started
during Bonjour startup announcements. A controlled diagnostic then sent three
multicast-only probes immediately after an observed native announcement. In three
runs there was no defence within 750 ms; a legacy unicast query also timed out
before one second. The same multicast probe was answered about 2.1 seconds after
the announcement. This is direct evidence of a response timing gap, not proof of
the installed daemon's internal cause.

When the port is shared and unicast defence cannot be received reliably, the
library now sends two further multicast probes, still 250 ms apart. It stays
tentative until 250 ms after the fifth probe. This adds 500 ms to establishment,
and rejected the original two-second-start Bonjour collision in three runs.
The unicast-capable path retains the usual three probes. Register and
RegisterProxy remain nonblocking; no cached announcement is used as conflict
proof. Startup delay, simultaneous-probe retry and excessive-conflict delays are
unchanged.

RFC 6762 section 8.1 permits announcing after the third probe; it does not require
immediate announcement. The additional multicast-only probes are an intentional
compatibility mitigation, not an RFC requirement. Packet format, probe spacing,
tentative-state restrictions, and deferral to live conflicting responses apply
throughout the extended sequence. Native Windows validation and broader Windows
transport work are still incomplete.
