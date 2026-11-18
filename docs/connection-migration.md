# Connection Migration and Flow Control

This document describes how quic-go handles connection migration (both
intentional migration and NAT rebinding), how the new network path is validated,
how congestion state is reset while connection-level flow-control credit is
preserved, and how send opportunities are shared fairly between streams during
a migration.

## Path validation

QUIC uses `PATH_CHALLENGE` and `PATH_RESPONSE` frames (RFC 9000, section 8.2)
to prove that a peer is reachable at a new address before migrating a connection
to that path.

### Intentional migration (client)

The client creates a new path with `Conn.AddPath` and probes it with
`Path.Probe`. The outgoing path manager (`path_manager_outgoing.go`) sends
`PATH_CHALLENGE` frames on the new transport and waits for a matching
`PATH_RESPONSE`.

- `Path.Switch` fails with `ErrPathNotValidated` until validation completes, so
  application data can never be sent on an unvalidated path.
- Probing uses exponential backoff. If no matching `PATH_RESPONSE` is received
  within `pathValidationTimeout` (5 seconds), `Path.Probe` returns
  `ErrPathValidationTimeout`, the path is removed and its connection ID is
  retired. A closed path returns `ErrPathClosed`.
- Only path probe packets (carrying `PATH_CHALLENGE`/`PATH_RESPONSE`) are sent
  on a path being probed; regular application data keeps using the active path.

### NAT rebinding and peer-initiated migration (server)

When the server receives a packet from an address that differs from the
connection's current remote address, the incoming path manager
(`path_manager.go`) creates a new path entry and starts validating it:

- The server sends `PATH_CHALLENGE` frames to the new address. It does not
  switch to the path, and does not send application data on it, until a matching
  `PATH_RESPONSE` is received and a non-probing packet arrives.
- Each unvalidated path carries a validation deadline
  (`pathValidationTimeout`). The run loop wakes at
  `pathManager.ValidationTimeout` and calls
  `pathManager.HandleValidationTimeout`, which closes every path that failed to
  validate in time and retires its connection ID. No application data is ever
  sent on a path that failed validation.
- A successful `PATH_RESPONSE` marks the path validated and clears its deadline.
  The connection only switches to the new path in response to the
  highest-numbered non-probing packet (RFC 9000, section 9.3).

## Anti-amplification

Before a client's address is validated, a server must not send more than three
times the number of bytes it received from that address (RFC 9000,
section 8.1.4). This limit is enforced by the sent packet handler
(`internal/ackhandler`) through `isAmplificationLimited`.

On a NAT rebinding the source address may be spoofed, so bytes received on the
old path cannot count towards the new path's anti-amplification budget:

- `SentPacketHandler.ResetPeerAddressValidation` re-enables the limit and starts
  the new path with a fresh byte budget. It is called when the server first
  observes a packet from a new, unvalidated address.
- `SentPacketHandler.PeerAddressValidated` lifts the limit once path validation
  (a matching `PATH_RESPONSE`) completes.
- Anti-amplification is a server-side concept; both methods are no-ops for a
  client.

## Congestion state on path switch

When the connection switches to a validated path, `MigratedPath` is called on
the sent packet handler:

- The RTT statistics are reset for the new path and the congestion controller is
  recreated (`congestion.NewRenoSender`), starting from the initial congestion
  window. Packets still in flight on the old path are declared lost and queued
  for retransmission, so no stream data is lost.
- ECN validation is restarted for the new path, and path MTU discovery is reset.

Connection-level flow-control credit is intentionally **not** reset. The
connection flow controller (`flow_controller_connection.go`) tracks the total
number of bytes the peer authorized with `MAX_DATA` independently of the
network path, so the send window and the already-consumed offsets survive a
migration unchanged. Only congestion/RTT state, which is path-specific, is
reset.

## Fair stream scheduling during migration

Right after a path switch the congestion window is small (the initial window),
so only a few packets can be in flight. Without per-stream accounting a single
large stream could fill the whole window on every packet, starving the other
streams for the duration of the ramp-up.

The framer therefore enables a migration fairness scheduler
(`migration_fairness.go`) while a migration is in progress:

- `framer.BeginMigration` starts a fairness round when path probing begins
  (client) or a new remote address is observed (server); `framer.EndMigration`
  stops it once the connection has switched to the validated path.
- Each incremental stream gets a per-round byte budget
  (`migrationFairnessBudget`, four full-size STREAM frames). A stream that used
  up its budget is re-queued behind the others and skipped until every active
  stream has had a turn, at which point a new round starts.
- This keeps the existing urgency-based priority scheduling and round-robin
  behavior; it only adds an additional fairness bound while the congestion
  window is being rebuilt. The scheduler self-disables after a safety timeout if
  a completion signal is ever missed.
- Retransmissions still take precedence over new data, and non-incremental
  (priority) streams keep their existing scheduling semantics.

## Error handling

- Path validation timeout: `ErrPathValidationTimeout`; the path is closed and
  its connection ID retired.
- Switching to an unvalidated path: `ErrPathNotValidated`.
- Using a path after it was closed: `ErrPathClosed`.

Errors are surfaced rather than swallowed, and the connection never sends
application data on an unvalidated or failed path. The existing `Conn`,
`SendStream`, `ReceiveStream` and `Stream` interfaces are unchanged.
