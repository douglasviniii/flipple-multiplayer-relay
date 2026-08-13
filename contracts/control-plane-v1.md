# Control plane contract v1 (superseded)

This manual room/invite contract is retained only for audit history. The
automatic virtual-network product uses `control-plane-v2.md`.

Status: API contract for the hidden POC. Endpoints are disabled unless
`MULTIPLAYER_POC_ENABLED=true`.

The Next/PostgreSQL control plane owns room state and signs short-lived Ed25519 tickets. The
relay receives only a public key and never queries PostgreSQL in the packet path.

Each active room owns one unique `/30` from `100.96.0.0/16`. Peer 1 receives
the first usable address and peer 2 the second. Closed or expired room subnets
may be reused after the control plane marks the previous room inactive.

## Endpoints

- `POST /api/v1/multiplayer/rooms`: create a room and host ticket.
- `POST /api/v1/multiplayer/rooms/{id}/join`: exchange a single-use invite for a guest ticket.
- `POST /api/v1/multiplayer/rooms/{id}/heartbeat`: extend room presence, not ticket expiry.
- `DELETE /api/v1/multiplayer/rooms/{id}`: close the room and invalidate future joins.

Every route requires Firebase authentication at the existing Next boundary. Invite codes are
stored only as hashes. PostgreSQL stores room/peer metadata and audit timestamps, never game
packets, residential addresses, or packet captures.

The relay ticket is a compact JWT with `alg=EdDSA`, `typ=JWT`, a rotating `kid`, issuer
`flipple-control-plane`, audience `flipple-multiplayer-relay`, and the claims listed in
`wire-v1.md`. Production private signing keys must not enter this repository or the relay host.
