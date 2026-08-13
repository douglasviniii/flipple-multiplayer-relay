# Multiplayer automatic network control plane v2

Users opt in once. The Android foreground VPN obtains and renews a virtual
network lease; it does not expose rooms, roles, invites, or manual host setup.

Endpoints:

- `POST /api/v1/multiplayer/network`: create or renew the caller's network
  lease and issue a relay ticket.
- `POST /api/v1/multiplayer/network/heartbeat`: extend the lease and issue a
  replacement short-lived ticket.
- `DELETE /api/v1/multiplayer/network`: disconnect the caller and close its
  active world advertisement.
- `PUT /api/v1/multiplayer/network/world`: create or refresh the world detected
  from Minecraft's RakNet LAN pong.
- `DELETE /api/v1/multiplayer/network/world`: close the automatic advertisement.
- `GET /api/v1/multiplayer/network/worlds`: cursor-paginated discovery of
  currently active worlds, excluding the caller's own world.

PostgreSQL stores lease, structured world metadata, expiration, and audit
timestamps. It never stores relay tickets or packet payloads. Firebase is used
only at the existing authentication boundary.
