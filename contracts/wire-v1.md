# Flipple Minecraft relay wire protocol v1

Status: frozen for Gate A on 27 July 2026. It is not a production protocol yet.

## Transport

- QUIC v1 with TLS 1.3 and ALPN `flipple-mc/1`.
- Application packets use QUIC DATAGRAM and may be lost or reordered.
- A frame must fit in one QUIC datagram. It is never fragmented or truncated.
- POC maximum frame size: 1200 bytes. Maximum raw IP payload: 1192 bytes.
- Control traffic and authentication use QUIC streams, never data frames.

## Data frame

All integer fields use network byte order.

| Offset | Size | Field | Value |
| --- | ---: | --- | --- |
| 0 | 1 | version | `1` |
| 1 | 1 | flags | `0` for a raw IP packet |
| 2 | 2 | destination peer | `1` host, `2` guest |
| 4 | 4 | sequence | wraps modulo 2^32 |
| 8 | N | payload | raw IPv4 packet read from the Android TUN |

Invalid versions, flags, destinations, empty payloads, and oversized frames are dropped. The
relay derives the source peer from the authenticated QUIC connection; clients cannot declare
or spoof a source peer in a frame.

The canonical interoperability vector is stored in `vectors/wire-v1.json`. Android and relay
implementations must both pass that vector before Gate B testing.

## Authentication stream

The client opens one bidirectional stream immediately after TLS and sends one JSON object, then
finishes its send side:

```json
{"ticket":"compact EdDSA JWT"}
```

The relay verifies the signature, claims, expiry, role mapping, and one-time `jti`, then replies:

```json
{"accepted":true,"peer_id":1,"room_id":"room-id"}
```

Ticket claims: `iss`, `aud`, `room_id`, `peer_id`, `role`, `virtual_ip`, `exp`, `jti`, and
`protocol_version`. Gate A accepts only host peer 1 at `100.96.0.1` and guest peer 2 at
`100.96.0.2`. Tickets live for at most five minutes and are consumed once.
