# Flipple Minecraft relay wire protocol v2

The client connects with QUIC/TLS 1.3 and ALPN `flipple-mc/2`, then sends one
length-bounded JSON authentication request on a bidirectional stream. A valid
Ed25519 ticket contains `network_id`, `lease_id`, `peer_id`, `role=member`,
`virtual_ip`, `exp`, `jti`, and `protocol_version=2`.

Each QUIC DATAGRAM contains exactly one complete raw IPv4 packet:

| Field | Bytes | Encoding |
| --- | ---: | --- |
| protocol version | 1 | unsigned, value 2 |
| flags | 1 | unsigned, value 0 |
| destination peer | 4 | unsigned, network byte order |
| sequence | 4 | unsigned, network byte order |
| IPv4 packet | remainder | complete packet, never truncated |

The total datagram is at most 1200 bytes. The relay accepts only unfragmented
IPv4 UDP where:

- the source IP equals the authenticated ticket IP and maps to its peer ID;
- the destination IP maps to the frame destination peer;
- source or destination UDP port is 19132 or 19133;
- the target peer is connected to the same `network_id`.

Broadcast discovery is synthesized by Android from the authenticated control
plane world list. It is never fanned out blindly by the relay.
