# Flipple Multiplayer Relay

Private relay for the hidden Minecraft Bedrock LAN-over-QUIC proof of concept.

This repository does not run a Bedrock server. It routes encrypted, authenticated raw IP
datagrams between Android devices connected to the same Flipple virtual network. The world
remains hosted by Minecraft on the host phone; users never create a relay room manually.

## Current scope

- Wire protocol v2 with deterministic unit tests.
- Ed25519 compact JWT verification with one-time `jti`.
- QUIC/TLS 1.3 relay using Quinn and rustls.
- Multi-peer routing by authenticated virtual IPv4 address, with no persistence of packet payloads.
- Source-address anti-spoofing and Minecraft Bedrock UDP-port filtering.
- Local Gate A harness before any VM or DNS deployment.

Implemented locally: Android Rust/JNI client core and a PostgreSQL control-plane contract. Still
pending: RakNet discovery synthesis, public VM, DNS, production certificates, metrics endpoint,
two-device gameplay validation, and Google Play enablement.

## Development

Requirements: Rust 1.97.1 and a platform linker.

```powershell
cargo fmt --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

The executable requires a TLS certificate/key and a base64url Ed25519 public key:

```powershell
cargo run --release -- `
  --bind 127.0.0.1:4433 `
  --certificate dev-cert.pem `
  --private-key dev-key.pem `
  --ticket-key-id local-dev `
  --ticket-public-key BASE64URL_32_BYTES
```

Never commit TLS private keys, ticket signing keys, tokens, packet captures, or environment
files. Protocol v2 supersedes the original two-peer Gate A contract.

The hardened systemd template for a future dedicated Linux VM lives in
`deploy/`. It is preparation only and is not authorization to expose the relay
or enable the app feature.
