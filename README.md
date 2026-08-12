# Flipple Multiplayer Relay

Private relay for the hidden Minecraft Bedrock LAN-over-QUIC proof of concept.

This repository does not run a Bedrock server. It routes encrypted, authenticated raw IP
datagrams between one host Android and one guest Android. The world remains hosted by Minecraft
on the host phone.

## Current scope

- Wire protocol v1 with deterministic unit tests.
- Ed25519 compact JWT verification with one-time `jti`.
- QUIC/TLS 1.3 relay using Quinn and rustls.
- Maximum two peers per room and no persistence of packet payloads.
- Local Gate A harness before any VM or DNS deployment.

Not implemented yet: Android Rust/JNI client, RakNet discovery synthesis, Next/PostgreSQL control
plane, public VM, DNS, production certificates, metrics endpoint, or Google Play enablement.

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
files. See `contracts/` for the frozen Gate A protocol.

The hardened systemd template for a future dedicated Linux VM lives in
`deploy/`. It is preparation only and is not authorization to expose the relay
or enable the app feature.
