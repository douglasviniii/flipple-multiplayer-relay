# Dedicated Linux relay deployment

This directory prepares a future dedicated Linux VM. It must not be installed
on SRV2022, the public Next.js host, or the legacy UDP relay.

## Required host state

- a dedicated Linux VM with a public IPv4 address;
- inbound and outbound UDP 443 allowed;
- `mc-relay.flipplearcade.com` pointing only to that VM;
- a public TLS certificate whose SAN contains that hostname;
- a non-login `flipple-relay` system user;
- the release binary at
  `/opt/flipple-multiplayer-relay/bin/flipple-multiplayer-relay`;
- `/etc/flipple-multiplayer-relay/relay.env` readable only by root and the
  service group.

The Ed25519 private signing key belongs only to the Next.js control plane. The
relay environment receives the public verification key and its `kid`; never
copy the private key to this VM.

## Reproducible build

Build on Linux from an audited commit:

```bash
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo build --locked --release
```

Copy `target/release/flipple-multiplayer-relay` to the path above, install the
unit as `/etc/systemd/system/flipple-multiplayer-relay.service`, then run:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now flipple-multiplayer-relay
sudo systemctl status flipple-multiplayer-relay --no-pager
sudo ss -lunp | grep ':443'
```

Do not enable the app feature from a successful process start alone. Gate A,
the control-plane ticket exchange, two-device Gate B and the later RakNet/game
gates must pass against the exact deployed commit first.
