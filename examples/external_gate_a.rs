use std::net::{Ipv4Addr, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use flipple_multiplayer_relay::client::RelayClient;
use flipple_multiplayer_relay::tls;
use tokio::time::timeout;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let relay = args.next().context("relay host:port is required")?;
    let server_name = args.next().context("TLS server name is required")?;
    let host_ticket = PathBuf::from(args.next().context("host ticket path is required")?);
    let guest_ticket = PathBuf::from(args.next().context("guest ticket path is required")?);
    ensure!(args.next().is_none(), "unexpected extra arguments");

    let relay = relay.to_string_lossy();
    let relay_address = relay
        .to_socket_addrs()
        .context("resolve relay")?
        .find(|address| address.is_ipv4())
        .context("relay has no IPv4 address")?;
    let server_name = server_name.to_string_lossy();
    let client_config = tls::public_client_config()?;
    let host = RelayClient::connect(
        UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?,
        relay_address,
        &server_name,
        std::fs::read_to_string(host_ticket)?.trim().to_owned(),
        client_config.clone(),
    )
    .await?;
    let guest = RelayClient::connect(
        UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?,
        relay_address,
        &server_name,
        std::fs::read_to_string(guest_ticket)?.trim().to_owned(),
        client_config,
    )
    .await?;

    ensure!(
        host.peer_id() == 1 && guest.peer_id() == 2,
        "unexpected peer ids"
    );
    ensure!(host.network_id() == guest.network_id(), "network mismatch");

    let host_packet = Bytes::from_static(&[
        0x45, 0, 0, 0x1c, 0, 1, 0, 0, 0x40, 0x11, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2, 0x4a, 0xbc,
        0x4a, 0xbc, 0, 8, 0, 0,
    ]);
    host.send_packet(2, 1, host_packet.clone())?;
    let received = timeout(Duration::from_secs(5), guest.receive_packet()).await??;
    ensure!(
        received.payload == host_packet,
        "host-to-guest payload mismatch"
    );

    let guest_packet = Bytes::from_static(&[
        0x45, 0, 0, 0x1c, 0, 2, 0, 0, 0x40, 0x11, 0, 0, 100, 64, 0, 2, 100, 64, 0, 1, 0x4a, 0xbc,
        0x4a, 0xbc, 0, 8, 0, 0,
    ]);
    guest.send_packet(1, 2, guest_packet.clone())?;
    let received = timeout(Duration::from_secs(5), host.receive_packet()).await??;
    ensure!(
        received.payload == guest_packet,
        "guest-to-host payload mismatch"
    );

    host.close();
    guest.close();
    println!("external Gate A passed over QUIC/TLS in both directions");
    Ok(())
}
