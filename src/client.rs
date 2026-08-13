use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use quinn::{ClientConfig, Connection, Endpoint, EndpointConfig, TokioRuntime, VarInt};
use tokio::time::timeout;

use crate::relay::authenticate_client;
use crate::wire::WireFrame;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(12);
const AUTH_TIMEOUT: Duration = Duration::from_secs(8);

/// QUIC data-plane client shared by the Android JNI bridge and deterministic tests.
///
/// Android must call `VpnService.protect(fd)` on `socket` before passing ownership
/// to this constructor. This type deliberately does not create its own socket so a
/// tunnel transport can never accidentally route itself back through the TUN.
#[derive(Clone)]
pub struct RelayClient {
    endpoint: Endpoint,
    connection: Connection,
    network_id: String,
    peer_id: u32,
}

impl RelayClient {
    pub async fn connect(
        socket: UdpSocket,
        relay_address: SocketAddr,
        server_name: &str,
        ticket: String,
        client_config: ClientConfig,
    ) -> Result<Self> {
        if server_name.trim().is_empty() || ticket.trim().is_empty() {
            bail!("relay server name and ticket are required");
        }
        socket
            .set_nonblocking(true)
            .context("set protected relay socket nonblocking")?;
        let mut endpoint = Endpoint::new(
            EndpointConfig::default(),
            None,
            socket,
            Arc::new(TokioRuntime),
        )
        .context("create QUIC client endpoint from protected socket")?;
        endpoint.set_default_client_config(client_config);

        let connection = timeout(
            CONNECT_TIMEOUT,
            endpoint
                .connect(relay_address, server_name)
                .context("prepare relay connection")?,
        )
        .await
        .context("relay connection timed out")?
        .context("relay QUIC handshake failed")?;
        let auth = timeout(AUTH_TIMEOUT, authenticate_client(&connection, ticket))
            .await
            .context("relay authentication timed out")??;

        Ok(Self {
            endpoint,
            connection,
            network_id: auth.network_id,
            peer_id: auth.peer_id,
        })
    }

    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    pub fn peer_id(&self) -> u32 {
        self.peer_id
    }

    pub fn send_packet(&self, destination_peer: u32, sequence: u32, packet: Bytes) -> Result<()> {
        if destination_peer == self.peer_id {
            bail!("cannot send a relay packet to the same peer");
        }
        let frame = WireFrame::new(destination_peer, sequence, packet)?;
        self.connection
            .send_datagram(frame.encode()?)
            .context("send QUIC datagram")
    }

    pub async fn receive_packet(&self) -> Result<WireFrame> {
        let encoded = self
            .connection
            .read_datagram()
            .await
            .context("read QUIC datagram")?;
        Ok(WireFrame::decode(encoded)?)
    }

    pub fn close(&self) {
        self.connection
            .close(VarInt::from_u32(0), b"client stopped");
        self.endpoint.close(VarInt::from_u32(0), b"client stopped");
    }
}

impl Drop for RelayClient {
    fn drop(&mut self) {
        self.close();
    }
}
