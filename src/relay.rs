use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use quinn::{Connection, Endpoint, VarInt};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::auth::{MAX_TICKET_LEN, TicketClaims, TicketVerifier, peer_id_for_ip};
use crate::wire::WireFrame;

const AUTH_STREAM_LIMIT: usize = MAX_TICKET_LEN + 256;
const MAX_NETWORK_PEERS: usize = 100_000;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthRequest {
    pub ticket: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthResponse {
    pub accepted: bool,
    pub peer_id: u32,
    pub network_id: String,
}

#[derive(Clone)]
struct Peer {
    connection: Connection,
    stable_id: usize,
}

type Networks = Arc<RwLock<HashMap<String, HashMap<u32, Peer>>>>;

#[derive(Clone)]
pub struct Relay {
    verifier: TicketVerifier,
    networks: Networks,
}

impl Relay {
    pub fn new(verifier: TicketVerifier) -> Self {
        Self {
            verifier,
            networks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn serve(self, endpoint: Endpoint) -> Result<()> {
        info!(address = %endpoint.local_addr()?, "relay listening");
        while let Some(incoming) = endpoint.accept().await {
            let relay = self.clone();
            tokio::spawn(async move {
                match incoming.await {
                    Ok(connection) => {
                        if let Err(error) = relay.handle_connection(connection.clone()).await {
                            warn!(remote = %connection.remote_address(), %error, "connection rejected or closed");
                            connection.close(VarInt::from_u32(1), b"relay protocol error");
                        }
                    }
                    Err(error) => warn!(%error, "QUIC handshake failed"),
                }
            });
        }
        Ok(())
    }

    async fn handle_connection(&self, connection: Connection) -> Result<()> {
        let claims = self.authenticate(&connection).await?;
        self.register(&claims, &connection).await?;
        let stable_id = connection.stable_id();
        info!(network_id = %claims.network_id, peer_id = claims.peer_id, "peer authenticated");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before Unix epoch")?
            .as_secs();
        let ticket_lifetime = claims.exp.saturating_sub(now);
        if ticket_lifetime == 0 {
            bail!("ticket expired before relay registration");
        }
        let ticket_expiration = sleep(Duration::from_secs(ticket_lifetime));
        tokio::pin!(ticket_expiration);

        loop {
            let datagram = tokio::select! {
                _ = &mut ticket_expiration => {
                    info!(network_id = %claims.network_id, peer_id = claims.peer_id, "ticket lifetime ended");
                    connection.close(VarInt::from_u32(3), b"ticket expired");
                    break;
                }
                datagram = connection.read_datagram() => datagram,
            };
            match datagram {
                Ok(encoded) => {
                    let frame = match WireFrame::decode(encoded) {
                        Ok(frame) => frame,
                        Err(error) => {
                            warn!(network_id = %claims.network_id, peer_id = claims.peer_id, %error, "invalid frame dropped");
                            continue;
                        }
                    };
                    if frame.dst_peer == claims.peer_id {
                        warn!(network_id = %claims.network_id, peer_id = claims.peer_id, "self-directed frame dropped");
                        continue;
                    }
                    let frame = match normalize_routed_packet(&claims, frame) {
                        Ok(frame) => frame,
                        Err(error) => {
                            warn!(network_id = %claims.network_id, peer_id = claims.peer_id, %error, "invalid routed packet dropped");
                            continue;
                        }
                    };
                    let encoded = match frame.encode() {
                        Ok(encoded) => encoded,
                        Err(error) => {
                            warn!(network_id = %claims.network_id, peer_id = claims.peer_id, %error, "normalized frame dropped");
                            continue;
                        }
                    };
                    let target = self.lookup(&claims.network_id, frame.dst_peer).await;
                    if let Some(target) = target {
                        if target
                            .max_datagram_size()
                            .is_some_and(|limit| encoded.len() <= limit)
                        {
                            if let Err(error) = target.send_datagram(encoded) {
                                debug!(network_id = %claims.network_id, dst_peer = frame.dst_peer, %error, "datagram dropped by QUIC send buffer");
                            }
                        } else {
                            warn!(network_id = %claims.network_id, dst_peer = frame.dst_peer, "peer does not support this datagram size");
                        }
                    }
                }
                Err(error) => {
                    debug!(network_id = %claims.network_id, peer_id = claims.peer_id, %error, "peer disconnected");
                    break;
                }
            }
        }

        self.unregister(&claims.network_id, claims.peer_id, stable_id)
            .await;
        Ok(())
    }

    async fn authenticate(&self, connection: &Connection) -> Result<TicketClaims> {
        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .context("missing authentication stream")?;
        let bytes = recv
            .read_to_end(AUTH_STREAM_LIMIT)
            .await
            .context("failed to read authentication request")?;
        let request: AuthRequest =
            serde_json::from_slice(&bytes).context("invalid authentication JSON")?;
        let claims = self.verifier.verify_once(&request.ticket).await?;
        let response = AuthResponse {
            accepted: true,
            peer_id: claims.peer_id,
            network_id: claims.network_id.clone(),
        };
        send.write_all(&serde_json::to_vec(&response)?).await?;
        send.finish()?;
        Ok(claims)
    }

    async fn register(&self, claims: &TicketClaims, connection: &Connection) -> Result<()> {
        let mut networks = self.networks.write().await;
        let network = networks.entry(claims.network_id.clone()).or_default();
        if network.len() >= MAX_NETWORK_PEERS && !network.contains_key(&claims.peer_id) {
            bail!("virtual network reached its peer limit");
        }
        if let Some(previous) = network.insert(
            claims.peer_id,
            Peer {
                connection: connection.clone(),
                stable_id: connection.stable_id(),
            },
        ) {
            previous
                .connection
                .close(VarInt::from_u32(2), b"peer replaced");
        }
        Ok(())
    }

    async fn lookup(&self, network_id: &str, peer_id: u32) -> Option<Connection> {
        self.networks
            .read()
            .await
            .get(network_id)
            .and_then(|network| network.get(&peer_id))
            .map(|peer| peer.connection.clone())
    }

    async fn unregister(&self, network_id: &str, peer_id: u32, stable_id: usize) {
        let mut networks = self.networks.write().await;
        let mut remove_network = false;
        if let Some(network) = networks.get_mut(network_id) {
            if network
                .get(&peer_id)
                .is_some_and(|peer| peer.stable_id == stable_id)
            {
                network.remove(&peer_id);
            }
            remove_network = network.is_empty();
        }
        if remove_network {
            networks.remove(network_id);
        }
    }
}

fn normalize_routed_packet(claims: &TicketClaims, mut frame: WireFrame) -> Result<WireFrame> {
    let mut packet = frame.payload.to_vec();
    if packet.len() < 28 || packet[0] >> 4 != 4 {
        bail!("payload is not a complete IPv4 UDP packet");
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len + 8 {
        bail!("IPv4 header length is invalid");
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len != packet.len() || packet[9] != 17 {
        bail!("only complete UDP packets are accepted");
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 {
        bail!("fragmented packets are not accepted");
    }
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let claimed_source: Ipv4Addr = claims.virtual_ip.parse().context("ticket IP is invalid")?;
    if peer_id_for_ip(claimed_source)? != claims.peer_id {
        bail!("ticket source does not match authenticated peer");
    }
    if peer_id_for_ip(destination)? != frame.dst_peer {
        bail!("packet destination does not match frame destination");
    }
    let udp_len = usize::from(u16::from_be_bytes([
        packet[header_len + 4],
        packet[header_len + 5],
    ]));
    if udp_len < 8 || header_len + udp_len != packet.len() {
        bail!("UDP length is invalid");
    }
    let source_port = u16::from_be_bytes([packet[header_len], packet[header_len + 1]]);
    let destination_port = u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]);
    if source_port == 0 || destination_port == 0 {
        bail!("UDP port zero is invalid");
    }

    // Android's VpnService can retain the Minecraft socket's physical source
    // address in packets captured by the narrow TUN. The authenticated ticket,
    // not that untrusted header, is the source of truth. Canonicalizing it here
    // keeps replies routable while still preventing peer spoofing. NetherNet
    // negotiates dynamic UDP ports after discovery, so restricting every packet
    // to 7551/19132/19133 breaks otherwise valid Bedrock sessions.
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    if source != claimed_source {
        packet[12..16].copy_from_slice(&claimed_source.octets());
        refresh_ipv4_udp_checksums(&mut packet, header_len, udp_len);
    }
    frame.payload = Bytes::from(packet);
    Ok(frame)
}

fn refresh_ipv4_udp_checksums(packet: &mut [u8], header_len: usize, udp_len: usize) {
    packet[10] = 0;
    packet[11] = 0;
    let header_checksum = internet_checksum(&[&packet[..header_len]]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    let udp_offset = header_len;
    let had_udp_checksum = packet[udp_offset + 6] != 0 || packet[udp_offset + 7] != 0;
    if !had_udp_checksum {
        return;
    }
    packet[udp_offset + 6] = 0;
    packet[udp_offset + 7] = 0;
    let udp_len_bytes = (udp_len as u16).to_be_bytes();
    let pseudo_tail = [0_u8, 17_u8];
    let checksum = internet_checksum(&[
        &packet[12..20],
        &pseudo_tail,
        &udp_len_bytes,
        &packet[udp_offset..udp_offset + udp_len],
    ]);
    let checksum = if checksum == 0 { u16::MAX } else { checksum };
    packet[udp_offset + 6..udp_offset + 8].copy_from_slice(&checksum.to_be_bytes());
}

fn internet_checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0_u32;
    let mut pending = None;
    for part in parts {
        for &byte in *part {
            if let Some(high) = pending.take() {
                sum += u32::from(u16::from_be_bytes([high, byte]));
            } else {
                pending = Some(byte);
            }
        }
    }
    if let Some(high) = pending {
        sum += u32::from(u16::from_be_bytes([high, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub async fn authenticate_client(connection: &Connection, ticket: String) -> Result<AuthResponse> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .context("failed to open authentication stream")?;
    let request = AuthRequest { ticket };
    send.write_all(&serde_json::to_vec(&request)?).await?;
    send.finish()?;
    let bytes = recv
        .read_to_end(AUTH_STREAM_LIMIT)
        .await
        .context("failed to read authentication response")?;
    let response: AuthResponse =
        serde_json::from_slice(&bytes).context("invalid authentication response")?;
    if !response.accepted {
        bail!("relay rejected authentication");
    }
    Ok(response)
}

pub fn bytes(data: &[u8]) -> Bytes {
    Bytes::copy_from_slice(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> TicketClaims {
        TicketClaims {
            iss: "flipple-control-plane".into(),
            aud: "flipple-multiplayer-relay".into(),
            network_id: "public-v1".into(),
            lease_id: "00000000-0000-4000-8000-000000000001".into(),
            peer_id: 1,
            role: "member".into(),
            virtual_ip: "100.64.0.1".into(),
            exp: u64::MAX,
            jti: "test-ticket".into(),
            protocol_version: 2,
        }
    }

    fn udp_packet(source_port: u16, destination_port: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        let packet_len = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[100, 64, 0, 1]);
        packet[16..20].copy_from_slice(&[100, 64, 0, 2]);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..26].copy_from_slice(&8u16.to_be_bytes());
        packet
    }

    #[test]
    fn accepts_nethernet_dynamic_ports_and_canonicalizes_source() {
        let nethernet = WireFrame::new(2, 1, bytes(&udp_packet(7551, 7551))).unwrap();
        assert!(normalize_routed_packet(&claims(), nethernet).is_ok());

        let dynamic = WireFrame::new(2, 2, bytes(&udp_packet(49_152, 37_777))).unwrap();
        assert!(normalize_routed_packet(&claims(), dynamic).is_ok());

        let mut physical_source = udp_packet(49_152, 37_777);
        physical_source[12..16].copy_from_slice(&[192, 168, 1, 25]);
        let normalized = normalize_routed_packet(
            &claims(),
            WireFrame::new(2, 3, bytes(&physical_source)).unwrap(),
        )
        .unwrap();
        assert_eq!(&normalized.payload[12..16], &[100, 64, 0, 1]);
    }

    #[test]
    fn refreshes_ipv4_and_nonzero_udp_checksums_after_source_rewrite() {
        let mut packet = udp_packet(49_152, 37_777);
        packet[12..16].copy_from_slice(&[100, 64, 0, 1]);
        packet[26..28].copy_from_slice(&u16::MAX.to_be_bytes());
        refresh_ipv4_udp_checksums(&mut packet, 20, 8);

        assert_eq!(internet_checksum(&[&packet[..20]]), 0);
        let pseudo_tail = [0_u8, 17_u8];
        let udp_len = 8_u16.to_be_bytes();
        assert_eq!(
            internet_checksum(&[&packet[12..20], &pseudo_tail, &udp_len, &packet[20..28]]),
            0,
        );
    }
}
