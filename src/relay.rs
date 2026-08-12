use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use quinn::{Connection, Endpoint, VarInt};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::auth::{MAX_TICKET_LEN, TicketClaims, TicketVerifier};
use crate::wire::WireFrame;

const AUTH_STREAM_LIMIT: usize = MAX_TICKET_LEN + 256;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthRequest {
    pub ticket: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthResponse {
    pub accepted: bool,
    pub peer_id: u16,
    pub room_id: String,
}

#[derive(Clone)]
struct Peer {
    connection: Connection,
    stable_id: usize,
}

type Rooms = Arc<RwLock<HashMap<String, HashMap<u16, Peer>>>>;

#[derive(Clone)]
pub struct Relay {
    verifier: TicketVerifier,
    rooms: Rooms,
}

impl Relay {
    pub fn new(verifier: TicketVerifier) -> Self {
        Self {
            verifier,
            rooms: Arc::new(RwLock::new(HashMap::new())),
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
        info!(room_id = %claims.room_id, peer_id = claims.peer_id, "peer authenticated");
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
                    info!(room_id = %claims.room_id, peer_id = claims.peer_id, "ticket lifetime ended");
                    connection.close(VarInt::from_u32(3), b"ticket expired");
                    break;
                }
                datagram = connection.read_datagram() => datagram,
            };
            match datagram {
                Ok(encoded) => {
                    let frame = match WireFrame::decode(encoded.clone()) {
                        Ok(frame) => frame,
                        Err(error) => {
                            warn!(room_id = %claims.room_id, peer_id = claims.peer_id, %error, "invalid frame dropped");
                            continue;
                        }
                    };
                    if frame.dst_peer == claims.peer_id {
                        warn!(room_id = %claims.room_id, peer_id = claims.peer_id, "self-directed frame dropped");
                        continue;
                    }
                    let target = self.lookup(&claims.room_id, frame.dst_peer).await;
                    if let Some(target) = target {
                        if target
                            .max_datagram_size()
                            .is_some_and(|limit| encoded.len() <= limit)
                        {
                            if let Err(error) = target.send_datagram(encoded) {
                                debug!(room_id = %claims.room_id, dst_peer = frame.dst_peer, %error, "datagram dropped by QUIC send buffer");
                            }
                        } else {
                            warn!(room_id = %claims.room_id, dst_peer = frame.dst_peer, "peer does not support this datagram size");
                        }
                    }
                }
                Err(error) => {
                    debug!(room_id = %claims.room_id, peer_id = claims.peer_id, %error, "peer disconnected");
                    break;
                }
            }
        }

        self.unregister(&claims.room_id, claims.peer_id, stable_id)
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
            room_id: claims.room_id.clone(),
        };
        send.write_all(&serde_json::to_vec(&response)?).await?;
        send.finish()?;
        Ok(claims)
    }

    async fn register(&self, claims: &TicketClaims, connection: &Connection) -> Result<()> {
        let mut rooms = self.rooms.write().await;
        let room = rooms.entry(claims.room_id.clone()).or_default();
        if room.len() >= 2 && !room.contains_key(&claims.peer_id) {
            bail!("POC room already has two peers");
        }
        if let Some(previous) = room.insert(
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

    async fn lookup(&self, room_id: &str, peer_id: u16) -> Option<Connection> {
        self.rooms
            .read()
            .await
            .get(room_id)
            .and_then(|room| room.get(&peer_id))
            .map(|peer| peer.connection.clone())
    }

    async fn unregister(&self, room_id: &str, peer_id: u16, stable_id: usize) {
        let mut rooms = self.rooms.write().await;
        let mut remove_room = false;
        if let Some(room) = rooms.get_mut(room_id) {
            if room
                .get(&peer_id)
                .is_some_and(|peer| peer.stable_id == stable_id)
            {
                room.remove(&peer_id);
            }
            remove_room = room.is_empty();
        }
        if remove_room {
            rooms.remove(room_id);
        }
    }
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
