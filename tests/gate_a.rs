use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ed25519_dalek::{Signer, SigningKey};
use flipple_multiplayer_relay::PROTOCOL_VERSION;
use flipple_multiplayer_relay::auth::{
    EXPECTED_AUDIENCE, EXPECTED_ISSUER, TicketClaims, TicketHeader, TicketVerifier,
};
use flipple_multiplayer_relay::client::RelayClient;
use flipple_multiplayer_relay::relay::{Relay, authenticate_client};
use flipple_multiplayer_relay::tls;
use flipple_multiplayer_relay::wire::WireFrame;
use quinn::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use quinn::{Connection, Endpoint};
use tokio::time::timeout;

const KEY_ID: &str = "gate-a-2026-01";
const SIGNING_KEY: [u8; 32] = [0x42; 32];

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeTicketFixture {
    generated_by: String,
    public_key: String,
    token: String,
}

#[test]
fn accepts_node_crypto_ed25519_ticket_contract() {
    let fixture: NodeTicketFixture =
        serde_json::from_str(include_str!("fixtures/node-ed25519-ticket.json")).unwrap();
    assert_eq!(fixture.generated_by, "node:crypto");

    let public_key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(fixture.public_key)
        .unwrap()
        .try_into()
        .unwrap();
    let segments: Vec<_> = fixture.token.split('.').collect();
    assert_eq!(segments.len(), 3);
    let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(segments[2]).unwrap()).unwrap();
    VerifyingKey::from_bytes(&public_key)
        .unwrap()
        .verify(
            format!("{}.{}", segments[0], segments[1]).as_bytes(),
            &signature,
        )
        .unwrap();

    let claims: TicketClaims =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[1]).unwrap()).unwrap();
    assert_eq!(claims.network_id, "public-v1");
    assert_eq!(claims.lease_id, "44444444-4444-4444-8444-444444444444");
    assert_eq!(claims.peer_id, 1);
    assert_eq!(claims.role, "member");
    assert_eq!(claims.virtual_ip, "100.64.0.1");
    assert_eq!(claims.protocol_version, PROTOCOL_VERSION);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gate_a_routes_raw_ip_datagrams_in_both_directions() {
    let signing_key = SigningKey::from_bytes(&SIGNING_KEY);
    let verifier = TicketVerifier::new(KEY_ID, signing_key.verifying_key().to_bytes()).unwrap();

    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate_der = CertificateDer::from(certificate.cert);
    let private_key = PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der());
    let server = Endpoint::server(
        tls::server_config(vec![certificate_der.clone()], private_key.into()).unwrap(),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .unwrap();
    let relay_address = server.local_addr().unwrap();
    let relay_task = tokio::spawn(Relay::new(verifier).serve(server));

    let (host_endpoint, host) = connect_peer(relay_address, certificate_der.clone(), 1).await;
    let (guest_endpoint, guest) = connect_peer(relay_address, certificate_der.clone(), 2).await;
    let (third_endpoint, third) = connect_peer(relay_address, certificate_der, 3).await;

    let spoofed_packet = Bytes::from_static(&[
        0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 0x40, 0x11, 0, 0, 100, 64, 0, 3, 100, 64, 0, 2, 0x4a,
        0xbc, 0x4a, 0xbc, 0, 8, 0, 0,
    ]);
    host.send_datagram(
        WireFrame::new(2, 6, spoofed_packet)
            .unwrap()
            .encode()
            .unwrap(),
    )
    .unwrap();
    assert!(
        timeout(Duration::from_millis(150), guest.read_datagram())
            .await
            .is_err()
    );

    let host_packet = Bytes::from_static(&[
        0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 0x40, 0x11, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2, 0x4a,
        0xbc, 0x4a, 0xbc, 0, 8, 0, 0,
    ]);
    let outbound = WireFrame::new(2, 7, host_packet.clone()).unwrap();
    host.send_datagram(outbound.encode().unwrap()).unwrap();
    let received = timeout(Duration::from_secs(2), guest.read_datagram())
        .await
        .expect("host-to-guest datagram timed out")
        .unwrap();
    assert_eq!(WireFrame::decode(received).unwrap(), outbound);

    let guest_packet = Bytes::from_static(&[
        0x45, 0x00, 0x00, 0x1c, 0, 1, 0, 0, 0x40, 0x11, 0, 0, 100, 64, 0, 2, 100, 64, 0, 1, 0x4a,
        0xbc, 0x4a, 0xbc, 0, 8, 0, 0,
    ]);
    let response = WireFrame::new(1, 8, guest_packet).unwrap();
    guest.send_datagram(response.encode().unwrap()).unwrap();
    let received = timeout(Duration::from_secs(2), host.read_datagram())
        .await
        .expect("guest-to-host datagram timed out")
        .unwrap();
    assert_eq!(WireFrame::decode(received).unwrap(), response);

    let third_packet = Bytes::from_static(&[
        0x45, 0x00, 0x00, 0x1c, 0, 2, 0, 0, 0x40, 0x11, 0, 0, 100, 64, 0, 3, 100, 64, 0, 1, 0x4a,
        0xbc, 0x4a, 0xbc, 0, 8, 0, 0,
    ]);
    let third_response = WireFrame::new(1, 9, third_packet).unwrap();
    third
        .send_datagram(third_response.encode().unwrap())
        .unwrap();
    let received = timeout(Duration::from_secs(2), host.read_datagram())
        .await
        .expect("third-to-host datagram timed out")
        .unwrap();
    assert_eq!(WireFrame::decode(received).unwrap(), third_response);

    host.close(0_u32.into(), b"gate complete");
    guest.close(0_u32.into(), b"gate complete");
    third.close(0_u32.into(), b"gate complete");
    host_endpoint.wait_idle().await;
    guest_endpoint.wait_idle().await;
    third_endpoint.wait_idle().await;
    relay_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_core_uses_caller_owned_udp_sockets_bidirectionally() {
    let signing_key = SigningKey::from_bytes(&SIGNING_KEY);
    let verifier = TicketVerifier::new(KEY_ID, signing_key.verifying_key().to_bytes()).unwrap();
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate_der = CertificateDer::from(certificate.cert);
    let private_key = PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der());
    let server = Endpoint::server(
        tls::server_config(vec![certificate_der.clone()], private_key.into()).unwrap(),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .unwrap();
    let relay_address = server.local_addr().unwrap();
    let relay_task = tokio::spawn(Relay::new(verifier).serve(server));

    let host = RelayClient::connect(
        std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
        relay_address,
        "localhost",
        ticket_for_peer(1),
        tls::client_config(certificate_der.clone()).unwrap(),
    )
    .await
    .unwrap();
    let guest = RelayClient::connect(
        std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
        relay_address,
        "localhost",
        ticket_for_peer(2),
        tls::client_config(certificate_der).unwrap(),
    )
    .await
    .unwrap();

    let outbound = Bytes::from_static(&[
        0x45, 0, 0, 0x1c, 0, 2, 0, 0, 0x40, 0x11, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2, 0x4a, 0xbc,
        0x4a, 0xbc, 0, 8, 0, 0,
    ]);
    host.send_packet(2, 11, outbound.clone()).unwrap();
    let received = timeout(Duration::from_secs(2), guest.receive_packet())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.payload, outbound);
    assert_eq!(received.dst_peer, 2);

    let response = Bytes::from_static(&[
        0x45, 0, 0, 0x1c, 0, 3, 0, 0, 0x40, 0x11, 0, 0, 100, 64, 0, 2, 100, 64, 0, 1, 0x4a, 0xbc,
        0x4a, 0xbc, 0, 8, 0, 0,
    ]);
    guest.send_packet(1, 12, response.clone()).unwrap();
    let received = timeout(Duration::from_secs(2), host.receive_packet())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.payload, response);
    assert_eq!(received.dst_peer, 1);

    host.close();
    guest.close();
    relay_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_closes_an_authenticated_connection_when_its_ticket_expires() {
    let signing_key = SigningKey::from_bytes(&SIGNING_KEY);
    let verifier = TicketVerifier::new(KEY_ID, signing_key.verifying_key().to_bytes()).unwrap();
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate_der = CertificateDer::from(certificate.cert);
    let private_key = PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der());
    let server = Endpoint::server(
        tls::server_config(vec![certificate_der.clone()], private_key.into()).unwrap(),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .unwrap();
    let relay_address = server.local_addr().unwrap();
    let relay_task = tokio::spawn(Relay::new(verifier).serve(server));

    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    endpoint.set_default_client_config(tls::client_config(certificate_der).unwrap());
    let connection = endpoint
        .connect(relay_address, "localhost")
        .unwrap()
        .await
        .unwrap();
    let ticket = sign_ticket(TicketClaims {
        exp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 2,
        jti: "short-lived-gate-a-ticket".into(),
        ..claims_for_peer(1, "gate-a-expiration")
    });
    authenticate_client(&connection, ticket).await.unwrap();

    timeout(Duration::from_secs(4), connection.closed())
        .await
        .expect("relay kept an expired authenticated connection open");
    endpoint.wait_idle().await;
    relay_task.abort();
}

async fn connect_peer(
    relay_address: SocketAddr,
    certificate: CertificateDer<'static>,
    peer_id: u32,
) -> (Endpoint, Connection) {
    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    endpoint.set_default_client_config(tls::client_config(certificate).unwrap());
    let connection = endpoint
        .connect(relay_address, "localhost")
        .unwrap()
        .await
        .unwrap();
    let virtual_ip = format!("100.64.0.{peer_id}");
    let ticket = sign_ticket(TicketClaims {
        iss: EXPECTED_ISSUER.into(),
        aud: EXPECTED_AUDIENCE.into(),
        network_id: "public-v1".into(),
        lease_id: format!("{peer_id:08x}-1111-4111-8111-111111111111"),
        peer_id,
        role: "member".into(),
        virtual_ip,
        exp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 120,
        jti: format!("gate-a-peer-{peer_id}"),
        protocol_version: PROTOCOL_VERSION,
    });
    let response = authenticate_client(&connection, ticket).await.unwrap();
    assert_eq!(response.peer_id, peer_id);
    assert_eq!(response.network_id, "public-v1");
    (endpoint, connection)
}

fn sign_ticket(claims: TicketClaims) -> String {
    let header = TicketHeader {
        alg: "EdDSA".into(),
        typ: "JWT".into(),
        kid: KEY_ID.into(),
    };
    let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{encoded_header}.{encoded_claims}");
    let signature = SigningKey::from_bytes(&SIGNING_KEY).sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

fn ticket_for_peer(peer_id: u32) -> String {
    sign_ticket(TicketClaims {
        exp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 120,
        jti: format!("gate-a-client-peer-{peer_id}"),
        ..claims_for_peer(peer_id, "gate-a-client-core")
    })
}

fn claims_for_peer(peer_id: u32, _network_id: &str) -> TicketClaims {
    let virtual_ip = format!("100.64.0.{peer_id}");
    TicketClaims {
        iss: EXPECTED_ISSUER.into(),
        aud: EXPECTED_AUDIENCE.into(),
        network_id: "public-v1".into(),
        lease_id: format!("{peer_id:08x}-1111-4111-8111-111111111111"),
        peer_id,
        role: "member".into(),
        virtual_ip,
        exp: 0,
        jti: String::new(),
        protocol_version: PROTOCOL_VERSION,
    }
}
