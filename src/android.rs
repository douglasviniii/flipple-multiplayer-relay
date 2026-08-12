use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JObject, JString, JValue};
use jni::sys::{JNI_FALSE, JNI_TRUE, jboolean, jbyteArray, jint, jlong, jstring};
use tokio::runtime::Runtime;
use tokio::time::timeout;

use crate::client::RelayClient;
use crate::tls;

struct NativeSession {
    runtime: Arc<Runtime>,
    client: RelayClient,
}

static NEXT_HANDLE: AtomicI64 = AtomicI64::new(1);
static SESSIONS: OnceLock<Mutex<HashMap<i64, NativeSession>>> = OnceLock::new();

fn sessions() -> &'static Mutex<HashMap<i64, NativeSession>> {
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn java_string(env: &mut JNIEnv<'_>, value: JString<'_>, field: &str) -> Result<String> {
    let result: String = env
        .get_string(&value)
        .with_context(|| format!("read {field}"))?
        .into();
    let result = result.trim().to_owned();
    if result.is_empty() {
        bail!("{field} is required");
    }
    Ok(result)
}

fn throw(env: &mut JNIEnv<'_>, error: impl std::fmt::Display) {
    let _ = env.throw_new("java/lang/IllegalStateException", error.to_string());
}

fn resolve_relay(host: &str, port: u16) -> Result<SocketAddr> {
    (host, port)
        .to_socket_addrs()
        .context("resolve relay host")?
        .next()
        .context("relay host did not resolve")
}

fn protected_socket(
    env: &mut JNIEnv<'_>,
    vpn_service: &JObject<'_>,
    relay: SocketAddr,
) -> Result<UdpSocket> {
    let bind = if relay.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    let socket = UdpSocket::bind(bind).context("bind relay UDP socket")?;
    let protected = env
        .call_method(
            vpn_service,
            "protect",
            "(I)Z",
            &[JValue::Int(socket.as_raw_fd())],
        )
        .context("call VpnService.protect")?
        .z()
        .context("read VpnService.protect result")?;
    if !protected {
        bail!("VpnService rejected relay socket protection");
    }
    Ok(socket)
}

fn cloned_session(handle: jlong) -> Result<(Arc<Runtime>, RelayClient)> {
    let sessions = sessions()
        .lock()
        .map_err(|_| anyhow::anyhow!("session lock poisoned"))?;
    let session = sessions
        .get(&handle)
        .context("relay session is not active")?;
    Ok((Arc::clone(&session.runtime), session.client.clone()))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_seuapp_flipplearcade_MinecraftRelayNative_nativeConnect(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    vpn_service: JObject<'_>,
    relay_host: JString<'_>,
    relay_port: jint,
    server_name: JString<'_>,
    ticket: JString<'_>,
) -> jlong {
    let result = (|| -> Result<jlong> {
        let host = java_string(&mut env, relay_host, "relay host")?;
        let server_name = java_string(&mut env, server_name, "relay server name")?;
        let ticket = java_string(&mut env, ticket, "relay ticket")?;
        let port = u16::try_from(relay_port).context("relay port is invalid")?;
        if port == 0 {
            bail!("relay port is invalid");
        }
        let relay = resolve_relay(&host, port)?;
        let socket = protected_socket(&mut env, &vpn_service, relay)?;
        let runtime = Arc::new(Runtime::new().context("create relay runtime")?);
        let client = runtime.block_on(RelayClient::connect(
            socket,
            relay,
            &server_name,
            ticket,
            tls::public_client_config()?,
        ))?;
        let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
        sessions()
            .lock()
            .map_err(|_| anyhow::anyhow!("session lock poisoned"))?
            .insert(handle, NativeSession { runtime, client });
        Ok(handle)
    })();
    match result {
        Ok(handle) => handle,
        Err(error) => {
            throw(&mut env, error);
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_seuapp_flipplearcade_MinecraftRelayNative_nativeSend(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    destination_peer: jint,
    sequence: jint,
    packet: JByteArray<'_>,
) -> jboolean {
    let result = (|| -> Result<()> {
        let (_, client) = cloned_session(handle)?;
        let destination_peer = u16::try_from(destination_peer).context("peer id is invalid")?;
        let packet = env
            .convert_byte_array(packet)
            .context("read raw IP packet")?;
        client.send_packet(destination_peer, sequence as u32, Bytes::from(packet))
    })();
    match result {
        Ok(()) => JNI_TRUE,
        Err(error) => {
            throw(&mut env, error);
            JNI_FALSE
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_seuapp_flipplearcade_MinecraftRelayNative_nativeReceive(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    timeout_ms: jint,
) -> jbyteArray {
    let result = (|| -> Result<Option<Vec<u8>>> {
        let (runtime, client) = cloned_session(handle)?;
        let duration = Duration::from_millis(u64::try_from(timeout_ms.max(1))?);
        match runtime.block_on(timeout(duration, client.receive_packet())) {
            Ok(frame) => Ok(Some(frame?.payload.to_vec())),
            Err(_) => Ok(None),
        }
    })();
    match result {
        Ok(Some(packet)) => match env.byte_array_from_slice(&packet) {
            Ok(array) => array.into_raw(),
            Err(error) => {
                throw(&mut env, error);
                std::ptr::null_mut()
            }
        },
        Ok(None) => std::ptr::null_mut(),
        Err(error) => {
            throw(&mut env, error);
            std::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_seuapp_flipplearcade_MinecraftRelayNative_nativeRoomId(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jstring {
    match cloned_session(handle).and_then(|(_, client)| {
        env.new_string(client.room_id())
            .context("create room id Java string")
    }) {
        Ok(value) => value.into_raw(),
        Err(error) => {
            throw(&mut env, error);
            std::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_seuapp_flipplearcade_MinecraftRelayNative_nativePeerId(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jint {
    match cloned_session(handle) {
        Ok((_, client)) => jint::from(client.peer_id()),
        Err(error) => {
            throw(&mut env, error);
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_seuapp_flipplearcade_MinecraftRelayNative_nativeClose(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    let result = sessions()
        .lock()
        .map_err(|_| anyhow::anyhow!("session lock poisoned"))
        .map(|mut sessions| sessions.remove(&handle));
    match result {
        Ok(Some(session)) => session.client.close(),
        Ok(None) => {}
        Err(error) => throw(&mut env, error),
    }
}
