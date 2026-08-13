pub mod auth;
pub mod client;
pub mod relay;
pub mod tls;
pub mod wire;

#[cfg(target_os = "android")]
mod android;

pub const PROTOCOL_VERSION: u8 = 2;
pub const ALPN: &[u8] = b"flipple-mc/2";
