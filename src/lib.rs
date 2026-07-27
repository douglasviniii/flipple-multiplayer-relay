pub mod auth;
pub mod relay;
pub mod tls;
pub mod wire;

pub const PROTOCOL_VERSION: u8 = 1;
pub const ALPN: &[u8] = b"flipple-mc/1";
