use bytes::{BufMut, Bytes, BytesMut};
use thiserror::Error;

use crate::PROTOCOL_VERSION;

pub const HEADER_LEN: usize = 10;
pub const MAX_DATAGRAM_LEN: usize = 1200;
pub const MAX_PAYLOAD_LEN: usize = MAX_DATAGRAM_LEN - HEADER_LEN;
pub const FLAG_IP_PACKET: u8 = 0;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireFrame {
    pub flags: u8,
    pub dst_peer: u32,
    pub sequence: u32,
    pub payload: Bytes,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum WireError {
    #[error("frame is shorter than the 10-byte header")]
    TooShort,
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported flags 0x{0:02x}")]
    UnsupportedFlags(u8),
    #[error("destination peer must be non-zero")]
    InvalidDestination,
    #[error("payload is empty")]
    EmptyPayload,
    #[error("frame exceeds the 1200-byte POC limit")]
    TooLarge,
}

impl WireFrame {
    pub fn new(dst_peer: u32, sequence: u32, payload: impl Into<Bytes>) -> Result<Self, WireError> {
        let frame = Self {
            flags: FLAG_IP_PACKET,
            dst_peer,
            sequence,
            payload: payload.into(),
        };
        frame.validate()?;
        Ok(frame)
    }

    pub fn encode(&self) -> Result<Bytes, WireError> {
        self.validate()?;
        let mut encoded = BytesMut::with_capacity(HEADER_LEN + self.payload.len());
        encoded.put_u8(PROTOCOL_VERSION);
        encoded.put_u8(self.flags);
        encoded.put_u32(self.dst_peer);
        encoded.put_u32(self.sequence);
        encoded.extend_from_slice(&self.payload);
        Ok(encoded.freeze())
    }

    pub fn decode(encoded: Bytes) -> Result<Self, WireError> {
        if encoded.len() < HEADER_LEN {
            return Err(WireError::TooShort);
        }
        if encoded.len() > MAX_DATAGRAM_LEN {
            return Err(WireError::TooLarge);
        }
        let version = encoded[0];
        if version != PROTOCOL_VERSION {
            return Err(WireError::UnsupportedVersion(version));
        }
        let frame = Self {
            flags: encoded[1],
            dst_peer: u32::from_be_bytes([encoded[2], encoded[3], encoded[4], encoded[5]]),
            sequence: u32::from_be_bytes([encoded[6], encoded[7], encoded[8], encoded[9]]),
            payload: encoded.slice(HEADER_LEN..),
        };
        frame.validate()?;
        Ok(frame)
    }

    fn validate(&self) -> Result<(), WireError> {
        if self.flags != FLAG_IP_PACKET {
            return Err(WireError::UnsupportedFlags(self.flags));
        }
        if self.dst_peer == 0 {
            return Err(WireError::InvalidDestination);
        }
        if self.payload.is_empty() {
            return Err(WireError::EmptyPayload);
        }
        if self.payload.len() > MAX_PAYLOAD_LEN {
            return Err(WireError::TooLarge);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_uses_network_byte_order() {
        let frame = WireFrame::new(0x1234, 0x89ab_cdef, Bytes::from_static(b"ip-packet")).unwrap();
        let encoded = frame.encode().unwrap();
        assert_eq!(
            &encoded[..10],
            &[2, 0, 0, 0, 0x12, 0x34, 0x89, 0xab, 0xcd, 0xef]
        );
        assert_eq!(WireFrame::decode(encoded).unwrap(), frame);
    }

    #[test]
    fn rejects_invalid_input_without_truncation() {
        assert_eq!(
            WireFrame::decode(Bytes::from_static(&[1, 0])).unwrap_err(),
            WireError::TooShort
        );
        assert_eq!(
            WireFrame::new(2, 1, vec![0_u8; MAX_PAYLOAD_LEN + 1]).unwrap_err(),
            WireError::TooLarge,
        );
    }

    #[test]
    fn matches_frozen_gate_a_vector() {
        let payload = Bytes::from_static(&[
            0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 0x40, 0x11, 0, 0, 100, 96, 0, 1, 100, 96, 0, 2,
            0x4a, 0x7e, 0x4a, 0x7e, 0, 8, 0, 0,
        ]);
        let encoded = WireFrame::new(2, 7, payload).unwrap().encode().unwrap();
        assert_eq!(
            encoded.as_ref(),
            &[
                0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07, 0x45, 0x00, 0x00, 0x1c,
                0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x64, 0x60, 0x00, 0x01, 0x64, 0x60,
                0x00, 0x02, 0x4a, 0x7e, 0x4a, 0x7e, 0x00, 0x08, 0x00, 0x00,
            ]
        );
    }
}
