//! LND watchtower wire protocol message types.
//!
//! Implements the message serialization format used between watchtower clients
//! and servers as defined in LND's `wtwire` package.

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Cursor, Read, Write};

/// Wire message type identifiers matching LND's constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MessageType {
    /// Client initiates a new session with the tower.
    CreateSession = 16,
    /// Tower responds to session creation.
    CreateSessionReply = 17,
    /// Client sends an encrypted state update (justice blob).
    StateUpdate = 18,
    /// Tower acknowledges a state update.
    StateUpdateReply = 19,
    /// Client requests to delete a session.
    DeleteSession = 20,
    /// Tower responds to session deletion.
    DeleteSessionReply = 21,
}

impl MessageType {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            16 => Some(Self::CreateSession),
            17 => Some(Self::CreateSessionReply),
            18 => Some(Self::StateUpdate),
            19 => Some(Self::StateUpdateReply),
            20 => Some(Self::DeleteSession),
            21 => Some(Self::DeleteSessionReply),
            _ => None,
        }
    }
}

/// Blob type flags matching LND's `blob.Type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobType(pub u16);

impl BlobType {
    /// Sweeps commitment outputs, no reward to tower.
    pub const ALTRUIST_COMMIT: Self = Self(0b010);
    /// Sweeps anchor commitment outputs, no reward.
    pub const ALTRUIST_ANCHOR_COMMIT: Self = Self(0b110);
    /// Sweeps taproot commitment outputs, no reward.
    pub const ALTRUIST_TAPROOT_COMMIT: Self = Self(0b1010);
}

/// CreateSession: client proposes a new backup session to the tower.
///
/// Wire format (20 bytes):
///   blob_type:      u16
///   max_updates:    u16
///   reward_base:    u32
///   reward_rate:    u32
///   sweep_fee_rate: u64 (SatPerKWeight)
#[derive(Debug, Clone)]
pub struct CreateSession {
    pub blob_type: BlobType,
    pub max_updates: u16,
    pub reward_base: u32,
    pub reward_rate: u32,
    pub sweep_fee_rate: u64,
}

impl CreateSession {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(20);
        buf.write_u16::<BigEndian>(self.blob_type.0).unwrap();
        buf.write_u16::<BigEndian>(self.max_updates).unwrap();
        buf.write_u32::<BigEndian>(self.reward_base).unwrap();
        buf.write_u32::<BigEndian>(self.reward_rate).unwrap();
        buf.write_u64::<BigEndian>(self.sweep_fee_rate).unwrap();
        buf
    }
}

/// CreateSessionReply: tower responds to session creation.
#[derive(Debug, Clone)]
pub struct CreateSessionReply {
    /// Response code (0 = accepted).
    pub code: u16,
    /// Serialized reward script (may be empty for altruist towers).
    pub data: Vec<u8>,
}

impl CreateSessionReply {
    pub fn decode(data: &[u8]) -> io::Result<Self> {
        let mut cursor = Cursor::new(data);
        let code = cursor.read_u16::<BigEndian>()?;
        let mut rest = Vec::new();
        cursor.read_to_end(&mut rest)?;
        Ok(Self { code, data: rest })
    }

    pub fn is_ok(&self) -> bool {
        self.code == 0
    }
}

/// StateUpdate: client sends an encrypted justice blob for a specific
/// revoked commitment transaction.
///
/// Wire format:
///   seq_num:       u16
///   last_applied:  u16
///   is_complete:   u8
///   hint:          [u8; 16]  (first 16 bytes of revoked commitment txid)
///   encrypted_blob: variable length
#[derive(Debug, Clone)]
pub struct StateUpdate {
    /// Monotonically increasing sequence number (1-indexed).
    pub seq_num: u16,
    /// Echoes the tower's last acknowledged sequence number.
    pub last_applied: u16,
    /// 1 if the client wants to close the connection after this update.
    pub is_complete: u8,
    /// First 16 bytes of the revoked commitment txid.
    pub hint: [u8; 16],
    /// Encrypted justice blob (chacha20poly1305).
    pub encrypted_blob: Vec<u8>,
}

impl StateUpdate {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(21 + self.encrypted_blob.len());
        buf.write_u16::<BigEndian>(self.seq_num).unwrap();
        buf.write_u16::<BigEndian>(self.last_applied).unwrap();
        buf.write_u8(self.is_complete).unwrap();
        buf.write_all(&self.hint).unwrap();
        // Blob length as u16 then the blob itself
        buf.write_u16::<BigEndian>(self.encrypted_blob.len() as u16).unwrap();
        buf.write_all(&self.encrypted_blob).unwrap();
        buf
    }
}

/// StateUpdateReply: tower acknowledges a state update.
#[derive(Debug, Clone)]
pub struct StateUpdateReply {
    /// Response code (0 = accepted).
    pub code: u16,
    /// The tower's latest applied sequence number.
    pub last_applied: u16,
}

impl StateUpdateReply {
    pub fn decode(data: &[u8]) -> io::Result<Self> {
        let mut cursor = Cursor::new(data);
        let code = cursor.read_u16::<BigEndian>()?;
        let last_applied = cursor.read_u16::<BigEndian>()?;
        Ok(Self { code, last_applied })
    }

    pub fn is_ok(&self) -> bool {
        self.code == 0
    }
}

/// Encode a wire message with its type prefix.
///
/// LND wire format: [u16 msg_type][payload]
pub fn encode_message(msg_type: MessageType, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + payload.len());
    buf.write_u16::<BigEndian>(msg_type as u16).unwrap();
    buf.write_all(payload).unwrap();
    buf
}

/// Decode a wire message type and payload.
pub fn decode_message(data: &[u8]) -> io::Result<(MessageType, Vec<u8>)> {
    if data.len() < 2 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "message too short"));
    }
    let mut cursor = Cursor::new(data);
    let type_id = cursor.read_u16::<BigEndian>()?;
    let msg_type = MessageType::from_u16(type_id).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("unknown message type: {}", type_id))
    })?;
    let mut payload = Vec::new();
    cursor.read_to_end(&mut payload)?;
    Ok((msg_type, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_session_roundtrip() {
        let msg = CreateSession {
            blob_type: BlobType::ALTRUIST_ANCHOR_COMMIT,
            max_updates: 1024,
            reward_base: 0,
            reward_rate: 0,
            sweep_fee_rate: 12500, // 50 sat/vB in sat/kw
        };
        let encoded = msg.encode();
        assert_eq!(encoded.len(), 20);
    }

    #[test]
    fn test_state_update_encode() {
        let mut hint = [0u8; 16];
        hint[0] = 0xde;
        hint[1] = 0xad;

        let update = StateUpdate {
            seq_num: 1,
            last_applied: 0,
            is_complete: 0,
            hint,
            encrypted_blob: vec![0u8; 314], // V0 blob size: 274 + 24 nonce + 16 MAC
        };
        let encoded = update.encode();
        // 2 + 2 + 1 + 16 + 2 + 314 = 337
        assert_eq!(encoded.len(), 337);
    }
}
