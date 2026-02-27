//! Watchtower client: manages sessions and sends state updates to an LND tower.

use crate::blob::{self, BreachKey, JusticeKitV0};
use crate::noise::NoiseTransport;
use crate::wire::{self, BlobType, CreateSession, CreateSessionReply, MessageType, StateUpdate, StateUpdateReply};
use log::{error, info, warn};
use std::io;
use tokio::net::TcpStream;

/// Configuration for connecting to an LND watchtower.
#[derive(Debug, Clone)]
pub struct TowerConfig {
    /// Tower address (host:port).
    pub address: String,
    /// Tower's static public key (33 bytes compressed secp256k1).
    pub tower_pubkey: [u8; 33],
    /// Our client's static private key (32 bytes).
    pub client_key: [u8; 32],
    /// Blob type for the session (determines channel type: legacy/anchor/taproot).
    pub blob_type: BlobType,
    /// Maximum number of updates per session.
    pub max_updates: u16,
    /// Fee rate for justice transactions (sat/kweight).
    pub sweep_fee_rate: u64,
}

/// A pending watchtower backup: the data needed to push one state update.
#[derive(Debug, Clone)]
pub struct PendingBackup {
    /// The full txid of the revoked commitment (used as encryption key + hint).
    pub breach_txid: [u8; 32],
    /// The justice kit containing sweep data.
    pub justice_kit: JusticeKitV0,
}

/// Active session with a tower.
struct TowerSession {
    transport: NoiseTransport,
    seq_num: u16,
    last_applied: u16,
    max_updates: u16,
}

/// Watchtower client.
pub struct WatchtowerClient {
    config: TowerConfig,
    session: Option<TowerSession>,
}

impl WatchtowerClient {
    /// Create a new watchtower client.
    pub fn new(config: TowerConfig) -> Self {
        Self {
            config,
            session: None,
        }
    }

    /// Connect to the tower and establish a session.
    pub async fn connect(&mut self) -> io::Result<()> {
        info!("Connecting to watchtower at {}", self.config.address);

        let stream = TcpStream::connect(&self.config.address).await?;
        let transport = NoiseTransport::connect(
            stream,
            &self.config.client_key,
            &self.config.tower_pubkey,
        )
        .await?;

        info!("Noise handshake complete, creating session");

        let mut session = TowerSession {
            transport,
            seq_num: 0,
            last_applied: 0,
            max_updates: self.config.max_updates,
        };

        // Send CreateSession
        let create_msg = CreateSession {
            blob_type: self.config.blob_type,
            max_updates: self.config.max_updates,
            reward_base: 0,
            reward_rate: 0,
            sweep_fee_rate: self.config.sweep_fee_rate,
        };
        let payload = create_msg.encode();
        let msg = wire::encode_message(MessageType::CreateSession, &payload);
        session.transport.send(&msg).await?;

        // Read CreateSessionReply
        let reply_data = session.transport.recv().await?;
        let (msg_type, payload) = wire::decode_message(&reply_data)?;

        if msg_type != MessageType::CreateSessionReply {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected CreateSessionReply, got {:?}", msg_type),
            ));
        }

        let reply = CreateSessionReply::decode(&payload)?;
        if !reply.is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("tower rejected session: code {}", reply.code),
            ));
        }

        info!("Watchtower session established (max {} updates)", self.config.max_updates);
        self.session = Some(session);
        Ok(())
    }

    /// Send a backup (state update) to the tower.
    ///
    /// The backup contains a justice blob that the tower will store and use
    /// to construct a justice transaction if it detects the revoked commitment
    /// on chain.
    pub async fn send_backup(&mut self, backup: &PendingBackup) -> io::Result<()> {
        let session = self.session.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "no active session")
        })?;

        if session.seq_num >= session.max_updates {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "session exhausted, need new session",
            ));
        }

        // Encode the justice kit
        let plaintext = backup.justice_kit.encode();

        // Encrypt with the breach txid as key
        let breach_key: BreachKey = backup.breach_txid;
        let encrypted = blob::encrypt_blob(&plaintext, &breach_key)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        // Compute the hint (first 16 bytes of breach txid)
        let hint = blob::compute_hint(&backup.breach_txid);

        // Build and send state update
        session.seq_num += 1;
        let update = StateUpdate {
            seq_num: session.seq_num,
            last_applied: session.last_applied,
            is_complete: 0,
            hint,
            encrypted_blob: encrypted,
        };

        let payload = update.encode();
        let msg = wire::encode_message(MessageType::StateUpdate, &payload);
        session.transport.send(&msg).await?;

        // Read StateUpdateReply
        let reply_data = session.transport.recv().await?;
        let (msg_type, payload) = wire::decode_message(&reply_data)?;

        if msg_type != MessageType::StateUpdateReply {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected StateUpdateReply, got {:?}", msg_type),
            ));
        }

        let reply = StateUpdateReply::decode(&payload)?;
        if !reply.is_ok() {
            warn!("Tower rejected state update {}: code {}", session.seq_num, reply.code);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("tower rejected update: code {}", reply.code),
            ));
        }

        session.last_applied = reply.last_applied;
        info!(
            "Backup {} sent successfully (tower applied up to {})",
            session.seq_num, session.last_applied
        );
        Ok(())
    }

    /// Returns the number of remaining update slots in the current session.
    pub fn remaining_updates(&self) -> Option<u16> {
        self.session
            .as_ref()
            .map(|s| s.max_updates.saturating_sub(s.seq_num))
    }

    /// Returns true if connected and session is active.
    pub fn is_connected(&self) -> bool {
        self.session.is_some()
    }
}
