//! # ldk-watchtower-client
//!
//! Cross-implementation watchtower bridge: allows LDK-based Lightning nodes
//! to use existing LND watchtowers for channel security.
//!
//! ## How it works
//!
//! 1. Your LDK node exports channel monitor data after each state update
//! 2. This crate translates the revocation data into LND's JusticeKit blob format
//! 3. Blobs are encrypted with the revoked commitment txid as the key
//! 4. The encrypted blobs are pushed to the LND tower via its Noise_XK wire protocol
//! 5. If the tower sees a revoked commitment on-chain, it decrypts the blob
//!    and broadcasts the justice transaction
//!
//! ## Architecture
//!
//! ```text
//! Phone (ldk-node)              Home Node (Umbrel)
//! ┌─────────────┐               ┌──────────────────┐
//! │ LDK monitor │──export──>    │                  │
//! │   updates   │  (SSH/API)    │  ldk-watchtower  │
//! └─────────────┘               │  -client         │
//!                               │    │             │
//!                               │    ├─ translate  │
//!                               │    │  to LND     │
//!                               │    │  blob fmt   │
//!                               │    │             │
//!                               │    └─ push via   │
//!                               │       Noise_XK   │
//!                               │       protocol   │
//!                               │         │        │
//!                               │    LND Tower     │
//!                               │    (existing)    │
//!                               └──────────────────┘
//! ```

pub mod blob;
pub mod client;
pub mod ffi;
pub mod noise;
pub mod wire;

pub use blob::{BreachKey, JusticeKitV0};
pub use client::{PendingBackup, TowerConfig, WatchtowerClient};
pub use wire::BlobType;
