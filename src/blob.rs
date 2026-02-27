//! Justice blob construction and encryption.
//!
//! Implements LND's `JusticeKit` blob format: the encrypted payload that a
//! watchtower stores and can decrypt when it sees a revoked commitment
//! transaction on chain.

use byteorder::{BigEndian, WriteBytesExt};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;
use std::io::Write;

/// Size of the encryption nonce (XChaCha20-Poly1305).
pub const NONCE_SIZE: usize = 24;
/// Size of the encryption key (= 32 bytes, the full revoked txid).
pub const KEY_SIZE: usize = 32;
/// MAC overhead from Poly1305.
pub const MAC_SIZE: usize = 16;
/// Maximum sweep address size in the blob.
pub const MAX_SWEEP_ADDR_SIZE: usize = 42;
/// Hint size: first 16 bytes of the revoked commitment txid.
pub const HINT_SIZE: usize = 16;

/// V0 plaintext size (legacy and anchor channels): 274 bytes.
///   sweep_addr_len:    1
///   sweep_addr:       42 (padded)
///   revocation_pk:    33
///   local_delay_pk:   33
///   csv_delay:         4
///   to_local_sig:     64
///   to_remote_pk:     33
///   to_remote_sig:    64
pub const V0_PLAINTEXT_SIZE: usize = 274;

/// V1 plaintext size (taproot channels): 300 bytes.
pub const V1_PLAINTEXT_SIZE: usize = 300;

/// The breach key used for encryption/decryption.
/// This is the full 32-byte txid of the revoked commitment transaction.
pub type BreachKey = [u8; KEY_SIZE];

/// Hint: first 16 bytes of the revoked commitment txid.
/// The tower uses this as a lookup key when scanning blocks.
pub fn compute_hint(breach_txid: &[u8; 32]) -> [u8; HINT_SIZE] {
    let mut hint = [0u8; HINT_SIZE];
    hint.copy_from_slice(&breach_txid[..HINT_SIZE]);
    hint
}

/// Justice data for a V0 (legacy/anchor) channel.
///
/// Contains everything the tower needs to construct a justice transaction
/// that sweeps the cheater's funds.
#[derive(Debug, Clone)]
pub struct JusticeKitV0 {
    /// Witness program where swept funds go (p2wpkh or p2tr).
    pub sweep_address: Vec<u8>,
    /// Compressed revocation public key (33 bytes).
    pub revocation_pubkey: [u8; 33],
    /// Compressed local delay public key (33 bytes).
    pub local_delay_pubkey: [u8; 33],
    /// CSV delay for the to-local output.
    pub csv_delay: u32,
    /// Signature for spending the to-local output (64 bytes, compact).
    pub to_local_sig: [u8; 64],
    /// Compressed to-remote public key (33 bytes, may be zeroed if no to-remote).
    pub to_remote_pubkey: [u8; 33],
    /// Signature for spending the to-remote output (64 bytes, may be zeroed).
    pub to_remote_sig: [u8; 64],
}

impl JusticeKitV0 {
    /// Encode to plaintext bytes (274 bytes, V0 format).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(V0_PLAINTEXT_SIZE);

        // Sweep address: 1 byte length + 42 bytes padded
        let addr_len = self.sweep_address.len().min(MAX_SWEEP_ADDR_SIZE);
        buf.write_u8(addr_len as u8).unwrap();
        buf.write_all(&self.sweep_address[..addr_len]).unwrap();
        // Pad to 42 bytes
        for _ in addr_len..MAX_SWEEP_ADDR_SIZE {
            buf.write_u8(0).unwrap();
        }

        // Keys and delay
        buf.write_all(&self.revocation_pubkey).unwrap();
        buf.write_all(&self.local_delay_pubkey).unwrap();
        buf.write_u32::<BigEndian>(self.csv_delay).unwrap();

        // Signatures
        buf.write_all(&self.to_local_sig).unwrap();
        buf.write_all(&self.to_remote_pubkey).unwrap();
        buf.write_all(&self.to_remote_sig).unwrap();

        debug_assert_eq!(buf.len(), V0_PLAINTEXT_SIZE);
        buf
    }
}

/// Encrypt a justice kit into an LND-compatible encrypted blob.
///
/// Returns the ciphertext: [24-byte nonce][encrypted plaintext][16-byte MAC]
pub fn encrypt_blob(plaintext: &[u8], breach_key: &BreachKey) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new(breach_key.into());

    // Generate random 24-byte nonce
    let nonce_bytes: [u8; NONCE_SIZE] = rand::random();
    let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("encryption failed: {}", e))?;

    // Output format: [nonce][ciphertext+MAC]
    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Decrypt an LND watchtower blob.
///
/// Input format: [24-byte nonce][encrypted plaintext][16-byte MAC]
pub fn decrypt_blob(encrypted: &[u8], breach_key: &BreachKey) -> Result<Vec<u8>, String> {
    if encrypted.len() < NONCE_SIZE + MAC_SIZE {
        return Err("ciphertext too small".into());
    }

    let cipher = XChaCha20Poly1305::new(breach_key.into());
    let nonce = chacha20poly1305::XNonce::from_slice(&encrypted[..NONCE_SIZE]);
    let ciphertext = &encrypted[NONCE_SIZE..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("decryption failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_justice_kit_v0_encode_size() {
        let kit = JusticeKitV0 {
            sweep_address: vec![0u8; 22], // p2wpkh
            revocation_pubkey: [2u8; 33],
            local_delay_pubkey: [3u8; 33],
            csv_delay: 144,
            to_local_sig: [0u8; 64],
            to_remote_pubkey: [0u8; 33],
            to_remote_sig: [0u8; 64],
        };
        let encoded = kit.encode();
        assert_eq!(encoded.len(), V0_PLAINTEXT_SIZE);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = vec![42u8; V0_PLAINTEXT_SIZE];
        let key: BreachKey = [0xab; 32];

        let encrypted = encrypt_blob(&plaintext, &key).unwrap();
        assert_eq!(encrypted.len(), NONCE_SIZE + V0_PLAINTEXT_SIZE + MAC_SIZE);

        let decrypted = decrypt_blob(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let plaintext = vec![42u8; V0_PLAINTEXT_SIZE];
        let key: BreachKey = [0xab; 32];
        let wrong_key: BreachKey = [0xcd; 32];

        let encrypted = encrypt_blob(&plaintext, &key).unwrap();
        assert!(decrypt_blob(&encrypted, &wrong_key).is_err());
    }

    #[test]
    fn test_compute_hint() {
        let mut txid = [0u8; 32];
        txid[0] = 0xde;
        txid[1] = 0xad;
        txid[15] = 0xff;
        txid[16] = 0x99; // This byte should NOT be in the hint

        let hint = compute_hint(&txid);
        assert_eq!(hint[0], 0xde);
        assert_eq!(hint[1], 0xad);
        assert_eq!(hint[15], 0xff);
    }
}
