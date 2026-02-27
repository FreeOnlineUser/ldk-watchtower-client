//! Brontide: LND's Noise_XK implementation with secp256k1.
//!
//! This is a direct implementation matching LND's brontide/noise.go exactly,
//! rather than using the `snow` framework (which can't handle secp256k1).
//!
//! Protocol: Noise_XK_secp256k1_ChaChaPoly_SHA256
//! Prologue: "lightning"
//! Handshake: -> e, es | <- e, ee | -> s, se

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const PROTOCOL_NAME: &[u8] = b"Noise_XK_secp256k1_ChaChaPoly_SHA256";
const PROLOGUE: &[u8] = b"lightning";
const MAC_SIZE: usize = 16;
const KEY_ROTATION_INTERVAL: u64 = 1000;

/// ECDH matching LND's Brontide: sha256(compressed_shared_point)
///
/// libsecp256k1's default ECDH hash function computes SHA256(0x02|0x03 || x),
/// which is identical to LND's sha256(sx.SerializeCompressed()).
fn ecdh(local_priv: &SecretKey, remote_pub: &PublicKey) -> [u8; 32] {
    secp256k1::ecdh::SharedSecret::new(remote_pub, local_priv).secret_bytes()
}

/// Generate a random secp256k1 keypair.
fn gen_keypair() -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let (sk, pk) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
    (sk, pk)
}

/// CipherState: ChaCha20-Poly1305 with nonce counter and key rotation.
struct CipherState {
    key: [u8; 32],
    salt: [u8; 32],
    nonce: u64,
}

impl CipherState {
    fn new() -> Self {
        Self {
            key: [0u8; 32],
            salt: [0u8; 32],
            nonce: 0,
        }
    }

    fn initialize_key(&mut self, key: [u8; 32]) {
        self.key = key;
        self.nonce = 0;
    }

    fn initialize_key_with_salt(&mut self, salt: [u8; 32], key: [u8; 32]) {
        self.salt = salt;
        self.initialize_key(key);
    }

    fn nonce_bytes(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.nonce.to_le_bytes());
        nonce
    }

    fn encrypt(&mut self, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key).unwrap();
        let nonce_bytes = self.nonce_bytes();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let result = cipher.encrypt(nonce, chacha20poly1305::aead::Payload {
            msg: plaintext,
            aad: ad,
        }).expect("encryption failed");

        self.nonce += 1;
        if self.nonce == KEY_ROTATION_INTERVAL {
            self.rotate_key();
        }

        result
    }

    fn decrypt(&mut self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, io::Error> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key).unwrap();
        let nonce_bytes = self.nonce_bytes();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let result = cipher.decrypt(nonce, chacha20poly1305::aead::Payload {
            msg: ciphertext,
            aad: ad,
        }).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "MAC check failed"))?;

        self.nonce += 1;
        if self.nonce == KEY_ROTATION_INTERVAL {
            self.rotate_key();
        }

        Ok(result)
    }

    fn rotate_key(&mut self) {
        let hk = Hkdf::<Sha256>::new(Some(&self.salt), &self.key);
        let mut new_salt = [0u8; 32];
        let mut new_key = [0u8; 32];
        let mut okm = [0u8; 64];
        hk.expand(&[], &mut okm).expect("hkdf expand");
        new_salt.copy_from_slice(&okm[..32]);
        new_key.copy_from_slice(&okm[32..]);
        self.salt = new_salt;
        self.initialize_key(new_key);
    }
}

/// SymmetricState: manages handshake digest and chaining key.
struct SymmetricState {
    cipher: CipherState,
    chaining_key: [u8; 32],
    handshake_digest: [u8; 32],
}

impl SymmetricState {
    fn initialize(protocol_name: &[u8]) -> Self {
        let h = Sha256::digest(protocol_name);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&h);

        Self {
            cipher: CipherState::new(),
            chaining_key: digest,
            handshake_digest: digest,
        }
    }

    fn mix_key(&mut self, input: &[u8]) {
        let hk = Hkdf::<Sha256>::new(Some(&self.chaining_key), input);
        let mut okm = [0u8; 64];
        hk.expand(&[], &mut okm).expect("hkdf expand");
        self.chaining_key.copy_from_slice(&okm[..32]);
        let mut temp_key = [0u8; 32];
        temp_key.copy_from_slice(&okm[32..]);
        self.cipher.initialize_key(temp_key);
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut h = Sha256::new();
        h.update(&self.handshake_digest);
        h.update(data);
        self.handshake_digest.copy_from_slice(&h.finalize());
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let ciphertext = self.cipher.encrypt(&self.handshake_digest, plaintext);
        self.mix_hash(&ciphertext);
        ciphertext
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, io::Error> {
        let plaintext = self.cipher.decrypt(&self.handshake_digest, ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }
}

/// Established Brontide transport after handshake.
pub struct BrontideTransport {
    stream: TcpStream,
    send_cipher: CipherState,
    recv_cipher: CipherState,
}

impl BrontideTransport {
    /// Perform the 3-act Brontide handshake as initiator.
    pub async fn connect(
        stream: TcpStream,
        local_key: &SecretKey,
        remote_static: &PublicKey,
    ) -> io::Result<Self> {
        Self::connect_with_ephemeral(stream, local_key, remote_static, None).await
    }

    /// Connect with an optional deterministic ephemeral key (for testing).
    pub async fn connect_with_ephemeral(
        mut stream: TcpStream,
        local_key: &SecretKey,
        remote_static: &PublicKey,
        test_ephemeral: Option<SecretKey>,
    ) -> io::Result<Self> {
        let secp = Secp256k1::new();

        // Initialize symmetric state (matches LND's newHandshakeState)
        let mut ss = SymmetricState::initialize(PROTOCOL_NAME);
        ss.mix_hash(PROLOGUE);

        // In Noise_XK, initiator knows responder's static key
        ss.mix_hash(&remote_static.serialize());

        // === Act 1: -> e, es ===
        let (ephemeral_priv, ephemeral_pub) = match test_ephemeral {
            Some(sk) => {
                let pk = PublicKey::from_secret_key(&secp, &sk);
                (sk, pk)
            }
            None => gen_keypair(),
        };

        // e: mix ephemeral public key into hash
        ss.mix_hash(&ephemeral_pub.serialize());

        // es: ECDH(ephemeral, remote_static)
        let es = ecdh(&ephemeral_priv, remote_static);
        ss.mix_key(&es);


        // Encrypt empty payload
        let auth_payload = ss.encrypt_and_hash(&[]);

        // Build act 1: version(1) + ephemeral_pub(33) + mac(16) = 50 bytes
        let mut act1 = [0u8; 50];
        act1[0] = 0; // version
        act1[1..34].copy_from_slice(&ephemeral_pub.serialize());
        act1[34..].copy_from_slice(&auth_payload);
        stream.write_all(&act1).await?;
        stream.flush().await?;

        // === Act 2: <- e, ee ===
        let mut act2 = [0u8; 50];
        stream.read_exact(&mut act2).await?;

        if act2[0] != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("act2: bad version {}", act2[0])));
        }

        // e: parse responder's ephemeral key
        let remote_ephemeral = PublicKey::from_slice(&act2[1..34])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData,
                format!("act2: bad ephemeral key: {}", e)))?;
        ss.mix_hash(&remote_ephemeral.serialize());

        // ee: ECDH(our_ephemeral, their_ephemeral)
        let ee = ecdh(&ephemeral_priv, &remote_ephemeral);
        ss.mix_key(&ee);

        // Decrypt and verify MAC
        ss.decrypt_and_hash(&act2[34..50])?;

        // === Act 3: -> s, se ===
        // Encrypt our static public key
        let local_pub = PublicKey::from_secret_key(&secp, local_key);
        let encrypted_static = ss.encrypt_and_hash(&local_pub.serialize());

        // se: ECDH(our_static, their_ephemeral)
        let se = ecdh(local_key, &remote_ephemeral);
        ss.mix_key(&se);

        // Encrypt empty payload
        let auth_payload = ss.encrypt_and_hash(&[]);

        // Build act 3: version(1) + encrypted_static(33+16) + mac(16) = 66 bytes
        let mut act3 = [0u8; 66];
        act3[0] = 0; // version
        act3[1..50].copy_from_slice(&encrypted_static);
        act3[50..66].copy_from_slice(&auth_payload);
        stream.write_all(&act3).await?;
        stream.flush().await?;

        // Derive send and receive cipher keys
        // Split: initiator sends with first key, receives with second
        let hk = Hkdf::<Sha256>::new(Some(&ss.chaining_key), &[]);
        let mut okm = [0u8; 64];
        hk.expand(&[], &mut okm).expect("hkdf expand");

        let mut send_key = [0u8; 32];
        let mut recv_key = [0u8; 32];
        send_key.copy_from_slice(&okm[..32]);
        recv_key.copy_from_slice(&okm[32..]);

        let mut send_cipher = CipherState::new();
        send_cipher.initialize_key_with_salt(ss.chaining_key, send_key);
        let mut recv_cipher = CipherState::new();
        recv_cipher.initialize_key_with_salt(ss.chaining_key, recv_key);

        Ok(Self {
            stream,
            send_cipher,
            recv_cipher,
        })
    }

    /// Send an encrypted message (length-prefixed, both length and body encrypted).
    pub async fn send(&mut self, plaintext: &[u8]) -> io::Result<()> {
        // Encrypt length (2 bytes)
        let len = plaintext.len() as u16;
        let enc_len = self.send_cipher.encrypt(&[], &len.to_be_bytes());
        self.stream.write_all(&enc_len).await?;

        // Encrypt body
        let enc_body = self.send_cipher.encrypt(&[], plaintext);
        self.stream.write_all(&enc_body).await?;
        self.stream.flush().await
    }

    /// Receive and decrypt a message.
    pub async fn recv(&mut self) -> io::Result<Vec<u8>> {
        // Read encrypted length (2 + 16 = 18 bytes)
        let mut enc_len = [0u8; 18];
        self.stream.read_exact(&mut enc_len).await?;
        let len_bytes = self.recv_cipher.decrypt(&[], &enc_len)?;
        let len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;

        // Read encrypted body (len + 16 bytes)
        let mut enc_body = vec![0u8; len + MAC_SIZE];
        self.stream.read_exact(&mut enc_body).await?;
        self.recv_cipher.decrypt(&[], &enc_body)
    }
}
