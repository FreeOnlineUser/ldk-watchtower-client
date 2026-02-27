//! Noise_XK handshake for LND watchtower protocol.
//!
//! LND's watchtower uses the same Noise protocol as Lightning P2P connections:
//! Noise_XK with secp256k1 keys and ChaChaPoly cipher.
//!
//! The handshake pattern:
//!   -> e (initiator sends ephemeral key)
//!   <- e, ee, s, es (responder sends ephemeral + static, DH)
//!   -> s, se (initiator sends static, DH)
//!
//! After handshake, all messages are encrypted with the established session keys.

use snow::{Builder, TransportState};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Noise protocol pattern used by LND (Brontide).
/// Note: LND uses a custom Noise_XK variant with secp256k1.
const NOISE_PATTERN: &str = "Noise_XK_secp256k1_ChaChaPoly_SHA256";

/// Maximum noise message size.
const MAX_MSG_SIZE: usize = 65535;

/// LND Brontide prologue.
const PROLOGUE: &[u8] = b"lightning";

/// Established encrypted transport after Noise handshake.
pub struct NoiseTransport {
    stream: TcpStream,
    noise: TransportState,
    /// Buffer for decrypted incoming messages.
    read_buf: Vec<u8>,
}

impl NoiseTransport {
    /// Perform Noise_XK handshake as initiator (client) connecting to a tower.
    ///
    /// `local_key` is the client's static private key (32 bytes).
    /// `remote_pubkey` is the tower's static public key (33 bytes compressed secp256k1).
    pub async fn connect(
        mut stream: TcpStream,
        local_key: &[u8; 32],
        remote_pubkey: &[u8; 33],
    ) -> io::Result<Self> {
        // Build Noise initiator state.
        // LND uses secp256k1 keys, but snow's secp256k1 resolver expects
        // 32-byte raw secret keys and 33-byte compressed public keys.
        let builder = Builder::new(NOISE_PATTERN.parse().map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("bad noise pattern: {}", e))
        })?)
        .prologue(PROLOGUE)
        .local_private_key(local_key)
        .remote_public_key(remote_pubkey);

        let mut handshake = builder.build_initiator().map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("noise build failed: {}", e))
        })?;

        let mut buf = vec![0u8; MAX_MSG_SIZE];

        // Act 1: -> e
        let len = handshake.write_message(&[], &mut buf).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("act1 write: {}", e))
        })?;
        write_noise_msg(&mut stream, &buf[..len]).await?;

        // Act 2: <- e, ee, s, es
        let msg = read_noise_msg(&mut stream).await?;
        handshake.read_message(&msg, &mut buf).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("act2 read: {}", e))
        })?;

        // Act 3: -> s, se
        let len = handshake.write_message(&[], &mut buf).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("act3 write: {}", e))
        })?;
        write_noise_msg(&mut stream, &buf[..len]).await?;

        // Transition to transport mode
        let noise = handshake.into_transport_mode().map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("transport mode: {}", e))
        })?;

        Ok(Self {
            stream,
            noise,
            read_buf: Vec::new(),
        })
    }

    /// Send an encrypted message.
    pub async fn send(&mut self, plaintext: &[u8]) -> io::Result<()> {
        let mut buf = vec![0u8; plaintext.len() + 64]; // overhead for encryption
        let len = self.noise.write_message(plaintext, &mut buf).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("encrypt: {}", e))
        })?;
        write_noise_msg(&mut self.stream, &buf[..len]).await
    }

    /// Receive and decrypt a message.
    pub async fn recv(&mut self) -> io::Result<Vec<u8>> {
        let msg = read_noise_msg(&mut self.stream).await?;
        let mut buf = vec![0u8; msg.len()];
        let len = self.noise.read_message(&msg, &mut buf).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("decrypt: {}", e))
        })?;
        buf.truncate(len);
        Ok(buf)
    }
}

/// Write a length-prefixed noise message to the stream.
async fn write_noise_msg(stream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    let len = data.len() as u16;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await
}

/// Read a length-prefixed noise message from the stream.
async fn read_noise_msg(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;

    if len > MAX_MSG_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("noise message too large: {} bytes", len),
        ));
    }

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}
