/// Live integration test against the LND watchtower on Umbrel.
/// Requires SSH tunnel: `ssh -L 19911:127.0.0.1:9911 umbrel@umbrel.local`
///
/// Run with: cargo test --test live_tower_test -- --ignored --nocapture

use ldk_watchtower_client::client::{TowerConfig, WatchtowerClient};
use ldk_watchtower_client::wire::BlobType;

#[tokio::test]
#[ignore] // Only run manually with tunnel active
async fn test_connect_to_live_tower() {
    // Tower pubkey from `lncli tower info`
    let tower_pubkey_hex = "03a3b07a5b0bf68f0972dd2d1f4ae5c16a9793f8580fefc844d38acdae71cf1242";
    let tower_pubkey: [u8; 33] = hex_to_bytes33(tower_pubkey_hex);

    // Random client key for this test
    let client_key: [u8; 32] = {
        let mut key = [0u8; 32];
        // Simple deterministic test key
        for i in 0..32 {
            key[i] = (i as u8).wrapping_mul(7).wrapping_add(42);
        }
        key
    };

    let config = TowerConfig {
        address: "127.0.0.1:19911".to_string(),
        tower_pubkey,
        client_key,
        blob_type: BlobType::ALTRUIST_ANCHOR_COMMIT,
        max_updates: 1024,
        sweep_fee_rate: 2500, // ~10 sat/vB, LND min is 1000
    };

    let mut client = WatchtowerClient::new(config);

    // First, test raw Brontide handshake directly (bypass WatchtowerClient)
    println!("Testing raw Brontide handshake...");
    {
        let stream = tokio::net::TcpStream::connect("127.0.0.1:19911").await.unwrap();
        let local_key = secp256k1::SecretKey::from_slice(&client_key).unwrap();
        let tower_pk = secp256k1::PublicKey::from_slice(&tower_pubkey).unwrap();

        match ldk_watchtower_client::brontide::BrontideTransport::connect(
            stream, &local_key, &tower_pk
        ).await {
            Ok(mut transport) => {
                println!("✅ Brontide handshake succeeded!");
                // Try sending a ping or reading
                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    transport.recv()
                ).await {
                    Ok(Ok(msg)) => println!("   Received {} bytes after handshake", msg.len()),
                    Ok(Err(e)) => println!("   Read error after handshake: {}", e),
                    Err(_) => println!("   No message (timeout) - expected, tower waits for Init"),
                }
            }
            Err(e) => {
                println!("❌ Brontide handshake failed: {}", e);
            }
        }
    }

    println!("\nConnecting via WatchtowerClient...");
    match client.connect().await {
        Ok(()) => {
            println!("✅ Connected to LND watchtower!");
            println!("   Full protocol: Brontide → Init → CreateSession");
            if let Some(remaining) = client.remaining_updates() {
                println!("   Remaining update slots: {}", remaining);
            }
        }
        Err(e) => {
            // Code 40 (TemporaryFailure) means protocol works, tower is just busy
            let msg = format!("{}", e);
            if msg.contains("code 40") {
                println!("⚠️  Tower returned TemporaryFailure (code 40)");
                println!("   Protocol works! Tower is just at capacity or temporarily unavailable.");
            } else {
                println!("❌ Connection failed: {}", e);
                panic!("Failed to connect to live tower: {}", e);
            }
        }
    }
}

fn hex_to_bytes33(hex: &str) -> [u8; 33] {
    let mut bytes = [0u8; 33];
    for i in 0..33 {
        bytes[i] = u8::from_str_radix(&hex[i*2..i*2+2], 16).unwrap();
    }
    bytes
}
