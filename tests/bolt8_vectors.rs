/// BOLT 8 test vectors for Brontide handshake.
/// Reference: https://github.com/lightning/bolts/blob/master/08-transport.md

use sha2::{Digest, Sha256};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap())
        .collect()
}

#[test]
fn test_handshake_state_initialization() {
    let protocol_name = b"Noise_XK_secp256k1_ChaChaPoly_SHA256";
    let prologue = b"lightning";

    // Step 1: h = SHA256(protocolName)
    let h = Sha256::digest(protocol_name);
    let mut h: [u8; 32] = h.into();
    let ck = h;

    // Step 2: ck = h (already done above)

    // Step 3: h = SHA256(h || prologue)
    let mut hasher = Sha256::new();
    hasher.update(&h);
    hasher.update(prologue);
    h.copy_from_slice(&hasher.finalize());

    // Step 4: h = SHA256(h || rs.pub)
    let rs_pub = hex("028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7");
    let mut hasher = Sha256::new();
    hasher.update(&h);
    hasher.update(&rs_pub);
    h.copy_from_slice(&hasher.finalize());

    // ck = SHA256(protocolName) = 0x2640f52eebcd9e882958951c794250eedb28002c05d7dc2ea0f195406042caf1
    let expected_ck = hex("2640f52eebcd9e882958951c794250eedb28002c05d7dc2ea0f195406042caf1");
    assert_eq!(&ck[..], &expected_ck[..], "ck doesn't match BOLT 8");
    println!("✅ ck matches BOLT 8");

    // Now mix ephemeral key (Act 1 step 2):
    // e.pub = 036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7
    let e_pub = hex("036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7");
    let mut hasher = Sha256::new();
    hasher.update(&h);
    hasher.update(&e_pub);
    h.copy_from_slice(&hasher.finalize());

    // Expected h after mixing ephemeral key:
    // h=0x9e0e7de8bb75554f21db034633de04be41a2b8a18da7a319a03c803bf02b396c
    let expected_h = hex("9e0e7de8bb75554f21db034633de04be41a2b8a18da7a319a03c803bf02b396c");
    assert_eq!(&h[..], &expected_h[..], "h after mixing ephemeral key doesn't match BOLT 8");
    println!("✅ h after mixing e.pub matches BOLT 8");

    println!("h (pre-e) = {:02x?}", &hex("9e0e7de8bb75554f21db034633de04be41a2b8a18da7a319a03c803bf02b396c")[..8]);
    println!("✅ Handshake state initialization matches BOLT 8 vectors!");
}

#[test]
fn test_ecdh_bolt8() {
    // e.priv = 0x1212...12
    // rs.pub = 0x028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7
    // es = ECDH(e.priv, rs.pub) = 0x1e2fb3c8fe8fb9f262f649f64d26ecf0f2c0a805a767cf02dc2d77a6ef1fdcc3

    let e_priv = secp256k1::SecretKey::from_slice(&[0x12u8; 32]).unwrap();
    let rs_pub_bytes = hex("028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7");
    let rs_pub = secp256k1::PublicKey::from_slice(&rs_pub_bytes).unwrap();

    let shared = secp256k1::ecdh::SharedSecret::new(&rs_pub, &e_priv);
    let expected = hex("1e2fb3c8fe8fb9f262f649f64d26ecf0f2c0a805a767cf02dc2d77a6ef1fdcc3");

    assert_eq!(shared.secret_bytes(), &expected[..],
        "ECDH result doesn't match BOLT 8 vector");

    println!("es = {:02x?}", &shared.secret_bytes()[..8]);
    println!("✅ ECDH matches BOLT 8 vectors!");
}
