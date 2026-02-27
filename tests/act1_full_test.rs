/// Full Act 1 test against BOLT 8 vector.
/// Uses known keys to verify exact byte output.

use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap())
        .collect()
}

#[test]
fn test_full_act1_bolt8_vector() {
    let protocol_name = b"Noise_XK_secp256k1_ChaChaPoly_SHA256";
    let prologue = b"lightning";

    // Known values from BOLT 8
    let rs_pub = hex("028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7");
    let e_priv = secp256k1::SecretKey::from_slice(&[0x12u8; 32]).unwrap();
    let e_pub = hex("036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7");

    // Step 1: Initialize
    let mut h: [u8; 32] = Sha256::digest(protocol_name).into();
    let mut ck = h;
    assert_eq!(hex::encode(&ck), "2640f52eebcd9e882958951c794250eedb28002c05d7dc2ea0f195406042caf1");

    // Step 2: mixHash(prologue)
    h = sha256_cat(&h, prologue);

    // Step 3: mixHash(rs.pub)
    h = sha256_cat(&h, &rs_pub);

    // Act 1 step 1: mixHash(e.pub)
    h = sha256_cat(&h, &e_pub);
    assert_eq!(hex::encode(&h), "9e0e7de8bb75554f21db034633de04be41a2b8a18da7a319a03c803bf02b396c");
    println!("✅ h after mixHash(e.pub) matches");

    // Act 1 step 2: es = ECDH(e.priv, rs.pub)
    let rs_pk = secp256k1::PublicKey::from_slice(&rs_pub).unwrap();
    let es = secp256k1::ecdh::SharedSecret::new(&rs_pk, &e_priv);
    assert_eq!(hex::encode(es.secret_bytes()), "1e2fb3c8fe8fb9f262f649f64d26ecf0f2c0a805a767cf02dc2d77a6ef1fdcc3");
    println!("✅ es matches");

    // Act 1 step 3: ck, temp_k1 = HKDF(ck, es)
    let hk = Hkdf::<Sha256>::new(Some(&ck), &es.secret_bytes());
    let mut okm = [0u8; 64];
    hk.expand(&[], &mut okm).unwrap();
    ck.copy_from_slice(&okm[..32]);
    let mut temp_k1 = [0u8; 32];
    temp_k1.copy_from_slice(&okm[32..]);

    assert_eq!(hex::encode(&ck), "b61ec1191326fa240decc9564369dbb3ae2b34341d1e11ad64ed89f89180582f");
    assert_eq!(hex::encode(&temp_k1), "e68f69b7f096d7917245f5e5cf8ae1595febe4d4644333c99f9c4a1282031c9f");
    println!("✅ ck and temp_k1 match");

    // Act 1 step 4: c = encryptWithAD(temp_k1, 0, h, empty)
    let cipher = ChaCha20Poly1305::new_from_slice(&temp_k1).unwrap();
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let c = cipher.encrypt(nonce, chacha20poly1305::aead::Payload {
        msg: &[],
        aad: &h,
    }).unwrap();
    assert_eq!(hex::encode(&c), "0df6086551151f58b8afe6c195782c6a");
    println!("✅ MAC tag matches");

    // Act 1 step 5: h = SHA256(h || c)
    h = sha256_cat(&h, &c);
    assert_eq!(hex::encode(&h), "9d1ffbb639e7e20021d9259491dc7b160aab270fb1339ef135053f6f2cebe9ce");
    println!("✅ h after mixHash(c) matches");

    // Full Act 1 output: 0x00 || e.pub || c
    let expected_act1 = hex("00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a");
    let mut act1 = vec![0u8];
    act1.extend_from_slice(&e_pub);
    act1.extend_from_slice(&c);
    assert_eq!(act1, expected_act1);
    println!("✅ Full Act 1 output matches BOLT 8 vector!");
    println!("   All crypto primitives verified correct.");
}

fn sha256_cat(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}
