// Fixture: quantum-safe Rust cryptography. This file MUST yield zero findings.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use jsonwebtoken::Algorithm;
use sha2::{Digest, Sha256, Sha512};
use sha3::Sha3_256;

// A local type whose name merely resembles a weak primitive. Nothing imports it
// from a crypto crate, so the import gate must keep it quiet.
struct Sha1;
struct Md5;
struct RsaPrivateKey;

impl Sha1 {
    fn new() -> Self {
        Sha1
    }
}

impl Md5 {
    fn digest(_data: &[u8]) -> Vec<u8> {
        Vec::new()
    }
}

fn sha256_digest(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn sha512_digest(data: &[u8]) -> Vec<u8> {
    Sha512::digest(data).to_vec()
}

fn sha3_digest(data: &[u8]) -> Vec<u8> {
    Sha3_256::digest(data).to_vec()
}

fn hmac_tag(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn aes_gcm_encrypt(key: &[u8; 32], nonce: &[u8; 12], data: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
    cipher.encrypt(Nonce::from_slice(nonce), data).unwrap()
}

fn symmetric_jwt() -> Algorithm {
    Algorithm::HS256
}

// Post-quantum primitives are the migration target — never flag them.
fn ml_kem_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = ml_kem::MlKem768::generate(&mut rand::rngs::OsRng);
    (pk.to_vec(), sk.to_vec())
}

fn ml_dsa_sign(msg: &[u8]) -> Vec<u8> {
    let key = ml_dsa::SigningKey::generate(&mut rand::rngs::OsRng);
    key.sign(msg).to_vec()
}

// A local helper whose name contains a weak token but is not the algorithm.
const SHA1_MIGRATION_NOTE: &str = "replaced by SHA-256 in 2024";
