// Fixture: quantum-vulnerable cryptography across the common Rust crates.
// Every construct here must produce a finding.

use ed25519_dalek::SigningKey as EdSigningKey;
use jsonwebtoken::{Algorithm, EncodingKey};
use md5::Md5;
use openssl::dsa::Dsa;
use openssl::hash::MessageDigest;
use openssl::rsa::Rsa;
use openssl::ssl::SslVersion;
use openssl::symm::Cipher;
use p256::ecdsa::SigningKey;
use rand::rngs::OsRng;
use ring::{agreement, signature};
use rsa::{Oaep, RsaPrivateKey};
use sha1::{Digest, Sha1};
use x25519_dalek::EphemeralSecret;

// --- RustCrypto: rsa ------------------------------------------------------ //

fn rsa_keygen() -> RsaPrivateKey {
    let mut rng = OsRng;
    RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate key")
}

fn rsa_encrypt_padding() -> Oaep {
    Oaep::new::<sha2::Sha256>()
}

fn rsa_signing(key: &RsaPrivateKey) -> rsa::pkcs1v15::SigningKey<sha2::Sha256> {
    rsa::pkcs1v15::SigningKey::new(key.clone())
}

fn rsa_pss(key: &RsaPrivateKey) -> rsa::pss::SigningKey<sha2::Sha256> {
    rsa::pss::SigningKey::new(key.clone())
}

// --- RustCrypto: elliptic curves ------------------------------------------ //

fn ecdsa_p256() -> SigningKey {
    SigningKey::random(&mut OsRng)
}

fn ecdsa_p384() -> p384::ecdsa::SigningKey {
    p384::ecdsa::SigningKey::random(&mut OsRng)
}

fn secp256k1_key() -> k256::SecretKey {
    k256::SecretKey::random(&mut OsRng)
}

fn ecdh_p256() -> p256::ecdh::EphemeralSecret {
    p256::ecdh::EphemeralSecret::random(&mut OsRng)
}

// --- Edwards / Montgomery curves ------------------------------------------ //

fn ed25519_keypair() -> EdSigningKey {
    EdSigningKey::generate(&mut OsRng)
}

fn x25519_exchange() -> EphemeralSecret {
    EphemeralSecret::random_from_rng(OsRng)
}

// --- Hashes and legacy ciphers -------------------------------------------- //

fn sha1_digest(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn md5_digest(data: &[u8]) -> Vec<u8> {
    Md5::digest(data).to_vec()
}

fn triple_des_cipher() -> Cipher {
    Cipher::des_ede3_cbc()
}

fn single_des_cipher() -> Cipher {
    Cipher::des_cbc()
}

// --- openssl bindings ------------------------------------------------------ //

fn openssl_rsa() -> Rsa<openssl::pkey::Private> {
    Rsa::generate(2048).unwrap()
}

fn openssl_ec() -> openssl::ec::EcKey<openssl::pkey::Private> {
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    openssl::ec::EcKey::generate(&group).unwrap()
}

fn openssl_dsa() -> Dsa<openssl::pkey::Private> {
    Dsa::generate(2048).unwrap()
}

fn openssl_dh() -> openssl::dh::Dh<openssl::pkey::Params> {
    openssl::dh::Dh::get_2048_256().unwrap()
}

fn openssl_sha1() -> MessageDigest {
    MessageDigest::sha1()
}

fn openssl_md5() -> MessageDigest {
    MessageDigest::md5()
}

fn legacy_tls_version() -> SslVersion {
    SslVersion::TLS1
}

// --- ring ------------------------------------------------------------------ //

fn ring_rsa_verify() -> &'static signature::RsaParameters {
    &signature::RSA_PKCS1_2048_8192_SHA256
}

fn ring_ecdsa_signing() -> &'static signature::EcdsaSigningAlgorithm {
    &signature::ECDSA_P256_SHA256_ASN1_SIGNING
}

fn ring_ed25519() -> &'static signature::EdDSAParameters {
    &signature::ED25519
}

fn ring_agreement_x25519() -> &'static agreement::Algorithm {
    &agreement::X25519
}

fn ring_agreement_ecdh() -> &'static agreement::Algorithm {
    &agreement::ECDH_P256
}

// --- JWT ------------------------------------------------------------------- //

fn jwt_algorithm() -> Algorithm {
    Algorithm::RS256
}

fn jwt_key(pem: &[u8]) -> EncodingKey {
    EncodingKey::from_rsa_pem(pem).unwrap()
}
