// Fixture: Node.js crypto module usage that pqc-scan must flag.
const crypto = require('crypto');
const forge = require('node-forge');

// PQC001 — RSA key pair generation.
crypto.generateKeyPair('rsa', { modulusLength: 2048 }, (err, publicKey, privateKey) => {});

// PQC004 — EC key pair generation.
crypto.generateKeyPair('ec', { namedCurve: 'P-256' }, (err, publicKey, privateKey) => {});

// PQC007 — classical Diffie-Hellman.
const dh = crypto.createDiffieHellman(2048);

// WebCrypto API
async function webcrypto() {
  // PQC002 — RSA-OAEP.
  await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048 }, true, ['encrypt']);
  // PQC005 — ECDH.
  await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
  // PQC004 — ECDSA.
  await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign']);
}

// PQC001 — node-forge RSA key pair.
const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048 });

// PQC002 — RSA-only encryption primitive.
const wrapped = crypto.publicEncrypt(publicKeyPem, Buffer.from('secret'));

// PQC003 — RSA signature via createSign.
const signer = crypto.createSign('RSA-SHA256');

module.exports = { webcrypto, dh, keypair, wrapped, signer };
