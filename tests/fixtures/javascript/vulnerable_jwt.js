// Fixture: jsonwebtoken with quantum-vulnerable asymmetric algorithms (PQC011).
const jwt = require('jsonwebtoken');

function issueRs256(payload, privateKey) {
  // PQC011 — RS256 (RSA signature).
  return jwt.sign(payload, privateKey, { algorithm: 'RS256' });
}

function issueEs256(payload, privateKey) {
  // PQC011 — ES256 (ECDSA signature).
  return jwt.sign(payload, privateKey, { algorithm: 'ES256' });
}

function verify(token, publicKey) {
  // PQC011 — verification restricted to an asymmetric algorithm.
  return jwt.verify(token, publicKey, { algorithms: ['RS256'] });
}

const { SignJWT, jwtVerify } = require('jose');

async function issueJose(claims, privateKey) {
  // PQC011 — jose: asymmetric algorithm in the protected header.
  return new SignJWT(claims).setProtectedHeader({ alg: 'RS256' }).sign(privateKey);
}

async function verifyJose(token, publicKey) {
  // PQC011 — jose: verification restricted to an asymmetric algorithm.
  return jwtVerify(token, publicKey, { algorithms: ['ES384'] });
}

module.exports = { issueRs256, issueEs256, verify, issueJose, verifyJose };
