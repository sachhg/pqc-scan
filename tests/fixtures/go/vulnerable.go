// Fixture exercising pqc-scan Go detection rules.
package main

import (
	"crypto/aes"
	"crypto/des"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"

	"crypto/ecdh"
	"crypto/tls"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/curve25519"
)

func vulnerable() {
	// PQC001 RSA key generation -> RSA-2048
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// PQC002 RSA encryption / padding
	ct, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &rsaKey.PublicKey, []byte("msg"), nil)

	// PQC003 RSA signature
	sig, _ := rsa.SignPKCS1v15(rand.Reader, rsaKey, 0, []byte("digest"))

	// PQC004 ECDSA key generation -> ECDSA-P-256
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// PQC004 ECDSA signing
	r, s, _ := ecdsa.Sign(rand.Reader, ecKey, []byte("digest"))
	// PQC004 with P-384 / P-521 curve labels
	ecKey384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ecKey521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

	// PQC005 ECDH NIST P-curve key exchange
	ecdhCurve := ecdh.P256()
	// PQC005 ECDH X25519 (chained)
	x25519Key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	// PQC005 curve25519 low-level key exchange -> X25519
	shared, _ := curve25519.X25519([]byte("scalar"), curve25519.Basepoint)

	// PQC006 Ed25519 key generation
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	// PQC006 Ed25519 signing
	edSig := ed25519.Sign(edPriv, []byte("message"))

	// PQC008 DSA key generation
	var dsaKey dsa.PrivateKey
	_ = dsa.GenerateKey(&dsaKey, rand.Reader)

	// PQC009 SHA-1
	sha1Hash := sha1.New()
	sha1Sum := sha1.Sum([]byte("data"))

	// PQC010 MD5
	md5Hash := md5.New()
	md5Sum := md5.Sum([]byte("data"))

	// PQC013 DES
	desBlock, _ := des.NewCipher([]byte("8bytekey"))
	// PQC013 3DES
	tdesBlock, _ := des.NewTripleDESCipher([]byte("24bytekey24bytekey24byte"))

	_ = ct
	_ = sig
	_, _, _ = r, s, ecKey
	_, _ = ecKey384, ecKey521
	_, _ = ecdhCurve, x25519Key
	_ = shared
	_, _ = edPub, edSig
	_ = sha1Hash
	_ = sha1Sum
	_ = md5Hash
	_ = md5Sum
	_ = desBlock
	_ = tdesBlock
}

// weakTLS exercises crypto/tls configuration and golang-jwt detection.
func weakTLS() {
	// PQC012 — pins TLS 1.0 and enables RSA/3DES cipher suites.
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS10,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
	// PQC011 — golang-jwt asymmetric signing method.
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, nil)

	_ = cfg
	_ = token
}

// modernTLS must yield ZERO findings: TLS 1.3 only, AEAD suites.
func modernTLS() {
	good := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256},
	}
	_ = good
}

// safe exercises algorithms that must yield ZERO findings.
func safe() {
	// SHA-256 is quantum-acceptable.
	h := sha256.New()
	sum := sha256.Sum256([]byte("data"))
	// AES is quantum-acceptable.
	block, _ := aes.NewCipher([]byte("0123456789abcdef"))

	_ = h
	_ = sum
	_ = block
}

func main() {
	vulnerable()
	weakTLS()
	modernTLS()
	safe()
}
