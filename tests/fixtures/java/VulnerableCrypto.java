package com.example.crypto;

import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

/**
 * Fixture exercising every Java rule the analyzer should fire on, plus a
 * deliberately-safe method that must yield ZERO findings.
 */
public class VulnerableCrypto {

    // --- KeyPairGenerator: PQC001 / PQC004 / PQC008 / PQC007 / PQC006 ------ //
    void keyPairGenerators() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");          // PQC001
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");           // PQC004
        KeyPairGenerator ecdsa = KeyPairGenerator.getInstance("ECDSA");     // PQC004
        KeyPairGenerator dsa = KeyPairGenerator.getInstance("DSA");         // PQC008
        KeyPairGenerator dh = KeyPairGenerator.getInstance("DH");           // PQC007
        KeyPairGenerator dh2 = KeyPairGenerator.getInstance("DiffieHellman"); // PQC007
        KeyPairGenerator eddsa = KeyPairGenerator.getInstance("EdDSA");     // PQC006
        KeyPairGenerator ed25519 = KeyPairGenerator.getInstance("Ed25519"); // PQC006
    }

    // --- KeyFactory: PQC001 / PQC004 / PQC008 ----------------------------- //
    void keyFactories() throws Exception {
        KeyFactory rsa = KeyFactory.getInstance("RSA");                     // PQC001
        KeyFactory ec = KeyFactory.getInstance("EC");                       // PQC004
        KeyFactory dsa = KeyFactory.getInstance("DSA");                     // PQC008
    }

    // --- Signature: PQC003 (+PQC009/PQC010) / PQC004 / PQC008 ------------- //
    void signatures() throws Exception {
        Signature s1 = Signature.getInstance("SHA256withRSA");             // PQC003
        Signature s2 = Signature.getInstance("SHA1withRSA");               // PQC003 + PQC009
        Signature s3 = Signature.getInstance("MD5withRSA");                // PQC003 + PQC010
        Signature s4 = Signature.getInstance("SHA256withECDSA");           // PQC004
        Signature s5 = Signature.getInstance("NONEwithECDSA");             // PQC004
        Signature s6 = Signature.getInstance("SHA1withDSA");               // PQC008
    }

    // --- MessageDigest: PQC009 / PQC010 ----------------------------------- //
    void digests() throws Exception {
        MessageDigest d1 = MessageDigest.getInstance("SHA-1");             // PQC009
        MessageDigest d2 = MessageDigest.getInstance("SHA1");              // PQC009
        MessageDigest d3 = MessageDigest.getInstance("MD5");               // PQC010
    }

    // --- Cipher: PQC002 / PQC013 ------------------------------------------ //
    void ciphers() throws Exception {
        Cipher c1 = Cipher.getInstance("RSA/ECB/OAEPPadding");             // PQC002
        Cipher c2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");            // PQC002
        Cipher c3 = Cipher.getInstance("DES");                            // PQC013 (DES)
        Cipher c4 = Cipher.getInstance("DESede/CBC/PKCS5Padding");         // PQC013 (3DES)
    }

    // --- KeyGenerator (symmetric DES/3DES): PQC013 ------------------------ //
    void symmetricKeyGen() throws Exception {
        KeyGenerator k1 = KeyGenerator.getInstance("DES");                 // PQC013 (DES)
        KeyGenerator k2 = KeyGenerator.getInstance("DESede");              // PQC013 (3DES)
    }

    // --- Bouncy Castle lightweight API: PQC001 / PQC004 / PQC006 ---------- //
    void bouncyCastle() throws Exception {
        RSAKeyGenerationParameters rsaParams =
            new RSAKeyGenerationParameters(null, null, 2048, 80);            // PQC001
        ECKeyPairGenerator ecGen = new ECKeyPairGenerator();                 // PQC004
        Ed25519Signer edSigner = new Ed25519Signer();                        // PQC006
    }

    // --- SSLContext pinning a legacy protocol: PQC012 ---------------------- //
    void sslContexts() throws Exception {
        javax.net.ssl.SSLContext bad = javax.net.ssl.SSLContext.getInstance("SSLv3"); // PQC012
        javax.net.ssl.SSLContext ok = javax.net.ssl.SSLContext.getInstance("TLSv1.3"); // safe
    }

    // --- SAFE: must produce ZERO findings --------------------------------- //
    void safe() throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        KeyGenerator aes = KeyGenerator.getInstance("AES");
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
    }
}
