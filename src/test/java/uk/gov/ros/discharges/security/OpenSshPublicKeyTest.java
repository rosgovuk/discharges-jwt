package uk.gov.ros.discharges.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.io.IOUtils;
import org.junit.Test;
import uk.gov.ros.discharges.OpenSshPrivateKey;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;

//2import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Tests that public keys can be decoded.
 */
public class OpenSshPublicKeyTest {

    static String[] keyNames = new String[]{
            "ecdsa256",
            "ecdsa384",
            "ecdsa521",
            "rsa1024",
            "rsa2048",
            "rsa3072",
            "rsa4096"
    };


    static class KeyTest {
        String public_key;
        String x;
        String y;
        String token;

        @Override
        public String toString() {
            return "k: " + public_key + "\n" +
                    "x: " + x + "\n" +
                    "y: " + y + "\n" +
                    "t: " + token;
        }
    }

    @Test
    public void shouldDecodeKeys() throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException, ParseException {

        for (String keyName : keyNames) {

            PrivateKey privateKey;
            try (InputStream input = this.getClass().getClassLoader().getResourceAsStream("keys/" + keyName)) {
                String key = IOUtils.toString(input, StandardCharsets.US_ASCII);
                privateKey = OpenSshPrivateKey.decodePrivateKey(key);
            }

            PublicKey publicKey;
            try (InputStream input = this.getClass().getClassLoader().getResourceAsStream("keys/" + keyName + ".pub")) {
                String key = IOUtils.toString(input, StandardCharsets.US_ASCII);
                publicKey = new OpenSshPublicKey(key).decode();
            }

            String token = sign(privateKey);
            verify(token, publicKey);
        }
    }

    String sign(PrivateKey privateKey) {

        SignatureAlgorithm algorithm;
        if ("ECDSA".equals(privateKey.getAlgorithm()) || "EC".equals(privateKey.getAlgorithm())) {
            algorithm = SignatureAlgorithm.ES256;
        } else if ("RSA".equals(privateKey.getAlgorithm())) {
            algorithm = SignatureAlgorithm.RS256;
        } else {
            throw new IllegalArgumentException("Unknown algorithm: " + privateKey.getAlgorithm());
        }

        // Build the token
        String token = Jwts.builder()
                .setSubject("David")
                .signWith(algorithm, privateKey)
                .compact();

        return token;
    }

    private void verify(String token, PublicKey publicKey) {

        // parse the token
        Jwts.parser()
                .setSigningKey(publicKey)
                .parseClaimsJws(token);
    }
}