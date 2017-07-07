package uk.gov.ros.discharges;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;

/**
 * Helper class for working with test keys.
 */
public class OpenSshPrivateKey {


    /**
     * Helper method to decode an OpenSSH-formatted private key, as found in id_xxx, providing it has no passphrase.
     * This is useful when generating key pairs for testing using ssh-keygen.
     *
     * @param opensshPrivateKey The String content of the OpenSSH private key.
     * @return The decoded private key. If decoding fails, an IllegalArgumentException is thrown.
     */
    public static PrivateKey decodePrivateKey(String opensshPrivateKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        try (Reader reader = new StringReader(opensshPrivateKey)) {

            Object object;
            try (PEMParser pp = new PEMParser(reader)) {
                object = pp.readObject();
            }

            PrivateKey privateKey;
            if (PEMKeyPair.class.isAssignableFrom(object.getClass())) {
                PEMKeyPair pemKeypair = (PEMKeyPair) object;
                privateKey = new JcaPEMKeyConverter().getKeyPair(pemKeypair).getPrivate();
            } else if (PrivateKeyInfo.class.isAssignableFrom(object.getClass())) {
                PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) object;
                privateKey = new JcaPEMKeyConverter().getPrivateKey(privateKeyInfo);
            } else {
                throw new IllegalArgumentException("Type " + object.getClass().getSimpleName() + " is not currently supported.");
            }

            return privateKey;
        }
    }
}
