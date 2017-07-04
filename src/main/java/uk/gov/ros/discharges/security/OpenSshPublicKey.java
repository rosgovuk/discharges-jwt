package uk.gov.ros.discharges.security;

import com.github.davidcarboni.cryptolite.ByteArray;
import io.jsonwebtoken.*;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.ECPoint;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;

/**
 * Enables OpenSSH-format public keys to be read to a JCE PublicKey instance.
 * <p>
 * See the following StackOverflow questions for more information:
 * <ul>
 * <li>https://stackoverflow.com/questions/44808132/using-openssh-public-key-ecdsa-sha2-nistp256-with-java-security</li>
 * <li>https://stackoverflow.com/questions/44829426/can-i-create-a-jce-ecpublickey-from-a-q-value-from-an-openssh-public-key-and-ecp</li>
 * </ul>
 */
public class OpenSshPublicKey {
    private byte[] bytes;
    private int pos;

    static {
        // Add the Bouncycastle provider if necessary.
        // This is currently required to recover an elliptic curve public key from the
        // Q value contained in OpenSSH-formated public key data.
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Decodes an OpenSSH-formatted public key, as found in id_xxx.pub, authorized_keys and the
     * Github API signature for public keys (e.g. https://api.github.com/users/davidcarboni/keys)
     *
     * @param opensshPublicKey The String content of the OpenSSH public key.
     * @return The decoded public key. If decoding fails, an IllegalArgumentException is thrown.
     */
    public PublicKey decodePublicKey(String opensshPublicKey) {
        bytes = null;
        pos = 0;

        bytes = getKeyBytes(opensshPublicKey);

        try {
            String type = decodeString();
            if (type.equals("ssh-rsa")) {
                BigInteger e = decodeBigInt();
                BigInteger m = decodeBigInt();
                RSAPublicKeySpec spec = new RSAPublicKeySpec(m, e);
                return KeyFactory.getInstance("RSA").generatePublic(spec);
            } else if (type.equals("ssh-dss")) {
                BigInteger p = decodeBigInt();
                BigInteger q = decodeBigInt();
                BigInteger g = decodeBigInt();
                BigInteger y = decodeBigInt();
                DSAPublicKeySpec spec = new DSAPublicKeySpec(y, p, q, g);
                return KeyFactory.getInstance("DSA").generatePublic(spec);
            } else if (type.startsWith("ecdsa-sha2-") &&
                    (type.endsWith("nistp256") || type.endsWith("nistp384") || type.endsWith("nistp521"))) {
                // Based on RFC 5656, section 3.1 (https://tools.ietf.org/html/rfc5656#section-3.1)
                String identifier = decodeString();
                BigInteger q = decodeBigInt();
                ECPoint ecPoint = getECPoint(q, identifier);
                ECParameterSpec ecParameterSpec = getECParameterSpec(identifier);
                ECPublicKeySpec spec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
                return KeyFactory.getInstance("EC").generatePublic(spec);
            } else {
                throw new IllegalArgumentException("Unsupported key type " + type);
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalArgumentException("Unable to decode public key", e);
        }
    }

    /**
     * Provides a means to get from a parsed Q value to the X and Y point values.
     * that can be used to create and ECPoint compatible with ECPublicKeySpec.
     *
     * @param q          According to RFC 5656:
     *                   "Q is the public key encoded from an elliptic curve point into an octet string"
     * @param identifier According to RFC 5656:
     *                   "The string [identifier] is the identifier of the elliptic curve domain parameters."
     * @return An ECPoint suitable for creating a JCE ECPublicKeySpec.
     */
    ECPoint getECPoint(BigInteger q, String identifier) {
        String name = identifier.replace("nist", "sec") + "r1";
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(name);
        org.bouncycastle.math.ec.ECPoint point = ecSpec.getCurve().decodePoint(q.toByteArray());
        BigInteger x = point.getAffineXCoord().toBigInteger();
        BigInteger y = point.getAffineXCoord().toBigInteger();
        return new ECPoint(x,y);
    }

    /**
     * Gets the curve parameters for the given key type identifier.
     * @param identifier According to RFC 5656:
     *                   "The string [identifier] is the identifier of the elliptic curve domain parameters."
     * @return An ECParameterSpec suitable for creating a JCE ECPublicKeySpec.
     */
    ECParameterSpec getECParameterSpec(String identifier) {
        try {
            // http://www.bouncycastle.org/wiki/pages/viewpage.action?pageId=362269#SupportedCurves(ECDSAandECGOST)-NIST(aliasesforSECcurves)
            String name = identifier.replace("nist", "sec") + "r1";
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(name));
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (InvalidParameterSpecException | NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Unable to get parameter spec for identifier " + identifier, e);
        }
    }

    /**
     * Looks for the Base64 encoded part of the line to decode.
     * The key type can be interpreted as base 64, so since keys begin with "AAAA" due to the length bytes,
     * we can use that as an indicator.
     *
     * @param opensshPublicKey An open-ssh format key (of the form: [type] [base-64.....] [comment])
     * @return The bytes from the base-64 section. If not found, an IllegalArgumentException is throuwn.
     */
    private byte[] getKeyBytes(String opensshPublicKey) {

        for (String part : opensshPublicKey.split(" ")) {

            if (Base64.isBase64(part) && part.startsWith("AAAA")) {
                return Base64.decodeBase64(part);
            }
        }
        throw new IllegalArgumentException("no Base64 part to decode");
    }

    /**
     * Parses a 4-byte int value. This is used to read a field header.
     * The field header specifies the byte length of a field.
     *
     * @return The number of bytes to read for the current field.
     */
    private int decodeInt() {
        int header = ((bytes[pos++] & 0xFF) << 24) | ((bytes[pos++] & 0xFF) << 16)
                | ((bytes[pos++] & 0xFF) << 8) | (bytes[pos++] & 0xFF);
        return header;
    }

    /**
     * @return A String field.
     */
    private String decodeString() {
        int len = decodeInt();
        String type = new String(bytes, pos, len);
        pos += len;
        return type;
    }

    /**
     * @return A BigInt field.
     */
    private BigInteger decodeBigInt() {
        int len = decodeInt();
        byte[] bigIntBytes = new byte[len];
        System.arraycopy(bytes, pos, bigIntBytes, 0, len);
        pos += len;
        return new BigInteger(bigIntBytes);
    }


    public static void main(String[] args) throws IOException {
        String openSshPublicKey;
        try (InputStream input = OpenSshPublicKey.class.getClassLoader().getResourceAsStream("keys/nistp256.pub")) {
            openSshPublicKey = IOUtils.toString(input, StandardCharsets.US_ASCII);
        }
        String openSshPrivateKey;
        try (InputStream input = OpenSshPublicKey.class.getClassLoader().getResourceAsStream("keys/nistp256")) {
            openSshPrivateKey = IOUtils.toString(input, StandardCharsets.US_ASCII);
        }
        OpenSshPublicKey decoder = new OpenSshPublicKey();
        PublicKey publicKeyQ = decoder.decodePublicKey(openSshPublicKey);
        PublicKey publicKeyXY = decoder.decodePublicKeyXY(openSshPublicKey);

        PrivateKey privateKey;
        try (Reader reader = new StringReader(openSshPrivateKey)) {

            Object object;
            try (PEMParser pp = new PEMParser(reader)) {
                object = pp.readObject();
            }

            if (PEMKeyPair.class.isAssignableFrom(object.getClass())) {
                PEMKeyPair pemKeypair = (PEMKeyPair) object;
                privateKey = new JcaPEMKeyConverter().getKeyPair(pemKeypair).getPrivate();
            }else if (PrivateKeyInfo.class.isAssignableFrom(object.getClass())) {
                PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) object;
                privateKey = new JcaPEMKeyConverter().getPrivateKey(privateKeyInfo);
            } else {
                throw new IllegalArgumentException("Type " + object.getClass().getSimpleName() + " is not currently supported.");
            }
        }

        String token = Jwts.builder().setSubject("David").signWith(SignatureAlgorithm.ES256, privateKey).compact();
        String tokenQ = Jwts.builder().setSubject("David").signWith(SignatureAlgorithm.ES256, privateKey).compact();



        Jws<Claims> claimsQ = Jwts.parser().setSigningKeyResolver(new SigningKeyResolverAdapter() {
            @Override
            public Key resolveSigningKey(JwsHeader header, Claims claims) {
                return publicKeyQ;
            }}).parseClaimsJws(token);
        System.out.println("claimsQ = " + claimsQ);

        Jws<Claims> claimsXY = Jwts.parser().setSigningKeyResolver(new SigningKeyResolverAdapter() {
            @Override
            public Key resolveSigningKey(JwsHeader header, Claims claims) {
                return publicKeyXY;
            }}).parseClaimsJws(token);
        System.out.println("claimsXY = " + claimsXY);
    }
}