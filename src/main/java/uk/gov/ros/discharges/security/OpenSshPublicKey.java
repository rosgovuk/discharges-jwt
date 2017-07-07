package uk.gov.ros.discharges.security;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
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

    private String opensshPublicKey;
    private byte[] bytes;
    private int pos;

    /**
     * @param opensshPublicKey The String content of the OpenSSH public key.
     */
    public OpenSshPublicKey(String opensshPublicKey) {
        this.opensshPublicKey = opensshPublicKey;
    }

    /**
     * Decodes an OpenSSH-formatted public key, as found in id_xxx.pub, authorized_keys and the
     * Github API signature for public keys (e.g. https://api.github.com/users/davidcarboni/keys)
     *
     * @return The decoded public key. If decoding fails, an IllegalArgumentException is thrown.
     */
    public PublicKey decode() {
        bytes = null;
        pos = 0;

        bytes = getKeyBytes(opensshPublicKey);

        try {
            String type = decodeType();
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
                String identifier = decodeType();
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
     * that can be used to create a JCE ECPoint for an ECPublicKeySpec.
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
        BigInteger y = point.getAffineYCoord().toBigInteger();
        return new ECPoint(x, y);
    }

    /**
     * Gets the curve parameters for the given key type identifier.
     *
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
     * @return A String field.
     */
    private String decodeType() {
        int len = decodeInt();
        String type = new String(bytes, pos, len);
        pos += len;
        return type;
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
     * @return A BigInt field.
     */
    private BigInteger decodeBigInt() {
        int len = decodeInt();
        byte[] bigIntBytes = new byte[len];
        System.arraycopy(bytes, pos, bigIntBytes, 0, len);
        pos += len;
        return new BigInteger(bigIntBytes);
    }

    @Override
    public String toString() {
        return opensshPublicKey;
    }
}