package uk.gov.ros.discharges.security;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Enumeration;

import com.github.davidcarboni.cryptolite.ByteArray;
import com.github.davidcarboni.cryptolite.SecurityProvider;
import com.nimbusds.jose.jwk.ECKey;

import net.schmizz.sshj.common.Buffer;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.tls.NamedCurve;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.*;
import org.bouncycastle.math.ec.*;

public class AuthorizedKeysDecoder {
    private byte[] bytes;
    private int pos;

    public PublicKey decodePublicKey(String keyLine) throws Exception {
        bytes = null;
        pos = 0;

        // look for the Base64 encoded part of the line to decode
        // both ssh-rsa and ssh-dss begin with "AAAA" due to the length bytes
        for (String part : keyLine.split(" ")) {
            if (part.startsWith("AAAA")) {
                bytes = Base64.decodeBase64(part);
                break;
            }
        }
        if (bytes == null) {
            throw new IllegalArgumentException("no Base64 part to decode");
        }

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

            // The string [identifier] is the identifier of the elliptic curve
            // domain parameters.  The format of this string is specified in
            // Section 6.1 (https://tools.ietf.org/html/rfc5656#section-6.1).
            // Information on the REQUIRED and RECOMMENDED sets of
            // elliptic curve domain parameters for use with this algorithm can be
            // found in Section 10 (https://tools.ietf.org/html/rfc5656#section-10).
            String identifier = decodeType();
            System.out.println("identifier = " + identifier);
            if (!type.endsWith(identifier)) {
                throw new IllegalArgumentException("Invalid identifier " + identifier + " for key type " + type + ".");
            }

            // Q is the public key encoded from an elliptic curve point into an
            // octet string as defined in Section 2.3.3 of [SEC1];
            // (https://tools.ietf.org/html/rfc5656#ref-SEC1)
            // point compression MAY be used.
            BigInteger q = decodeBigInt();
            System.out.println("q = " + q);

            //ECPoint point = getPoint(q, identifier);
            //ECParameterSpec parameterSpec = getECParameterSpec(identifier);
            //ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(point, parameterSpec);
            ECPublicKey keyBC = getKeyBC(q, identifier);
            return keyBC;
        } else {
            throw new IllegalArgumentException("unknown type " + type);
        }
    }

void otherStuff(String identifier) throws NoSuchAlgorithmException, InvalidKeySpecException {
            // Based on reconstructPrivateKey in:
            // http://www.programcreek.com/java-api-examples/index.php?source_dir=bitseal-master/src/org/bitseal/crypt/KeyConverter.java
            // http://www.programcreek.com/java-api-examples/index.php?api=org.spongycastle.jce.spec.ECNamedCurveParameterSpec
            ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec(identifier);
            KeyFactory fact = KeyFactory.getInstance("EC");
            ECCurve curve = params.getCurve();
            java.security.spec.EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, params.getSeed());
            java.security.spec.ECParameterSpec params2 = EC5Util.convertSpec(ellipticCurve, params);


            ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(identifier);
            //org.bouncycastle.math.ec.ECPoint bcPoint = spec.getCurve().decodePoint(Q.toByteArray());

            ECPoint point = null;//EC5Util.convertPoint(curve, bcPoint, false);
            java.security.spec.ECPublicKeySpec keySpec = new java.security.spec.ECPublicKeySpec(point, params2);

            ECPublicKey publicKey = (ECPublicKey) fact.generatePublic(keySpec);








            //BigInteger x = decodeBigInt();
            //BigInteger y = decodeBigInt();
            ECNamedCurveParameterSpec speac = ECNamedCurveTable.getParameterSpec(identifier);
            //ECPublicKeySpec pubKey = new ECPublicKeySpec(spec.getCurve().decodePoint(Q.toByteArray()), spec);
//            ECPoint ecPoint = new ECPoint(x, y);
            ECNamedCurveParameterSpec bcParameterSpec = ECNamedCurveTable.getParameterSpec(identifier);
            //ECParameterSpec ecParameterSpec = EC5Util.convertSpec(spec.getCurve(), bcParameterSpec);
            //ECParameterSpec ecParameterSpec = parameterSpec.;
            //new ECParameterSpec(parameterSpec.getCurve()., parameterSpec.getG(), parameterSpec.getN(), parameterSpec.getH().intValue());
//            ECParameterSpec ecParameterSpec = ECKey.Curve.P_256.toECParameterSpec();
            //org.bouncycastle.math.ec.ECPoint bcaPoint = spec.getCurve().decodePoint(q.toByteArray());

            //EC5Util.convertPoint(ecParameterSpec, bcPoint, false);
            //ECPoint ecPoint = new ECPoint(bcPoint.getAffineXCoord().toBigInteger(), bcPoint.getAffineYCoord().toBigInteger());
           // ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
            //return publicKey; //KeyFactory.getInstance("EC").generatePublic(publicKeySpec);
        }

    ECPublicKey getKeyBC(BigInteger q, String identifier) {
        // https://stackoverflow.com/questions/42639620/generate-ecpublickey-from-ecprivatekey
        try {
            // This only works with the Bouncycastle library:
            Security.addProvider(new BouncyCastleProvider());
            //KeyFactory keyFactory = KeyFactory.getInstance("EC");
            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
            ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(bcName(identifier));
            org.bouncycastle.math.ec.ECPoint point = ecSpec.getCurve().decodePoint(q.toByteArray());
            org.bouncycastle.jce.spec.ECPublicKeySpec pubSpec = new org.bouncycastle.jce.spec.ECPublicKeySpec(point, ecSpec);
            ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(pubSpec);
            return publicKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    ECParameterSpec getECParameterSpec(String identifier) {

        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(bcName(identifier)));
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (InvalidParameterSpecException | NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Unable to get parameter spc for identifier " + identifier, e);
        }

        // Using Jose JWT library:
//        ECKey.Curve curve;
//        if (identifier.equals("nistp256"))
//            curve = ECKey.Curve.P_256;
//        else if (identifier.endsWith("nistp384"))
//            curve = ECKey.Curve.P_384;
//        else if (identifier.endsWith("nistp521"))
//            curve = ECKey.Curve.P_521;
//        else
//            throw new IllegalArgumentException("Unsupported curve " + identifier);
//        return curve.toECParameterSpec();
    }

    String bcName(String identifier) {

        // http://www.bouncycastle.org/wiki/pages/viewpage.action?pageId=362269#SupportedCurves(ECDSAandECGOST)-NIST(aliasesforSECcurves)

        //Enumeration names = ECNamedCurveTable.getNames();
        //while (names.hasMoreElements()) {
        //    System.out.println(names.nextElement());
        //}

        return identifier.replace("nist", "sec") + "r1";
    }

    ECPublicKey JCA(String identifier, byte[] x, byte[] y, ECParameterSpec ecParameters) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException {
        ECPoint pubPoint = new ECPoint(new BigInteger(1, x),new BigInteger(1, y));
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(pubPoint, ecParameters);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return (ECPublicKey)keyFactory.generatePublic(pubSpec);
    }

    private String decodeType() {
        int len = decodeInt();
        String type = new String(bytes, pos, len);
        pos += len;
        System.out.println("type = " + type);
        return type;
    }

    private int decodeInt() {
        int header = ((bytes[pos++] & 0xFF) << 24) | ((bytes[pos++] & 0xFF) << 16)
                | ((bytes[pos++] & 0xFF) << 8) | (bytes[pos++] & 0xFF);
        System.out.println("header = " + header + " (" + (bytes.length - pos) + " bytes remaining)");
        return header;
    }

    private BigInteger decodeBigInt() {
        int len = decodeInt();
        byte[] bigIntBytes = new byte[len];
        System.arraycopy(bytes, pos, bigIntBytes, 0, len);
        pos += len;
        System.out.println("bigIntBytes = " + new BigInteger(bigIntBytes));
        return new BigInteger(bigIntBytes);
    }

//    public static void main(String[] args) throws Exception {
//        AuthorizedKeysDecoder decoder = new AuthorizedKeysDecoder();
//        File file = new File("authorized_keys");
//        Scanner scanner = new Scanner(file).useDelimiter("\n");
//        while (scanner.hasNext()) {
//            System.out.println(decoder.decodePublicKey(scanner.next()));
//        }
//        scanner.close();
//    }

    public static void main(String[] args) throws Exception {
        String opensshkey = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFLvYF5x/sDCQ0HmMshZCbRyqR0QW/sF7Xal6IQ2qg3BFiTOv6WFWXOQarHUbkKrM4LPyjx+KWoba2PI93bKYnw= my comment";
        AuthorizedKeysDecoder authorizedKeysDecoder = new AuthorizedKeysDecoder();
        PublicKey publicKey = authorizedKeysDecoder.decodePublicKey(opensshkey);
        byte[] encoded = publicKey.getEncoded();

        // These produce partly-the-same output:
        System.out.println("Original  : " + ByteArray.toHexString(ByteArray.fromBase64String(opensshkey.split(" ")[1])));
        System.out.println("Recovered : " + ByteArray.toHexString(encoded));

        // Attempt to recreate the OpenSSH format:
        byte[] b = new Buffer.PlainBuffer().putPublicKey(publicKey).getCompactData();
        String openssh = ByteArray.toHexString(b);
        System.out.println("openssh   : " + ByteArray.toHexString(b));
        System.out.println("openssh   : " + ByteArray.toBase64String(b));
    }

   // Original  : 0000001365636473612d736861322d6e69737470323536000000086e69737470323536000000410452ef605e71fec0c24341e632c85909b472a91d105bfb05ed76a5e88436aa0dc11624cebfa5855973906ab1d46e42ab3382cfca3c7e296a1b6b63c8f776ca627c
   // Recovered :                           3059301306072a8648ce3d020106082a8648ce3d0301070342000452ef605e71fec0c24341e632c85909b472a91d105bfb05ed76a5e88436aa0dc11624cebfa5855973906ab1d46e42ab3382cfca3c7e296a1b6b63c8f776ca627c
}