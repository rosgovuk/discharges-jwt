package uk.gov.ros.discharges.security;

import io.jsonwebtoken.*;
import org.apache.commons.lang.StringUtils;

import java.security.Key;
import java.util.List;
import java.util.Map;

public class Token {
    public static Jws<Claims> verify(String token, Map<String, OpenSshPublicKey> keys) {
        Jws<Claims> claimsJws = Jwts.parser().setSigningKeyResolver(new SigningKeyResolverAdapter() {
            @Override
            public Key resolveSigningKey(JwsHeader header, Claims claims) {

                // Locate the public signing key
                String keyId = header.getKeyId();
                OpenSshPublicKey publicKey = keys.get(keyId);
                if (publicKey != null) {
                    System.out.println("Located key ID " + keyId + ": " + publicKey.decode());
                    return publicKey.decode();
                }
                // If we get here, the key ID is not known:
                throw new SignatureException("Unable to locate signing key " + keyId +
                        " in known public keys: " + keys.keySet());
            }
        }).parseClaimsJws(token);

        return claimsJws;
    }
}
