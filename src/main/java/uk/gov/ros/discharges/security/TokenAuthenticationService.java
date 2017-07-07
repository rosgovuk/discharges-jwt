package uk.gov.ros.discharges.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

import static java.util.Collections.emptyList;

class TokenAuthenticationService {

    static Authentication getAuthentication(HttpServletRequest request) {
        String token = request.getHeader("Authorization");
        if (token != null) {
            token = token.replace("Bearer", "").trim();
            Map<String, OpenSshPublicKey> publicKeys = Keys.listPublicKeys();
            Jws<Claims> claims = Token.verify(token, publicKeys);
            String user = claims.getBody().getSubject();
            return user != null ?
                    new UsernamePasswordAuthenticationToken(user, null, emptyList()) :
                    null;
        }
        return null;
    }

}