package store.auth;

import java.util.Base64;
import java.util.Date;
import java.util.Map;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import store.account.AccountOut;

@Service
public class JwtService {

    @Value("${store.jwt.secretKey}")
    private String secretKey;

    public String generate(AccountOut account, long duration) {
        Date now = new Date();
        return Jwts.builder()
            .id(account.id())
            .issuer("Insper::PMA")
            .claims(Map.of("email", account.email()))
            .subject(account.name())
            .notBefore(now)
            .expiration(new Date(now.getTime() + duration))
            .signWith(getKey())
            .compact();
    }

    // valida assinatura, nbf e exp; qualquer problema vira 401
    public String getId(String jwt) {
        try {
            return Jwts.parser().verifyWith(getKey()).build()
                .parseSignedClaims(jwt).getPayload().getId();
        } catch (JwtException | IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid token");
        }
    }

    private SecretKey getKey() {
        return Keys.hmacShaKeyFor(Base64.getDecoder().decode(secretKey));
    }

}
