package com.aycil.securegate.security;

import com.aycil.securegate.model.UserAccount;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;

@Service
public class JwtService {

    private final SecretKey signingKey;
    private final long expirationMs;

    public JwtService(
            @Value("${security.jwt.secret}") String base64Secret,
            @Value("${security.jwt.expiration-ms:3600000}") long expirationMs
    ) {
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(base64Secret));
        this.expirationMs = expirationMs;
    }

    public String generateToken(UserAccount user) {
        Instant now = Instant.now();
        List<String> roles = user.getRoles().stream().map(Enum::name).toList();
        List<String> scopes = List.copyOf(user.getScopes());

        return Jwts.builder()
                .subject(user.getUsername())
                .claim("principalType", user.getPrincipalType().name())
                .claim("roles", roles)
                .claim("scopes", scopes)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusMillis(expirationMs)))
                .signWith(signingKey)
                .compact();
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    public boolean isTokenValid(String token, String expectedUsername) {
        try {
            Claims claims = extractAllClaims(token);
            Date expiration = claims.getExpiration();
            return expectedUsername.equals(claims.getSubject())
                    && expiration != null
                    && expiration.after(new Date());
        } catch (Exception ex) {
            return false;
        }
    }
}
