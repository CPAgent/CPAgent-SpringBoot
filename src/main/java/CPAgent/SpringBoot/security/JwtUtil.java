package CPAgent.SpringBoot.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtUtil {

    private final Key hmacKey; // for HS256 fallback
    private final PrivateKey rsaPrivateKey; // for RS256 signing
    private final PublicKey rsaPublicKey; // for RS256 verification
    private final long validityMillis;
    private final long refreshValidityMillis;

    public JwtUtil(
            @Value("${jwt.secret:}") String secret,
            @Value("${jwt.private-key-file:}") String privateKeyFileOrPem,
            @Value("${jwt.public-key-file:}") String publicKeyFileOrPem,
            @Value("${jwt.expiration-ms:3600000}") long validityMillis,
            @Value("${jwt.refresh-expiration-ms:1209600000}") long refreshValidityMillis) throws Exception {
        this.validityMillis = validityMillis;
        this.refreshValidityMillis = refreshValidityMillis;

        // Try load RSA keys if provided (either direct PEM text or a file path)
        PrivateKey pKey = null;
        PublicKey pubKey = null;
        if (privateKeyFileOrPem != null && !privateKeyFileOrPem.isBlank()) {
            String pem = readKeyContent(privateKeyFileOrPem);
            pKey = loadPrivateKeyFromPem(pem);
        }
        if (publicKeyFileOrPem != null && !publicKeyFileOrPem.isBlank()) {
            String pem = readKeyContent(publicKeyFileOrPem);
            pubKey = loadPublicKeyFromPem(pem);
        }

        this.rsaPrivateKey = pKey;
        this.rsaPublicKey = pubKey;

        // HMAC key fallback
        if (secret != null && !secret.isBlank()) {
            this.hmacKey = Keys.hmacShaKeyFor(secret.getBytes());
        } else {
            this.hmacKey = null;
        }
    }

    public String generateToken(String email) {
        Date now = new Date();
        Date exp = new Date(now.getTime() + validityMillis);
        JwtBuilder builder = Jwts.builder()
                .setSubject(email)
                .setIssuedAt(now)
                .claim("token_type", "access")
                .setExpiration(exp);

        if (rsaPrivateKey != null) {
            return builder.signWith(rsaPrivateKey, SignatureAlgorithm.RS256).compact();
        }
        if (hmacKey != null) {
            return builder.signWith(hmacKey, SignatureAlgorithm.HS256).compact();
        }
        throw new IllegalStateException("No signing key configured for JWT. Provide rsa private key or jwt.secret.");
    }

    public String generateRefreshToken(String email) {
        Date now = new Date();
        Date exp = new Date(now.getTime() + refreshValidityMillis);
        JwtBuilder builder = Jwts.builder()
                .setSubject(email)
                .setIssuedAt(now)
                .claim("token_type", "refresh")
                .setExpiration(exp);

        if (rsaPrivateKey != null) {
            return builder.signWith(rsaPrivateKey, SignatureAlgorithm.RS256).compact();
        }
        if (hmacKey != null) {
            return builder.signWith(hmacKey, SignatureAlgorithm.HS256).compact();
        }
        throw new IllegalStateException("No signing key configured for JWT. Provide rsa private key or jwt.secret.");
    }

    public long getRefreshValidityMillis() {
        return this.refreshValidityMillis;
    }

    public String extractUsername(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(resolveVerificationKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            return claims.getSubject();
        } catch (JwtException e) {
            return null;
        }
    }

    public boolean validateToken(String token) {
        return validateToken(token, null);
    }

    public boolean validateToken(String token, String expectedTokenType) {
        try {
            Claims claims = Jwts.parserBuilder().setSigningKey(resolveVerificationKey()).build().parseClaimsJws(token)
                    .getBody();
            if (expectedTokenType != null) {
                Object t = claims.get("token_type");
                if (t == null)
                    return false;
                if (!expectedTokenType.equals(t.toString()))
                    return false;
            }
            return true;
        } catch (JwtException e) {
            return false;
        }
    }

    private Key resolveVerificationKey() {
        if (rsaPublicKey != null)
            return rsaPublicKey;
        if (hmacKey != null)
            return hmacKey;
        throw new IllegalStateException(
                "No verification key configured for JWT. Provide rsa public key or jwt.secret.");
    }

    private String readKeyContent(String pathOrPem) throws IOException {
        String trimmed = pathOrPem.trim();
        if (trimmed.startsWith("-----BEGIN")) {
            return trimmed;
        }
        // treat as file path
        return Files.readString(Path.of(trimmed));
    }

    private PrivateKey loadPrivateKeyFromPem(String pem) throws Exception {
        String base64 = stripPemHeaders(pem);
        byte[] keyBytes = Base64.getDecoder().decode(base64);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    private PublicKey loadPublicKeyFromPem(String pem) throws Exception {
        String base64 = stripPemHeaders(pem);
        byte[] keyBytes = Base64.getDecoder().decode(base64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    private String stripPemHeaders(String pem) {
        return pem.replaceAll("-----BEGIN [A-Z ]+-----", "")
                .replaceAll("-----END [A-Z ]+-----", "")
                .replaceAll("\r|\n", "").trim();
    }
}
