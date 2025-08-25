package com.example.drive.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);

    private final Key key;
    private final long accessTokenExpirationMs;
    private final long refreshTokenExpirationMs;

    public JwtService(
            @Value("${app.security.jwtSecret}") String secret,
            @Value("${app.security.jwtExpirationMs}") long accessTokenExpirationMs,
            @Value("${app.security.jwtRefreshExpirationMs}") long refreshTokenExpirationMs
    ) {
        // Ensure the secret is long enough for HS256 (minimum 256 bits / 32 bytes)
        if (secret.length() < 32) {
            throw new IllegalArgumentException("JWT secret must be at least 32 characters long for HS256");
        }

        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenExpirationMs = accessTokenExpirationMs;
        this.refreshTokenExpirationMs = refreshTokenExpirationMs;
    }

    // Generate Access Token with additional claims
    public String generateAccessToken(String subject) {
        return generateToken(new HashMap<>(), subject, accessTokenExpirationMs);
    }

    // Generate Access Token with custom claims
    public String generateAccessToken(Map<String, Object> extraClaims, String subject) {
        return generateToken(extraClaims, subject, accessTokenExpirationMs);
    }

    // Generate Refresh Token
    public String generateRefreshToken(String subject) {
        return generateToken(new HashMap<>(), subject, refreshTokenExpirationMs);
    }

    // Generic token generation method
    private String generateToken(Map<String, Object> extraClaims, String subject, long expirationTime) {
        try {
            return Jwts.builder()
                    .setClaims(extraClaims)
                    .setSubject(subject)
                    .setIssuedAt(new Date(System.currentTimeMillis()))
                    .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                    .signWith(key, SignatureAlgorithm.HS256)
                    .compact();
        } catch (Exception e) {
            logger.error("Error generating JWT token", e);
            throw new RuntimeException("Could not generate JWT token", e);
        }
    }

    // Extract username (email) from token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // Extract expiration date
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // Extract any claim from token
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Extract all claims from token
    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            logger.debug("JWT token is expired: {}", e.getMessage());
            throw e;
        } catch (JwtException e) {
            logger.error("JWT token is invalid: {}", e.getMessage());
            throw e;
        }
    }

    // Validate token against UserDetails (compatible with Spring Security)
    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            if (!StringUtils.hasText(token) || userDetails == null) {
                return false;
            }

            final String tokenUsername = extractUsername(token);
            return (tokenUsername.equals(userDetails.getUsername()) && !isTokenExpired(token));
        } catch (Exception e) {
            logger.debug("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    // Check if token is expired
    private boolean isTokenExpired(String token) {
        try {
            Date expiration = extractExpiration(token);
            return expiration.before(new Date());
        } catch (Exception e) {
            logger.debug("Could not check token expiration: {}", e.getMessage());
            return true; // Consider expired if we can't determine
        }
    }

    // Validate token format and signature (without checking expiration)
    public boolean isTokenValidFormat(String token) {
        try {
            extractAllClaims(token);
            return true;
        } catch (ExpiredJwtException e) {
            return true; // Token format is valid, just expired
        } catch (Exception e) {
            return false;
        }
    }

    // Get remaining time until expiration (in milliseconds)
    public long getTimeUntilExpiration(String token) {
        try {
            Date expiration = extractExpiration(token);
            return expiration.getTime() - System.currentTimeMillis();
        } catch (Exception e) {
            return 0; // Token is invalid or expired
        }
    }
}