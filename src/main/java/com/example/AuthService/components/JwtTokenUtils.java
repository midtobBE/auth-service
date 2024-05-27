package com.example.AuthService.components;

import com.example.AuthService.exceptions.TokenExpiredException;
import com.example.AuthService.models.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.security.SecureRandom;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtTokenUtils {
    @Value("${jwt.expiration}")
    private int expiration;
    @Value("${jwt.secretKey}")
    private String secretKey;
    public String generateToken(User user){
        Map<String,Object> claims = new HashMap<>();
        claims.put("userName",user.getUsername());
        try {
            String token = Jwts.builder()
                    .setClaims(claims)
                    .setSubject(user.getUsername())
                    .setExpiration(new Date(System.currentTimeMillis()+expiration*1000000L))
                    .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                    .compact();
            return token;
        } catch (Exception e){
            throw new RuntimeException("Cannot create jwt token "+ e.getMessage());
        }
    }
    private String generateSecretKey(){
        SecureRandom random = new SecureRandom();
        byte[] keyBytes = new byte[32];
        random.nextBytes(keyBytes);
        String secretKey = Encoders.BASE64.encode(keyBytes);
        return secretKey;
    }
    private Key getSignInKey() {
        byte[] bytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(bytes);
    }
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    public  <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = this.extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    public String validateToken(String token) {
        try {
            String userName = extractClaim(token,Claims::getSubject);
            Date expirationDate = this.extractClaim(token,Claims::getExpiration);
            if (expirationDate.before(new Date())) {
                throw new TokenExpiredException("Token has expired");
            }
            return userName;
        } catch (JwtException e) {
            throw new JwtException("Invalid token: " + e.getMessage());
        }
    }
    public String extractUserName(String token) {
        return extractClaim(token,Claims::getSubject);
    }
    public boolean isExpired(String token) {
        try {
            Claims claims = extractAllClaims(token);
            Date expirationDate = claims.getExpiration();
            return expirationDate.before(new Date());
        } catch (ExpiredJwtException ex) {
            return true;
        } catch (Exception ex) {
            return true;
        }
    }
}
