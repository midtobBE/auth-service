package com.example.AuthService.services;

import com.example.AuthService.components.JwtTokenUtils;
import com.example.AuthService.exceptions.DataNotFoundException;
import com.example.AuthService.exceptions.TokenExpiredException;
import com.example.AuthService.models.Token;
import com.example.AuthService.models.User;
import com.example.AuthService.repositories.TokenRepository;
import com.example.AuthService.responses.auth.TokenResponse;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.UUID;
@Service
@RequiredArgsConstructor
public class TokenService implements ITokenService {
    @Value("${jwt.expiration}")
    private Long expiration;
    @Value("${jwt.expiration-refresh-token}")
    private Long expirationRefreshToken;
    private final int MAX_TOKENS = 3;
    private final TokenRepository tokenRepository;
    private final JwtTokenUtils jwtTokenUtils;

    @Transactional
    @Override
    public TokenResponse addToken(User user, String token, String userAgent){
        List<Token> userTokens = tokenRepository.findByUserId(user.getUserId())
                .orElseThrow(()->new DataNotFoundException("Cannot found token"));
        int tokenCount = userTokens.size();
        if (tokenCount >= MAX_TOKENS){
            userTokens.sort(Comparator.comparing(Token::getCreatedAt));
            Token oldestToken = userTokens.get(0);
            tokenRepository.delete(oldestToken);
        }
        for (Token userToken : userTokens) {
            if (userToken.getUserAgent().equals(userAgent) || userToken.isExpired()) {
                tokenRepository.delete(userToken);
            }
        }
        Date expirationDate = jwtTokenUtils.extractClaim(token, Claims::getExpiration);
        boolean expired = expirationDate != null && expirationDate.before(new Date());
        Token newToken = Token.builder()
                .user(user)
                .userAgent(userAgent)
                .tokenType("Bearer")
                .token(token)
                .expiration(expirationDate)
                .expired(expired)
                .revoked(false)
                .build();
        newToken.setRefreshToken(UUID.randomUUID().toString());
        newToken.setRefreshTokenDate(new Date(System.currentTimeMillis()+expirationRefreshToken*1000000L));
        tokenRepository.save(newToken);
        System.out.println(newToken.getTokenId());
        return TokenResponse.builder()
                .tokenType(newToken.getTokenType())
                .accessToken(newToken.getToken())
                .refreshToken(newToken.getRefreshToken())
                .build();
    }
    @Override
    public void validateToken(String token) {
        Token existingToken = tokenRepository.findByToken(token).orElseThrow(()-> new DataNotFoundException("Token not found"));
        if (existingToken.isExpired() || jwtTokenUtils.isExpired(token)) {
            throw new TokenExpiredException("Token has expired");
        }
    }
    @Transactional
    @Override
    public TokenResponse refreshToken(User user, String refreshToken){
        Token existingToken = tokenRepository.findByRefreshToken(refreshToken)
                .orElseThrow(()->new DataNotFoundException("Cannot found token"));
        if (existingToken.getRefreshTokenDate().after(new Date())){
            throw new TokenExpiredException("Refresh token has expired");
        }
        String newAccessToken = jwtTokenUtils.generateToken(user);
        String newRefreshToken = UUID.randomUUID().toString();
        existingToken.setToken(newAccessToken);
        existingToken.setRefreshToken(newRefreshToken);
        tokenRepository.save(existingToken);
        return TokenResponse.builder()
                .tokenType(existingToken.getTokenType())
                .accessToken(existingToken.getToken())
                .refreshToken(existingToken.getRefreshToken())
                .build();
    }
    @Transactional
    @Override
    public void deleteToken(User user) {
        List<Token> tokens = tokenRepository.findByUserId(user.getUserId())
                .orElseThrow(()->new DataNotFoundException(""));
        tokenRepository.deleteAll(tokens);
    }
}
