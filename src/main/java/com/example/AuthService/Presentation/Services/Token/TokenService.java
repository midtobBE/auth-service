package com.example.AuthService.Presentation.Services.Token;

import com.example.AuthService.Persistence.Models.TokenEntity;
import com.example.AuthService.components.JwtTokenUtils;
import com.example.AuthService.exceptions.DataNotFoundException;
import com.example.AuthService.exceptions.TokenExpiredException;
import com.example.AuthService.Persistence.Models.UserEntity;
import com.example.AuthService.Persistence.Repositories.TokenRepository;
import com.example.AuthService.Presentation.Responses.auth.TokenResponse;
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
    public TokenResponse addToken(UserEntity userEntity, String token, String userAgent){
        List<TokenEntity> userTokenEntities = tokenRepository.findByUserId(userEntity.getUserId())
                .orElseThrow(()->new DataNotFoundException("Cannot found token"));
        int tokenCount = userTokenEntities.size();
        if (tokenCount >= MAX_TOKENS){
            userTokenEntities.sort(Comparator.comparing(TokenEntity::getCreatedAt));
            TokenEntity oldestTokenEntity = userTokenEntities.get(0);
            tokenRepository.delete(oldestTokenEntity);
        }
        for (TokenEntity userTokenEntity : userTokenEntities) {
            if (userTokenEntity.getUserAgent().equals(userAgent) || userTokenEntity.isExpired()) {
                tokenRepository.delete(userTokenEntity);
            }
        }
        Date expirationDate = jwtTokenUtils.extractClaim(token, Claims::getExpiration);
        boolean expired = expirationDate != null && expirationDate.before(new Date());
        TokenEntity newTokenEntity = TokenEntity.builder()
                .userEntity(userEntity)
                .userAgent(userAgent)
                .tokenType("Bearer")
                .token(token)
                .expiration(expirationDate)
                .expired(expired)
                .revoked(false)
                .build();
        newTokenEntity.setRefreshToken(UUID.randomUUID().toString());
        newTokenEntity.setRefreshTokenDate(new Date(System.currentTimeMillis()+expirationRefreshToken*1000000L));
        tokenRepository.save(newTokenEntity);
        return TokenResponse.builder()
                .tokenType(newTokenEntity.getTokenType())
                .accessToken(newTokenEntity.getToken())
                .refreshToken(newTokenEntity.getRefreshToken())
                .build();
    }
    @Override
    public void validateToken(String token) {
        TokenEntity existingTokenEntity = tokenRepository.findByToken(token).orElseThrow(()-> new DataNotFoundException("Token not found"));
        if (existingTokenEntity.isExpired() || jwtTokenUtils.isExpired(token)) {
            throw new TokenExpiredException("Token has expired");
        }
    }
    @Transactional
    @Override
    public TokenResponse refreshToken(UserEntity userEntity, String refreshToken){
        TokenEntity existingTokenEntity = tokenRepository.findByRefreshToken(refreshToken)
                .orElseThrow(()->new DataNotFoundException("Cannot found token"));
        if (existingTokenEntity.getRefreshTokenDate().after(new Date())){
            throw new TokenExpiredException("Refresh token has expired");
        }
        String newAccessToken = jwtTokenUtils.generateToken(userEntity);
        String newRefreshToken = UUID.randomUUID().toString();
        existingTokenEntity.setToken(newAccessToken);
        existingTokenEntity.setRefreshToken(newRefreshToken);
        tokenRepository.save(existingTokenEntity);
        return TokenResponse.builder()
                .tokenType(existingTokenEntity.getTokenType())
                .accessToken(existingTokenEntity.getToken())
                .refreshToken(existingTokenEntity.getRefreshToken())
                .build();
    }
    @Transactional
    @Override
    public void deleteToken(UserEntity userEntity) {
        List<TokenEntity> tokenEntities = tokenRepository.findByUserId(userEntity.getUserId())
                .orElseThrow(()->new DataNotFoundException(""));
        tokenRepository.deleteAll(tokenEntities);
    }
}
