package com.example.AuthService.Presentation.Services.Token;
import com.example.AuthService.Persistence.Models.UserEntity;
import com.example.AuthService.Presentation.Responses.auth.TokenResponse;
public interface ITokenService {
    TokenResponse addToken(UserEntity userEntity, String token, String userAgent);
    void validateToken(String token);
    TokenResponse refreshToken(UserEntity userEntity, String refreshToken);
    void deleteToken(UserEntity userEntity);
}
