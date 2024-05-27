package com.example.AuthService.services;
import com.example.AuthService.models.User;
import com.example.AuthService.responses.auth.TokenResponse;
public interface ITokenService {
    TokenResponse addToken(User user, String token, String userAgent);
    void validateToken(String token);
    TokenResponse refreshToken(User user, String refreshToken);
    void deleteToken(User user);
}
