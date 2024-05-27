package com.example.AuthService.services;


import com.example.AuthService.dataTransferObjects.ChangePasswordRequest;
import com.example.AuthService.dataTransferObjects.LoginDTO;
import com.example.AuthService.dataTransferObjects.RegisterDTO;
import com.example.AuthService.models.User;
import com.example.AuthService.responses.auth.AuthResponse;
import com.example.AuthService.responses.auth.LoginResponse;

public interface IAuthService {
    LoginResponse register(RegisterDTO registerDTO, String userAgent);
    LoginResponse login(LoginDTO loginDTO, String userAgent);
    void logout();
    LoginResponse changePassword(ChangePasswordRequest passwordRequest);
    void deleteUser(Long userId);
    User authenticationToken(String token);
    LoginResponse refreshToken(String refreshToken);


    User getCurrentUser();
}
