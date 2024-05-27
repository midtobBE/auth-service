package com.example.AuthService.services;


import com.example.AuthService.dataTransferObjects.ChangePasswordRequest;
import com.example.AuthService.dataTransferObjects.LoginDTO;
import com.example.AuthService.dataTransferObjects.RegisterDTO;
import com.example.AuthService.models.User;
import com.example.AuthService.responses.auth.AuthResponse;

public interface IAuthService {
    AuthResponse register(RegisterDTO registerDTO, String userAgent);
    AuthResponse login(LoginDTO loginDTO, String userAgent);
    void logout();
    AuthResponse changePassword(ChangePasswordRequest passwordRequest);
    void deleteUser(Long userId);
    User authenticationToken(String token);
    AuthResponse refreshToken(String refreshToken);


    User getCurrentUser();
    User getUserByUserId(Long userId);
    User getUserByUserName(String userName);
}
