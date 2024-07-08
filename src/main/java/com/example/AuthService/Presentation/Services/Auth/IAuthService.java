package com.example.AuthService.Presentation.Services.Auth;


import com.example.AuthService.Persistence.Models.UserEntity;
import com.example.AuthService.Presentation.DataTransferObjects.ChangePasswordRequest;
import com.example.AuthService.Presentation.DataTransferObjects.LoginDTO;
import com.example.AuthService.Presentation.DataTransferObjects.RegisterDTO;
import com.example.AuthService.Presentation.Responses.auth.LoginResponse;
import com.example.AuthService.Presentation.DataTransferObjects.ResetPasswordDTO;

public interface IAuthService {
    LoginResponse register(RegisterDTO registerDTO, String userAgent);
    LoginResponse login(LoginDTO loginDTO, String userAgent);
    void logout();

    LoginResponse changePassword(ChangePasswordRequest passwordRequest);

    void forgotPassword(String email);
    void confirmCode(Long userId,Long code);
    void resetPassword(ResetPasswordDTO resetPasswordDTO);


    UserEntity authenticationToken(String token);
    LoginResponse refreshToken(String refreshToken);

    UserEntity getCurrentUser();
}
