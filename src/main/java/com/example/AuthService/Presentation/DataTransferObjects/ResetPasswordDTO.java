package com.example.AuthService.Presentation.DataTransferObjects;

import lombok.Data;

@Data
public class ResetPasswordDTO {
    private Long userId;
    private String token;
    private String newPassword;
    private String confirmPassword;
}
