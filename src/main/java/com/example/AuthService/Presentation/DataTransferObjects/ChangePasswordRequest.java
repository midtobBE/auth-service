package com.example.AuthService.Presentation.DataTransferObjects;

import lombok.Data;
import lombok.Getter;

@Data
@Getter
public class ChangePasswordRequest {
    private String currentPassword;
    private String newPassword;
}