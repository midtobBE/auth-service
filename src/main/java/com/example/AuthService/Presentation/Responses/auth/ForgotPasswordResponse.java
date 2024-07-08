package com.example.AuthService.Presentation.Responses.auth;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class ForgotPasswordResponse {
    private LocalDateTime expiresAt;
    private Long confirmationCode;
}
