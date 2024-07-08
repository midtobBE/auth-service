package com.example.AuthService.Presentation.Responses.auth;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class AuthResponse {
    private Long userId;
    private List<String> roles;
}
