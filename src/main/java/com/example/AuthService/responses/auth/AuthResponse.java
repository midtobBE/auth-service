package com.example.AuthService.responses.auth;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class AuthResponse {
    private Long userId;
    private List<String> roles;
}
