package com.example.AuthService.Presentation.Services.Auth;

import com.example.AuthService.Persistence.Models.RoleEntity;

public interface IRoleService {
    RoleEntity findRole(String roleName);
}
