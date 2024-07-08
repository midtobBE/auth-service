package com.example.AuthService.Presentation.Services.Auth;

import com.example.AuthService.Persistence.Models.RoleEntity;
import com.example.AuthService.Persistence.Repositories.RoleRepository;
import com.example.AuthService.exceptions.DataNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RoleService implements IRoleService{
    private final RoleRepository roleRepository;
    @Override
    public RoleEntity findRole(String roleName) {
        RoleEntity existingRoleEntity = roleRepository.findByRoleName(roleName)
                .orElseThrow(()-> new DataNotFoundException("Cannot found role"));
        return existingRoleEntity;
    }
}
