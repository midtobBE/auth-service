package com.example.AuthService.repositories;

import com.example.AuthService.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;
public interface RoleRepository extends JpaRepository<Role,Long> {
    @Query("SELECT r FROM Role r WHERE name = :roleName")
    Optional<Role> findByRoleName(String roleName);
}
