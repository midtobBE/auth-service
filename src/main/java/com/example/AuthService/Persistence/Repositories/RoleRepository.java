package com.example.AuthService.Persistence.Repositories;

import com.example.AuthService.Persistence.Models.RoleEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;
public interface RoleRepository extends JpaRepository<RoleEntity,Long> {
    @Query("SELECT r FROM Role r WHERE name = :roleName")
    Optional<RoleEntity> findByRoleName(String roleName);
}
