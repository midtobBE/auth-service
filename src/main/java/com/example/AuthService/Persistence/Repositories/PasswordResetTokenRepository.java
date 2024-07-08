package com.example.AuthService.Persistence.Repositories;

import com.example.AuthService.Persistence.Models.PasswordResetTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetTokenEntity,Long> {
    @Query("SELECT prt FROM PasswordResetTokenEntity prt WHERE prt.userId = :userId AND prt.isActive = true")
    PasswordResetTokenEntity findByUserId(@Param("userId") Long userId);
}
