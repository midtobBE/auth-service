package com.example.AuthService.Persistence.Repositories;
import com.example.AuthService.Persistence.Models.TokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;
import java.util.Optional;
public interface TokenRepository extends JpaRepository<TokenEntity,Long> {
    @Query("SELECT t FROM Token t WHERE t.user.userId = :userId")
    Optional<List<TokenEntity>> findByUserId(@RequestParam Long userId);
    Optional<TokenEntity> findByRefreshToken(String refreshToken);
    Optional<TokenEntity> findByToken(String token);
}
