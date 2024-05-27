package com.example.AuthService.repositories;
import com.example.AuthService.models.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;
import java.util.Optional;
public interface TokenRepository extends JpaRepository<Token,Long> {
    @Query("SELECT t FROM Token t WHERE t.user.userId = :userId")
    Optional<List<Token>> findByUserId(@RequestParam Long userId);
    Optional<Token> findByRefreshToken(String refreshToken);
    Optional<Token> findByToken(String token);
}
