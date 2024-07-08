package com.example.AuthService.Persistence.Repositories;

import com.example.AuthService.Persistence.Models.UserEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity,Long> {
    @Query("SELECT u FROM User u WHERE u.email = :email")
    Optional<UserEntity> findByEmail(String email);
    @Query("SELECT u FROM User u WHERE u.userName = :userName")
    Optional<UserEntity> findByUserName(String userName);
    @Query("SELECT CASE WHEN COUNT(u) > 0 THEN true ELSE false END FROM User u WHERE u.email = :email")
    boolean existByUserName(String email);
    @Query("SELECT u FROM User u JOIN u.roles r WHERE r.name = :roleName")
    Page<UserEntity> findAllUserByRole(String roleName, PageRequest pageRequest);
}
