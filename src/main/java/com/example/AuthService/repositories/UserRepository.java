package com.example.AuthService.repositories;

import com.example.AuthService.models.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Long> {
    @Query("SELECT u FROM User u WHERE u.email = :email")
    Optional<User> findByEmail(String email);
    @Query("SELECT u FROM User u WHERE u.userName = :userName")
    Optional<User> findByUserName(String userName);
    @Query("SELECT CASE WHEN COUNT(u) > 0 THEN true ELSE false END FROM User u WHERE u.email = :email")
    boolean existByUserName(String email);
    @Query("SELECT u FROM User u JOIN u.roles r WHERE r.name = :roleName")
    Page<User> findAllUserByRole(String roleName, PageRequest pageRequest);
}
