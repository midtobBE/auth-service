package com.example.AuthService.controllers;

import com.example.AuthService.dataTransferObjects.ChangePasswordRequest;
import com.example.AuthService.dataTransferObjects.LoginDTO;
import com.example.AuthService.dataTransferObjects.RegisterDTO;
import com.example.AuthService.models.Role;
import com.example.AuthService.models.User;
import com.example.AuthService.responses.ResponseObject;
import com.example.AuthService.responses.auth.AuthResponse;
import com.example.AuthService.responses.auth.LoginResponse;
import com.example.AuthService.services.IAuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/${api.prefix}/auth")
@RequiredArgsConstructor
public class AuthController {
    private final IAuthService authService;
    @PostMapping("/register")
    public ResponseEntity<?> hanldeRegister(
            @ModelAttribute RegisterDTO registerDTO,
            HttpServletRequest request,
            BindingResult result
    ) {
        if (result.hasErrors()) {
            List<String> errorMessages = result.getFieldErrors()
                    .stream()
                    .map(FieldError::getDefaultMessage)
                    .collect(Collectors.toList());
            return ResponseEntity.badRequest().body(ResponseObject.error(HttpStatus.BAD_REQUEST, errorMessages));
        }
        String userAgent = request.getHeader("User-Agent");
        LoginResponse loginResponse = authService.register(registerDTO,userAgent);
        return ResponseEntity.ok(ResponseObject.success(HttpStatus.OK, "Register successfully", loginResponse));
    }

    @PostMapping("/login")
    public ResponseEntity<?> handleLogin(
            @Valid @RequestBody LoginDTO loginDTO,
            HttpServletRequest request,
            BindingResult result
    ) {
        if (result.hasErrors()) {
            List<String> errorMessages = result.getFieldErrors()
                    .stream()
                    .map(FieldError::getDefaultMessage)
                    .collect(Collectors.toList());
            return ResponseEntity.badRequest().body(ResponseObject.error(HttpStatus.BAD_REQUEST, errorMessages));
        }
        String userAgent = request.getHeader("User-Agent");
        LoginResponse loginResponse = authService.login(loginDTO, userAgent);
        return ResponseEntity.ok(ResponseObject.success(HttpStatus.OK, "Login successfully", loginResponse));
    }
    @PostMapping("/validateToken")
    @PreAuthorize("hasRole('ROLE_USER')")
    public ResponseEntity<?> hanldeValidateToken(){
        System.out.println("Hi");
        User userResponse = authService.getCurrentUser();
        return ResponseEntity.ok(ResponseObject.success(HttpStatus.OK,
                "",
                AuthResponse.builder()
                        .userId(userResponse.getUserId())
                        .roles(userResponse.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                        .build()));
    }
    @PostMapping("/logout")
    @PreAuthorize("hasRole('ROLE_USER')")
    public ResponseEntity<?> logout() {
        authService.logout();
        return ResponseEntity.ok(ResponseObject.success(HttpStatus.OK, "Logout successfully", null));
    }
    @PostMapping("/refresh-token")
    @PreAuthorize("hasRole('ROLE_USER')")
    public ResponseEntity<?> refreshToken(@RequestHeader("Authorization") String refreshTokenHeader) {
        LoginResponse loginResponse = authService.refreshToken(refreshTokenHeader);
        return ResponseEntity.ok(ResponseObject.success(HttpStatus.OK, "Refresh Token successfully", loginResponse));
    }
    @PostMapping("/change-password")
    @PreAuthorize("hasRole('ROLE_USER')")
    public ResponseEntity<?> changePassword(
            @RequestBody ChangePasswordRequest passwordRequest
    ) {
        LoginResponse loginResponse = authService.changePassword(passwordRequest);
        return ResponseEntity.ok(ResponseObject.success(HttpStatus.OK, "Change password successful!", loginResponse));
    }

    @DeleteMapping("/delete-user")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<?> deleteUser(
            @RequestParam Long userId
    ) {
        authService.deleteUser(userId);
        return ResponseEntity.ok(ResponseObject.success(HttpStatus.OK, String.format("Delete user with id %d successful!", userId), null));
    }
}
