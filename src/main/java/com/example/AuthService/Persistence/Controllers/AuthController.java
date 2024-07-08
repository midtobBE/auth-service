package com.example.AuthService.Persistence.Controllers;

import com.example.AuthService.Presentation.DataTransferObjects.ChangePasswordRequest;
import com.example.AuthService.Presentation.DataTransferObjects.LoginDTO;
import com.example.AuthService.Presentation.DataTransferObjects.RegisterDTO;
import com.example.AuthService.Persistence.Models.RoleEntity;
import com.example.AuthService.Persistence.Models.UserEntity;
import com.example.AuthService.Presentation.Responses.ResponseObject;
import com.example.AuthService.Presentation.Responses.auth.AuthResponse;
import com.example.AuthService.Presentation.Responses.auth.LoginResponse;
import com.example.AuthService.Presentation.Services.Auth.IAuthService;
import com.example.AuthService.Presentation.DataTransferObjects.ResetPasswordDTO;
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
        UserEntity userEntityResponse = authService.getCurrentUser();
        return ResponseEntity.ok(ResponseObject.success(HttpStatus.OK,
                "",
                AuthResponse.builder()
                        .userId(userEntityResponse.getUserId())
                        .roles(userEntityResponse.getRoleEntities().stream().map(RoleEntity::getName).collect(Collectors.toList()))
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
    public ResponseEntity<?> handleChangePassword(
            @RequestBody ChangePasswordRequest passwordRequest
    ) {
        LoginResponse loginResponse = authService.changePassword(passwordRequest);
        return ResponseEntity.ok(ResponseObject.success(HttpStatus.OK, "Change password successful!", loginResponse));
    }
    @PostMapping("/forgot-password")
    public ResponseEntity<?> hanldeForgotPassword(
            @RequestParam String email
    ){
        authService.forgotPassword(email);
        return ResponseEntity.ok(ResponseObject.success(HttpStatus.OK, "" +
                "Send token successful", null));
    }
    @PostMapping("/confirm-code")
    public ResponseEntity<?> hanldeConfirmCode(
            @RequestParam Long userId,
            @RequestParam Long code
    ){
        authService.confirmCode(userId,code);
        return ResponseEntity.ok(ResponseObject.success(HttpStatus.OK, "" +
                "Send token successful", null));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> handleResetPassword(
            @RequestBody ResetPasswordDTO resetPasswordDTO
            ){
        return ResponseEntity.ok(ResponseObject.success(HttpStatus.OK, "" +
                "", null));
    }
}
