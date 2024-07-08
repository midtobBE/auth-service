package com.example.AuthService.Presentation.Services.Auth;

import com.example.AuthService.Persistence.Models.PasswordResetTokenEntity;
import com.example.AuthService.Persistence.Models.UserEntity;
import com.example.AuthService.Persistence.Repositories.PasswordResetTokenRepository;
import com.example.AuthService.Presentation.Services.Token.ITokenService;
import com.example.AuthService.Presentation.DataTransferObjects.*;
import com.example.AuthService.Presentation.Responses.auth.ForgotPasswordResponse;
import com.example.AuthService.components.JwtTokenUtils;
import com.example.AuthService.dataTransferObjects.*;
import com.example.AuthService.exceptions.AccessDeniedException;
import com.example.AuthService.exceptions.DataNotFoundException;
import com.example.AuthService.exceptions.InvalidParamException;
import com.example.AuthService.Persistence.Models.RoleEntity;
import com.example.AuthService.Persistence.Repositories.UserRepository;
import com.example.AuthService.Presentation.Responses.auth.LoginResponse;
import com.example.AuthService.Presentation.Responses.auth.TokenResponse;
import com.example.AuthService.validations.ValidationUtils;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;
@Service
@RequiredArgsConstructor
public class AuthService implements IAuthService {
    private final UserRepository userRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final IRoleService roleService;
    private final ITokenService tokenService;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenUtils jwtTokenUtils;
    private final ValidationUtils validationUtils;
    private final KafkaTemplate<String, Object> kafkaTemplate;
    @Transactional
    @Override
    public LoginResponse register(RegisterDTO registerDTO, String userAgent) {
        List<RoleEntity> roleEntities = new ArrayList<>();
        RoleEntity roleEntity = roleService.findRole(RoleEntity.USER);
        roleEntities.add(roleEntity);
        UserEntity newUserEntity = UserEntity.builder()
                .roleEntities(roleEntities)
                .userName(registerDTO.getUserName())
                .email(registerDTO.getEmail())
                .password(passwordEncoder.encode(registerDTO.getPassword()))
                .build();
        newUserEntity.setActive(true);
        userRepository.save(newUserEntity);
        String newToken = jwtTokenUtils.generateToken(newUserEntity);
        TokenResponse tokenResponse = tokenService.addToken(newUserEntity,newToken,userAgent);
        return LoginResponse.builder()
                .userId(newUserEntity.getUserId())
                .roles(newUserEntity.getRoleEntities().stream().map(RoleEntity::getName).collect(Collectors.toList()))
                .token(tokenResponse)
                .build();
    }
    @Override
    public LoginResponse login(LoginDTO loginDTO, String userAgent) {
        Optional<UserEntity> optionalUser = Optional.empty();
        String subject = "";
        if (!validationUtils.isValidEmail(loginDTO.getUserName()) && loginDTO.getUserName() != null && !loginDTO.getUserName().isEmpty()){
            subject = loginDTO.getUserName();
            optionalUser = userRepository.findByUserName(subject);
        }
        if (optionalUser.isEmpty() && validationUtils.isValidEmail(loginDTO.getUserName()) && loginDTO.getUserName() != null){
            subject = loginDTO.getUserName();
            optionalUser = userRepository.findByEmail(subject);
        }
        if (optionalUser.isEmpty()) {
            throw new DataNotFoundException("Cannot found user!");
        }
        UserEntity existingUserEntity = optionalUser.get();
        if (!passwordEncoder.matches(loginDTO.getPassword(), existingUserEntity.getPassword())){
            throw new BadCredentialsException("Wrong email or password");
        }
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                subject, loginDTO.getPassword(),
                existingUserEntity.getAuthorities()
        );
        authenticationManager.authenticate(authenticationToken);
        System.out.println(existingUserEntity.getUsername());
        String newToken = jwtTokenUtils.generateToken(existingUserEntity);
        TokenResponse tokenResponse = tokenService.addToken(existingUserEntity,newToken,userAgent);
        return LoginResponse.builder()
                .userId(existingUserEntity.getUserId())
                .roles(existingUserEntity.getRoleEntities().stream().map(RoleEntity::getName).collect(Collectors.toList()))
                .token(tokenResponse)
                .build();
    }
    @Override
    public void logout() {
        Long userId = this.getCurrentUser().getUserId();
        UserEntity existingUserEntity = userRepository.findById(userId)
                .orElseThrow(() -> new AccessDeniedException("User with userId " + userId + " not found."));
        tokenService.deleteToken(existingUserEntity);
    }
    @Override
    public LoginResponse changePassword(ChangePasswordRequest passwordRequest) {
        if (!passwordRequest.getCurrentPassword().equals(passwordRequest.getNewPassword())){
            throw new InvalidParamException("New password must be different from the current password!");
        }
        String userName = getCurrentUser().getUsername();
        UserEntity existingUserEntity = userRepository.findByUserName(userName)
                .orElseThrow(() -> new AccessDeniedException("User with username " + userName + " not found."));
        if (!passwordEncoder.matches(passwordRequest.getCurrentPassword(), existingUserEntity.getPassword())){
            throw new BadCredentialsException("Current password is incorrect.");
        }
        existingUserEntity.setPassword(passwordEncoder.encode(passwordRequest.getNewPassword()));
        userRepository.save(existingUserEntity);
        tokenService.deleteToken(existingUserEntity);
        String newToken = jwtTokenUtils.generateToken(existingUserEntity);
        TokenResponse tokenResponse = tokenService.addToken(existingUserEntity,newToken,null);
        return LoginResponse.builder()
                .userId(existingUserEntity.getUserId())
                .roles(existingUserEntity.getRoleEntities().stream().map(RoleEntity::getName).collect(Collectors.toList()))
                .token(tokenResponse)
                .build();
    }

    @Override
    @Builder
    public void forgotPassword(String email) {
        UserEntity existingUserEntity = userRepository.findByEmail(email)
                .orElseThrow(() -> new DataNotFoundException("Cannot found user with email " + email));
        Random random = new Random();
        Long confirmationCode = random.nextLong(900000) + 100000;
        LocalDateTime createdAt = LocalDateTime.now();
        LocalDateTime expiresAt = LocalDateTime.now().plusHours(24);
        PasswordResetTokenEntity newTokenEntity = PasswordResetTokenEntity.builder()
                .userId(existingUserEntity.getUserId())
                .confirmationCode(confirmationCode)
                .isActive(true)
                .expiresAt(expiresAt)
                .createdAt(createdAt)
                .build();
        passwordResetTokenRepository.save(newTokenEntity);
        kafkaTemplate.send("forgot-password",
                UserContactDTO.builder()
                        .recipient(email)
                        .subject("Forgot Password")
                        .body(ForgotPasswordResponse.builder()
                                .confirmationCode(confirmationCode)
                                .expiresAt(expiresAt)
                                .build())
                .build());
    }
    @Override
    public void confirmCode(Long userId, Long code) {
        PasswordResetTokenEntity passwordResetTokenEntity = passwordResetTokenRepository.findByUserId(userId);
        if (passwordResetTokenEntity.getConfirmationCode().equals(code)){
            String newToken = UUID.randomUUID().toString();
            passwordResetTokenEntity.setToken(newToken);
            passwordResetTokenRepository.save(passwordResetTokenEntity);
        } else {
            throw new InvalidParamException("");
        }
    }

    @Override
    public void resetPassword(ResetPasswordDTO resetPasswordDTO) {
        PasswordResetTokenEntity passwordResetTokenEntity = passwordResetTokenRepository.findByUserId(resetPasswordDTO.getUserId());
        if (passwordResetTokenEntity.getToken().equals(resetPasswordDTO.getToken())){
            if (resetPasswordDTO.getNewPassword().equals(resetPasswordDTO.getConfirmPassword())) {
                UserEntity existingUserEntity = userRepository.findById(resetPasswordDTO.getUserId())
                        .orElseThrow(null);
                existingUserEntity.setPassword(passwordEncoder.encode(resetPasswordDTO.getNewPassword()));
                userRepository.save(existingUserEntity);
            } else {
                throw new InvalidParamException("");
            }
        } else {
            throw new InvalidParamException("");
        }
    }


    @Override
    public UserEntity authenticationToken(String token) {
        tokenService.validateToken(token);
        String userName = jwtTokenUtils.extractUserName(token);
        UserEntity existingUserEntity = null;
        if (!validationUtils.isValidEmail(userName)){
            existingUserEntity = userRepository.findByUserName(userName)
                    .orElseThrow(() -> new DataNotFoundException("Cannot found user with userName " + userName));
        }
        if (existingUserEntity == null && validationUtils.isValidEmail(userName)){
            existingUserEntity = userRepository.findByEmail(userName)
                    .orElseThrow(()->new DataNotFoundException("Cannot found user with email " + userName));
        }
        if (existingUserEntity == null || !existingUserEntity.isActive()){
            throw new InvalidParamException("User is not active");
        }
        return existingUserEntity;
    }
    @Override
    public LoginResponse refreshToken(String refreshToken) {
        String userName = getCurrentUser().getUsername();
        UserEntity existingUserEntity = userRepository.findByUserName(userName)
                .orElseThrow(() -> new DataNotFoundException(""));
        if (!existingUserEntity.isActive()) {
            throw new InvalidParamException("User is not active");
        }
        TokenResponse tokenResponse = tokenService.refreshToken(existingUserEntity,refreshToken);
        return LoginResponse.builder()
                .userId(existingUserEntity.getUserId())
                .roles(existingUserEntity.getRoleEntities().stream().map(RoleEntity::getName).collect(Collectors.toList()))
                .token(tokenResponse)
                .build();
    }
    @Override
    public UserEntity getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof UserEntity) {
            return (UserEntity) authentication.getPrincipal();
        } else {
            return null;
        }
    }
}
