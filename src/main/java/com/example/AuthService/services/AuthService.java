package com.example.AuthService.services;

import com.example.AuthService.components.JwtTokenUtils;
import com.example.AuthService.dataTransferObjects.ChangePasswordRequest;
import com.example.AuthService.dataTransferObjects.LoginDTO;
import com.example.AuthService.dataTransferObjects.RegisterDTO;
import com.example.AuthService.exceptions.AccessDeniedException;
import com.example.AuthService.exceptions.DataNotFoundException;
import com.example.AuthService.exceptions.InvalidParamException;
import com.example.AuthService.models.Role;
import com.example.AuthService.models.User;
import com.example.AuthService.repositories.RoleRepository;
import com.example.AuthService.repositories.UserRepository;
import com.example.AuthService.responses.auth.AuthResponse;
import com.example.AuthService.responses.auth.TokenResponse;
import com.example.AuthService.validations.ValidationUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
@Service
@RequiredArgsConstructor
public class AuthService implements IAuthService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenUtils jwtTokenUtils;
    private final ITokenService tokenService;
    private final ValidationUtils validationUtils;


    @Transactional
    @Override
    public AuthResponse register(RegisterDTO registerDTO, String userAgent) {
        if (userRepository.existByUserName(registerDTO.getEmail())){
            throw new InvalidParamException("Email already exists!");
        }
        List<Role> roles = new ArrayList<>();
        Role role = roleRepository.findByRoleName(Role.USER)
                .orElseThrow(()-> new DataNotFoundException("Cannot found role"));
        roles.add(role);
        User newUser = User.builder()
                .roles(roles)
                .userName(registerDTO.getUserName())
                .email(registerDTO.getEmail())
                .password(passwordEncoder.encode(registerDTO.getPassword()))
                .build();
        newUser.setActive(true);
        userRepository.save(newUser);
        String newToken = jwtTokenUtils.generateToken(newUser);
        TokenResponse tokenResponse = tokenService.addToken(newUser,newToken,userAgent);
        return AuthResponse.builder()
                .userId(newUser.getUserId())
                .roles(newUser.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                .token(tokenResponse)
                .build();
    }
    @Override
    public AuthResponse login(LoginDTO loginDTO, String userAgent) {
        Optional<User> optionalUser = Optional.empty();
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
        User existingUser = optionalUser.get();
        if (!passwordEncoder.matches(loginDTO.getPassword(),existingUser.getPassword())){
            throw new BadCredentialsException("Wrong email or password");
        }
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                subject, loginDTO.getPassword(),
                existingUser.getAuthorities()
        );
        authenticationManager.authenticate(authenticationToken);
        System.out.println(existingUser.getUsername());
        String newToken = jwtTokenUtils.generateToken(existingUser);
        TokenResponse tokenResponse = tokenService.addToken(existingUser,newToken,userAgent);
        return AuthResponse.builder()
                .userId(existingUser.getUserId())
                .roles(existingUser.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                .token(tokenResponse)
                .build();
    }
    @Override
    public void logout() {
        Long userId = this.getCurrentUser().getUserId();
        User existingUser = userRepository.findById(userId)
                .orElseThrow(() -> new AccessDeniedException("User with userId " + userId + " not found."));
        tokenService.deleteToken(existingUser);
    }
    @Override
    public AuthResponse changePassword(ChangePasswordRequest passwordRequest) {
        if (!passwordRequest.getCurrentPassword().equals(passwordRequest.getNewPassword())){
            throw new InvalidParamException("New password must be different from the current password!");
        }
        String userName = getCurrentUser().getUsername();
        User existingUser = userRepository.findByUserName(userName)
                .orElseThrow(() -> new AccessDeniedException("User with username " + userName + " not found."));
        if (!passwordEncoder.matches(passwordRequest.getCurrentPassword(), existingUser.getPassword())){
            throw new BadCredentialsException("Current password is incorrect.");
        }
        existingUser.setPassword(passwordEncoder.encode(passwordRequest.getNewPassword()));
        userRepository.save(existingUser);
        tokenService.deleteToken(existingUser);
        String newToken = jwtTokenUtils.generateToken(existingUser);
        TokenResponse tokenResponse = tokenService.addToken(existingUser,newToken,null);
        return AuthResponse.builder()
                .userId(existingUser.getUserId())
                .roles(existingUser.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                .token(tokenResponse)
                .build();
    }
    @Override
    public void deleteUser(Long userId){
        User existingUser = userRepository.findById(userId)
                .orElseThrow(()-> new DataNotFoundException("Cannot found user with id " + userId));
        userRepository.delete(existingUser);
    }
    @Override
    public User authenticationToken(String token) {

        tokenService.validateToken(token);
        String userName = jwtTokenUtils.extractUserName(token);
        User existingUser = null;
        if (!validationUtils.isValidEmail(userName)){
            existingUser = userRepository.findByUserName(userName)
                    .orElseThrow(() -> new DataNotFoundException("Cannot found user with userName " + userName));
        }
        if (existingUser == null && validationUtils.isValidEmail(userName)){
            existingUser = userRepository.findByEmail(userName)
                    .orElseThrow(()->new DataNotFoundException("Cannot found user with email " + userName));
        }
        if (!existingUser.isActive()){
            throw new InvalidParamException("User is not active");
        }
        System.out.println("hello!!");
        return existingUser;
    }
    @Override
    public AuthResponse refreshToken(String refreshToken) {
        String userName = getCurrentUser().getUsername();
        User existingUser = userRepository.findByUserName(userName)
                .orElseThrow(() -> new DataNotFoundException(""));

        if (!existingUser.isActive()) {
            throw new InvalidParamException("User is not active");
        }
        TokenResponse tokenResponse = tokenService.refreshToken(existingUser,refreshToken);
        return AuthResponse.builder()
                .userId(existingUser.getUserId())
                .roles(existingUser.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                .token(tokenResponse)
                .build();
    }
    @Override
    public User getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof User) {
            return (User) authentication.getPrincipal();
        } else {
            return null;
        }
    }
    @Override
    public User getUserByUserId(Long userId){
        return userRepository.findById(userId)
                .orElseThrow(()->new DataNotFoundException(""));
    }
    @Override
    public User getUserByUserName(String userName) {
        if (validationUtils.isValidEmail(userName)){
            return userRepository.findByEmail(userName)
                    .orElseThrow(()->new DataNotFoundException(""));
        }
        return userRepository.findByUserName(userName)
                .orElseThrow(()->new DataNotFoundException(""));
    }
}
