package com.example.AuthService.filters;

import com.example.AuthService.Persistence.Models.UserEntity;
import com.example.AuthService.exceptions.AccessDeniedException;
import com.example.AuthService.Presentation.Services.Auth.IAuthService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.util.Pair;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtTokenFilter extends OncePerRequestFilter {
    @Value("${api.prefix}")
    private String apiPrefix;
    private final IAuthService authService;
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        try {
                String token = authHeader.substring(7);
                UserEntity userEntityDetails = authService.authenticationToken(token);
                Authentication authentication =
                        new UsernamePasswordAuthenticationToken(userEntityDetails,
                                null,
                                userEntityDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authentication);
                filterChain.doFilter(request, response);
        } catch (Exception e){
            if (isBypassToken(request)) {
                filterChain.doFilter(request, response);
                return;
            }
                throw new AccessDeniedException("You don't have access");
            }
    }
    private boolean isBypassToken(@NonNull ServletRequest servletRequest) {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        String requestPath = request.getServletPath();
        String requestMethod = request.getMethod();
        final List<Pair<String, String>> bypassRoutes  = Arrays.asList(
                Pair.of(String.format("/%s/auth/login",apiPrefix),"POST"),
                Pair.of(String.format("/%s/auth/register",apiPrefix),"POST")
        );
        for(Pair<String,String> bypassToken:bypassRoutes){
            if (requestPath.contains(bypassToken.getFirst())
                    && requestMethod.equals(bypassToken.getSecond())){
                return true;
            }
        }
        return false;
    }
}
