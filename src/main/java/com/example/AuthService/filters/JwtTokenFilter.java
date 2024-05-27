package com.example.AuthService.filters;

import com.example.AuthService.exceptions.AccessDeniedException;
import com.example.AuthService.models.User;
import com.example.AuthService.services.IAuthService;
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
        if (request.getServletPath().contains("/ws")) {
            filterChain.doFilter(request,response);
            return;
        }
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        try {
//            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);
                User userDetails = authService.authenticationToken(token);
                Authentication authentication =
                        new UsernamePasswordAuthenticationToken(userDetails,
                                null,
                                userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authentication);
                filterChain.doFilter(request, response);
                return;
//            }
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
                Pair.of(String.format("/%s/answer",apiPrefix),"GET"),
                Pair.of(String.format("/%s/question",apiPrefix),"GET"),
                Pair.of(String.format("/%s/category",apiPrefix),"GET"),


                Pair.of(String.format("/%s/post",apiPrefix),"GET"),
                Pair.of(String.format("/%s/comment",apiPrefix),"GET"),
                Pair.of(String.format("/%s/replyComment",apiPrefix),"GET"),
                Pair.of(String.format("/%s/like",apiPrefix),"GET"),


                Pair.of(String.format("/%s/user/profile/",apiPrefix),"GET"),

                Pair.of(String.format("/%s/auth/login",apiPrefix),"POST"),
                Pair.of(String.format("/%s/auth/register",apiPrefix),"POST"),

                Pair.of("/swagger-ui/","GET"),
                Pair.of("/api-docs","GET"),
                Pair.of("/api-docs/","GET")
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
