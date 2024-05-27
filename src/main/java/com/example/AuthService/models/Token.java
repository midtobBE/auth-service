package com.example.AuthService.models;

import jakarta.persistence.*;
import lombok.*;

import java.util.Date;

@Entity
@Table(name = "tokens")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class Token extends BaseEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "token_id")
    private Long tokenId;
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
    @Column(name = "user_agent", nullable = false)
    private String userAgent;
    @Column(name = "token_type", nullable = false, length = 50)
    private String tokenType;
    @Column(name = "token", unique = true, nullable = false, length = 255)
    private String token;
    @Column(name = "expiration_date")
    @Temporal(TemporalType.TIMESTAMP)
    private Date expiration;
    @Column(name = "refresh_token")
    private String refreshToken;
    @Column(name = "refresh_token_date")
    private Date refreshTokenDate;
    @Column(name = "revoked", nullable = false)
    private boolean revoked;
    @Column(name = "expired", nullable = false)
    private boolean expired;
}
