package com.example.AuthService.models;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Entity
@Table(name = "roles")
@Builder
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "role_id")
    private Long roleId;
    @Column(name = "role_name")
    private String name;
    @ManyToMany(mappedBy = "roles")
    private List<User> user;

    public static String ADMIN = "ADMIN";
    public static String USER = "USER";
    public static String POSTER = "POSTER";
    public static String TASKER = "TASKER";
}
