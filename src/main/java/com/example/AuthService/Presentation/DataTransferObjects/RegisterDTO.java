package com.example.AuthService.Presentation.DataTransferObjects;

import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;

@Data

public class RegisterDTO {
    private String userName;
    private String email;
    private String password;
    private String firstName;
    private String lastName;
    private String gender;
    private LocalDateTime dateOfBirth;
    private String address;
    private MultipartFile avatar;
    private MultipartFile banner;
}
