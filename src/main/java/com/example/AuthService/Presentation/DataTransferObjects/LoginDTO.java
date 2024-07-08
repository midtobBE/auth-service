package com.example.AuthService.Presentation.DataTransferObjects;

import lombok.Data;
import lombok.Getter;

@Data
@Getter
public class LoginDTO {
    private String userName;
    private String password;
}
