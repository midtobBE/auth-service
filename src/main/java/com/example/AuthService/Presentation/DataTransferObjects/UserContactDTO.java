package com.example.AuthService.Presentation.DataTransferObjects;

import lombok.Builder;
import lombok.Data;


@Data
@Builder
public class UserContactDTO {
    private String recipient;
    private String subject;
    private Object body;
}
