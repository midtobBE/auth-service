package com.example.AuthService.responses;
import lombok.Builder;
import lombok.Data;
import org.springframework.http.HttpStatus;
@Data
@Builder
public class ResponseObject {
    private HttpStatus status;
    private Object message;
    private Object data;
    public static ResponseObject success(HttpStatus status, Object message, Object data) {
        return ResponseObject.builder()
                .status(status)
                .message(message)
                .data(data)
                .build();
    }
    public static ResponseObject error(HttpStatus status, Object message) {
        return ResponseObject.builder()
                .status(status)
                .message(message)
                .build();
    }
}