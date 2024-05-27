package com.example.AuthService.validations;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.time.LocalDateTime;

public class FutureDateTimeValidator implements ConstraintValidator<FutureDateTime, LocalDateTime> {

    @Override
    public void initialize(FutureDateTime constraintAnnotation) {
    }
    @Override
    public boolean isValid(LocalDateTime value, ConstraintValidatorContext context) {
        return value == null || value.isAfter(LocalDateTime.now());
    }
}
