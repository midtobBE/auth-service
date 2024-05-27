package com.example.AuthService.validations;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = FutureDateTimeValidator.class)
public @interface FutureDateTime {
    String message() default "Deadline must be in the future";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
