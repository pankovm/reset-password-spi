package ru.pankovm.validator;

import java.util.Optional;

public class Validator {
    public static Optional<String> validatePassword(String password, int minLength) {
        for (ValidationRule rule : ValidationRule.values()) {
            Optional<String> error = rule.validate(password, minLength);
            if (error.isPresent()) {
                return error;
            }
        }
        return Optional.empty();
    }
}
