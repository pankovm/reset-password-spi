package ru.pankovm.validator;

import java.util.Optional;
import java.util.function.BiPredicate;
import java.util.function.Function;
import java.util.regex.Pattern;

public enum ValidationRule {
    NULL_PASSWORD(
            (password, minLength) -> password != null,
            minLength -> "Пароль не можеть быть null."
    ),
    MIN_LENGTH(
            (password, minLength) -> Pattern.compile("^.{" + minLength + ",}$").asPredicate().test(password),
            minLength -> "Пароль должен быть не менее " + minLength + " символов."
    ),
    HAS_DIGIT(
            (password, minLength) -> Pattern.compile("\\d+").asPredicate().test(password),
            minLength -> "Пароль должен содержать хотя бы одну цифру."
    ),
    HAS_LETTER(
            (password, minLength) -> Pattern.compile("[A-Za-z]+").asPredicate().test(password),
            minLength -> "Пароль должен содержать хотя бы одну букву."
    );

    private final BiPredicate<String, Integer> validator;
    private final Function<Integer, String> errorMessage;

    ValidationRule(BiPredicate<String, Integer> validator, Function<Integer, String> errorMessage) {
        this.validator = validator;
        this.errorMessage = errorMessage;
    }

    public Optional<String> validate(String password, int minLength) {
        return validator.test(password, minLength) ? Optional.empty() : Optional.of(getErrorMessage(minLength));
    }

    public String getErrorMessage(int minLength) {
        return errorMessage.apply(minLength);
    }
}
