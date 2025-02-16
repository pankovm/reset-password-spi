package ru.pankovm.authentocator;

import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import ru.pankovm.CustomPasswordResetAuthenticatorFactory;
import ru.pankovm.validator.Validator;

import java.util.Optional;

public class CustomPasswordResetAuthenticator implements Authenticator {
    public static final String PASSWORD = "password";
    public static final String NEW_PASSWORD = "password-new";
    public static final String PASSWORD_FORM = "custom-login-update-password.ftl";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String password = context.getHttpRequest().getDecodedFormParameters().getFirst(PASSWORD);
        String passMinLength = context.getAuthenticatorConfig().getConfig().get(CustomPasswordResetAuthenticatorFactory.PASSWORD_MIN_LENGTH);

        if (password == null || password.isEmpty()) {
            Response response = context.form().createForm(PASSWORD_FORM);
            context.challenge(response);
            return;
        }

        Optional<String> error = Validator.validatePassword(password, Integer.parseInt(passMinLength));
        if (error.isPresent()) {
            context.challenge(context.form().setError(error.get()).createForm(PASSWORD_FORM));
            return;
        }

        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        String password = context.getHttpRequest().getDecodedFormParameters().getFirst(NEW_PASSWORD);
        String passMinLength = context.getAuthenticatorConfig().getConfig().get(CustomPasswordResetAuthenticatorFactory.PASSWORD_MIN_LENGTH);
        Optional<String> error = Validator.validatePassword(password, Integer.parseInt(passMinLength));

        if (error.isPresent()) {
            context.challenge(context.form().setError(error.get()).createForm(PASSWORD_FORM));
            return;
        }

        context.getAuthenticationSession().setAuthNote(PASSWORD, password);
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public void close() {

    }
}
