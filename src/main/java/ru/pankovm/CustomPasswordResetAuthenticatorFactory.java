package ru.pankovm;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import ru.pankovm.authentocator.CustomPasswordResetAuthenticator;

import java.util.List;

public class CustomPasswordResetAuthenticatorFactory implements AuthenticatorFactory {
    public static final String PROVIDER_ID = "custom-password-reset-authenticator";
    public static final String PASSWORD_MIN_LENGTH = "passwordMinLength";

    @Override
    public String getDisplayType() {
        return "Custom password reset authenticator";
    }

    @Override
    public String getReferenceCategory() {
        return "";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return getRequirements();
    }

    private AuthenticationExecutionModel.Requirement[] getRequirements() {
        return new AuthenticationExecutionModel.Requirement[]{
                AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Validates password before reset";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of(
                new ProviderConfigProperty(
                        PASSWORD_MIN_LENGTH, "Минимальная длина пароля", "Установите минимальную длину пароля", ProviderConfigProperty.STRING_TYPE, "6")
        );
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new CustomPasswordResetAuthenticator();
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
