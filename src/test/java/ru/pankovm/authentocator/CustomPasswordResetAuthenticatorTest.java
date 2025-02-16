package ru.pankovm.authentocator;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import ru.pankovm.CustomPasswordResetAuthenticatorFactory;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.*;

public class CustomPasswordResetAuthenticatorTest {
    private CustomPasswordResetAuthenticator authenticator;
    private AuthenticationFlowContext context;
    private LoginFormsProvider formsProvider;
    private AuthenticatorConfigModel configModel;
    private Map<String, String> config;

    @BeforeEach
    public void setUp() {
        authenticator = new CustomPasswordResetAuthenticator();
        context = mock(AuthenticationFlowContext.class);
        formsProvider = mock(LoginFormsProvider.class);
        configModel = new AuthenticatorConfigModel();
        config = new HashMap<>();

        config.put(CustomPasswordResetAuthenticatorFactory.PASSWORD_MIN_LENGTH, "8");
        configModel.setConfig(config);

        when(context.getAuthenticatorConfig()).thenReturn(configModel);
        when(context.form()).thenReturn(formsProvider);

        HttpRequest httpRequest = mock(HttpRequest.class);
        when(context.getHttpRequest()).thenReturn(httpRequest);
    }

    @Test
    public void testAuthenticateEmptyPassword() {
        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        when(context.getHttpRequest().getDecodedFormParameters()).thenReturn(formData);

        Response simpleResponse = Response.ok().build();
        when(formsProvider.createForm(CustomPasswordResetAuthenticator.PASSWORD_FORM)).thenReturn(simpleResponse);

        authenticator.authenticate(context);

        verify(context, times(1)).challenge(simpleResponse);
        verify(context, never()).success();
    }

    @Test
    public void testAuthenticateInvalidPassword() {
        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.add(CustomPasswordResetAuthenticator.PASSWORD, "abc");
        when(context.getHttpRequest().getDecodedFormParameters()).thenReturn(formData);

        Response simpleResponse = Response.ok().build();
        when(formsProvider.setError(anyString())).thenReturn(formsProvider);
        when(formsProvider.createForm(CustomPasswordResetAuthenticator.PASSWORD_FORM)).thenReturn(simpleResponse);

        authenticator.authenticate(context);

        verify(context, times(1)).challenge(simpleResponse);
        verify(context, never()).success();
    }

    @Test
    public void testAuthenticateValidPassword() {
        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.add(CustomPasswordResetAuthenticator.PASSWORD, "Password1");
        when(context.getHttpRequest().getDecodedFormParameters()).thenReturn(formData);

        authenticator.authenticate(context);

        verify(context, times(1)).success();
        verify(context, never()).challenge(any());
    }

    @Test
    public void testActionInvalidPassword() {
        // Симулируем ситуацию, когда в метод action() введён невалидный новый пароль
        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.add(CustomPasswordResetAuthenticator.NEW_PASSWORD, "abc");
        when(context.getHttpRequest().getDecodedFormParameters()).thenReturn(formData);

        Response simpleResponse = Response.ok().build();
        when(formsProvider.setError(anyString())).thenReturn(formsProvider);
        when(formsProvider.createForm(CustomPasswordResetAuthenticator.PASSWORD_FORM))
                .thenReturn(simpleResponse);

        authenticator.action(context);

        verify(context, times(1)).challenge(simpleResponse);
        verify(context, never()).success();
    }

    @Test
    public void testActionValidPassword() {
        // Симулируем ситуацию, когда в метод action() введён валидный новый пароль, например, "Password1"
        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        String validPassword = "Password1";
        formData.add(CustomPasswordResetAuthenticator.NEW_PASSWORD, validPassword);
        when(context.getHttpRequest().getDecodedFormParameters()).thenReturn(formData);

        AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
        when(context.getAuthenticationSession()).thenReturn(authSession);

        authenticator.action(context);

        // Проверяем, что установлена auth note и вызван success()
        verify(authSession, times(1)).setAuthNote(CustomPasswordResetAuthenticator.PASSWORD, validPassword);
        verify(context, times(1)).success();
        verify(context, never()).challenge(any());
    }
}
