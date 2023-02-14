package com.stratumn.keycloak.authenticator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import javax.ws.rs.core.Response;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.email.EmailException;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.ThemeManager;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * @author Abdessalam Zaimi
 */
@ExtendWith(MockitoExtension.class)
public class EmailAuthenticatorTest {
	private static final Map<String, String> config = Map.of("length", "6", "ttl", "300");
	private static final String THEME_NAME = "custom-theme";
	private static final Locale locale = Locale.US;
	private static final Properties properties = System.getProperties();
	private static final String otpCode = "123456";

	@Mock
	EmailSender emailSender;

	@Mock
	AuthenticationFlowContext authenticationFlowContext;

	@Mock
	AuthenticatorConfigModel authenticatorConfig;

	@Mock
	KeycloakSession keycloakSession;

	@Mock
	UserModel userModel;

	@Mock
	AuthenticationSessionModel authenticationSessionModel;

	@Mock
	ThemeManager themeManager;

	@Mock
	Theme theme;

	@Mock
	KeycloakContext keycloakContext;

	@Mock
	LoginFormsProvider loginFormsProvider;

	@Mock
	RealmModel realmModel;

	@Mock
	SecretGenerator secretGenerator;

	@BeforeAll
	static void setUp() {
		properties.putIfAbsent("emailOtpText", "Your email code is %1$s and is valid for %2$d minutes.");
		properties.putIfAbsent("emailSubject", "OTP");
	}

	void setUpMocks() throws IOException {
		when(authenticatorConfig.getConfig()).thenReturn(config);
		when(keycloakSession.getContext()).thenReturn(keycloakContext);
		when(keycloakContext.resolveLocale(userModel)).thenReturn(locale);
		when(theme.getMessages(locale)).thenReturn(properties);
		when(themeManager.getTheme(THEME_NAME, Theme.Type.LOGIN)).thenReturn(theme);
		when(keycloakSession.theme()).thenReturn(themeManager);

		when(authenticationFlowContext.getAuthenticatorConfig()).thenReturn(authenticatorConfig);
		when(authenticationFlowContext.getSession()).thenReturn(keycloakSession);
		when(authenticationFlowContext.getUser()).thenReturn(userModel);
		when(authenticationFlowContext.getAuthenticationSession()).thenReturn(authenticationSessionModel);
		when(authenticationFlowContext.form()).thenReturn(loginFormsProvider);

		when(secretGenerator.randomString(Integer.parseInt(config.get("length")), SecretGenerator.DIGITS))
				.thenReturn(otpCode);
	}

	@Test
	public void testAuthenticate() throws EmailException, IOException {
		setUpMocks();
		when(authenticationFlowContext.getRealm()).thenReturn(realmModel);
		when(loginFormsProvider.setAttribute("realm", realmModel)).thenReturn(loginFormsProvider);
		EmailAuthenticator emailAuthenticator = new EmailAuthenticator(emailSender, secretGenerator);
		emailAuthenticator.authenticate(authenticationFlowContext);
		verify(emailSender, times(1)).send(userModel, properties.getProperty("emailSubject"),
				String.format(properties.getProperty("emailOtpText"), otpCode,
						Math.floorDiv(Integer.parseInt(config.get("ttl")), 60)));
	}

	@Test
	public void testAuthenticateException() throws EmailException, IOException {
		setUpMocks();
		EmailAuthenticator emailAuthenticator = new EmailAuthenticator(emailSender, secretGenerator);
		Response errorResponse = Response.serverError().build();
		when(loginFormsProvider.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR)).thenReturn(errorResponse);
		when(loginFormsProvider.setError("emailNotSent", "failed to send email")).thenReturn(loginFormsProvider);
		doThrow(new EmailException("failed to send email")).when(emailSender).send(userModel,
				properties.getProperty("emailSubject"), String.format(properties.getProperty("emailOtpText"), otpCode,
						Math.floorDiv(Integer.parseInt(config.get("ttl")), 60)));
		emailAuthenticator.authenticate(authenticationFlowContext);
		verify(authenticationFlowContext, times(1)).failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				errorResponse);
	}

	@Test
	public void testEmailAuthenticatorConfig() {
		EmailAuthenticator emailAuthenticator = new EmailAuthenticator(emailSender, secretGenerator);
		assertEquals(true, emailAuthenticator.requiresUser());
		assertEquals(false, emailAuthenticator.configuredFor(keycloakSession, realmModel, userModel));
		when(userModel.getEmail()).thenReturn("some@email.com");
		assertEquals(true, emailAuthenticator.configuredFor(keycloakSession, realmModel, userModel));
		emailAuthenticator.setRequiredActions(keycloakSession, realmModel, userModel);
		verify(userModel, times(1)).addRequiredAction("email-ra");
	}
}
