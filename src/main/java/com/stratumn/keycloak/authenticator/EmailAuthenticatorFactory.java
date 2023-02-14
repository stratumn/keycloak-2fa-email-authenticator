package com.stratumn.keycloak.authenticator;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * @author Niko Köbler, https://www.n-k.de, @niroj
 * @author Stratumn, https://www.stratumn.com
 */
public class EmailAuthenticatorFactory implements AuthenticatorFactory {
	public static final String PROVIDER_ID = "email-authenticator";
	public static final String DISPLAY_TYPE = "EMAIL Authentication";
	public static final String HELP_TEXT = "Validates an OTP sent via email to the users.";
	public static final String REFERENCE_CATEGORY = "otp";

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public String getDisplayType() {
		return DISPLAY_TYPE;
	}

	@Override
	public String getHelpText() {
		return HELP_TEXT;
	}

	@Override
	public String getReferenceCategory() {
		return REFERENCE_CATEGORY;
	}

	@Override
	public boolean isConfigurable() {
		return true;
	}

	@Override
	public boolean isUserSetupAllowed() {
		return false;
	}

	@Override
	public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
		return REQUIREMENT_CHOICES;
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return List.of(
				new ProviderConfigProperty("length", "Code length", "The number of digits of the generated code.",
						ProviderConfigProperty.STRING_TYPE, "6"),
				new ProviderConfigProperty("ttl", "Time-to-live",
						"The time to live in seconds for the code to be valid.", ProviderConfigProperty.STRING_TYPE,
						"300"));
	}

	@Override
	public Authenticator create(KeycloakSession session) {
		return new EmailAuthenticator(new EmailSender(session), SecretGenerator.getInstance());
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
}
