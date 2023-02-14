package com.stratumn.keycloak.authenticator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.ListIterator;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * @author Abdessalam Zaimi
 */
@ExtendWith(MockitoExtension.class)
public class EmailAuthenticatorFactoryTest {
    private static EmailAuthenticatorFactory emailAuthenticatorFactory;
    private static final List<ProviderConfigProperty> expectedConfigProperties = List.of(
            new ProviderConfigProperty("length", "Code length", "The number of digits of the generated code.",
                    ProviderConfigProperty.STRING_TYPE, "6"),
            new ProviderConfigProperty("ttl", "Time-to-live", "The time to live in seconds for the code to be valid.",
                    ProviderConfigProperty.STRING_TYPE, "300"));

    @Mock
    KeycloakSession session;

    @Mock
    KeycloakContext context;

    @Mock
    RealmModel realmModel;

    @BeforeAll
    static void setUp() {
        emailAuthenticatorFactory = new EmailAuthenticatorFactory();
    }

    @Test
    void testAuthenticatorFactoryConfig() {
        assertEquals("email-authenticator", emailAuthenticatorFactory.getId());
        assertEquals("EMAIL Authentication", emailAuthenticatorFactory.getDisplayType());
        assertEquals("Validates an OTP sent via email to the users.", emailAuthenticatorFactory.getHelpText());
        assertEquals("otp", emailAuthenticatorFactory.getReferenceCategory());
        assertEquals(true, emailAuthenticatorFactory.isConfigurable());
        assertEquals(false, emailAuthenticatorFactory.isUserSetupAllowed());
        assertEquals(AuthenticatorFactory.REQUIREMENT_CHOICES, emailAuthenticatorFactory.getRequirementChoices());

        List<ProviderConfigProperty> configProperties = emailAuthenticatorFactory.getConfigProperties();
        assertEquals(expectedConfigProperties.size(), configProperties.size());
        ListIterator<ProviderConfigProperty> configPropertiesIterator = configProperties.listIterator();
        ListIterator<ProviderConfigProperty> expectedConfigPropertiesIterator = expectedConfigProperties.listIterator();

        while (configPropertiesIterator.hasNext() && expectedConfigPropertiesIterator.hasNext()) {
            ProviderConfigProperty property = configPropertiesIterator.next();
            ProviderConfigProperty expectedProperty = expectedConfigPropertiesIterator.next();
            assertEquals(expectedProperty.getName(), property.getName());
            assertEquals(expectedProperty.getLabel(), property.getLabel());
            assertEquals(expectedProperty.getHelpText(), property.getHelpText());
            assertEquals(expectedProperty.getType(), property.getType());
            assertEquals(expectedProperty.getDefaultValue(), property.getDefaultValue());
        }

        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realmModel);
        when(realmModel.getSmtpConfig()).thenReturn(Map.of("some", "config"));
        assertInstanceOf(EmailAuthenticator.class, emailAuthenticatorFactory.create(session));
    }
}