package com.stratumn.keycloak.authenticator;

import java.util.Map;

import org.keycloak.email.DefaultEmailSenderProvider;
import org.keycloak.email.EmailException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;

/**
 * @author Stratumn, https://www.stratumn.com
 */
public class EmailSender extends DefaultEmailSenderProvider {
    private final Map<String, String> smtpConfig;

    public EmailSender(KeycloakSession session) {
        super(session);
        smtpConfig = session.getContext().getRealm().getSmtpConfig();
    }

    public void send(UserModel user, String subject, String body) throws EmailException {
        send(smtpConfig, user, subject, body, body);
    }
}
