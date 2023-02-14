package com.stratumn.keycloak.authenticator;

import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import javax.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

/**
 * @author Niko Köbler, https://www.n-k.de, @niroj
 * @author Stratumn, https://www.stratumn.com
 */
public class EmailAuthenticator implements Authenticator {
	private static final Logger log = Logger.getLogger(EmailAuthenticator.class);
	private static final String THEME_NAME = "custom-theme";
	private static final String TPL_NAME = "otp-code.ftl";
	private static final String CODE = "code";
	private static final String TTL = "ttl";
	private static final String LENGTH = "length";
	private static final String EXPIRATION_DATE = "expiration";

	private final EmailSender emailSender;
	private final SecretGenerator secretGenerator;

	EmailAuthenticator(EmailSender emailSender, SecretGenerator secretGenerator) {
		this.emailSender = emailSender;
		this.secretGenerator = secretGenerator;
	}

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		Map<String, String> config = context.getAuthenticatorConfig().getConfig();
		KeycloakSession session = context.getSession();
		UserModel user = context.getUser();

		try {
			Theme theme = session.theme().getTheme(THEME_NAME, Theme.Type.LOGIN);
			Locale locale = session.getContext().resolveLocale(user);
			Properties messages = theme.getMessages(locale);
			String emailText = String.format(messages.getProperty("emailOtpText"),
					generateOtpCode(context.getAuthenticationSession(), config), Math.floorDiv(getTtl(config), 60));

			log.debug(String.format("Sending otp email to [%s]", user.getEmail()));
			emailSender.send(user, messages.getProperty("emailSubject"), emailText);

			log.debug(String.format("Otp sent by email to [%s] now displaying form", user.getEmail()));
			context.challenge(context.form().setAttribute("realm", context.getRealm()).createForm(TPL_NAME));
		} catch (Exception e) {
			log.error(String.format("Failed to send email for reason [%s]", e.getMessage()), e);
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
					context.form().setError("emailNotSent", e.getMessage())
							.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
		}
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst(CODE);

		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String code = authSession.getAuthNote(CODE);
		String ttl = authSession.getAuthNote(EXPIRATION_DATE);

		if (code == null || ttl == null) {
			log.error("Missing code or ttl");
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
					context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
			return;
		}

		if (enteredCode.equals(code)) {
			if (Long.parseLong(ttl) < System.currentTimeMillis()) {
				log.debug("Entered code is expired");
				context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
						context.form().setError("emailOtpCodeExpired").createErrorPage(Response.Status.BAD_REQUEST));
			} else {
				log.debug("Entered code is valid");
				context.success();
			}
		} else {
			log.debug("Entered code is invalid");
			AuthenticationExecutionModel execution = context.getExecution();
			if (execution.isRequired()) {
				context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
						context.form().setAttribute("realm", context.getRealm())
								.setError("emailOtpCodeInvalid").createForm(TPL_NAME));
			} else if (execution.isConditional() || execution.isAlternative()) {
				context.attempted();
			}
		}
	}

	@Override
	public boolean requiresUser() {
		return true;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		return user.getEmail() != null;
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
		// this will only work if you have the required action from here configured:
		// https://github.com/dasniko/keycloak-extensions-demo/tree/main/requiredaction
		user.addRequiredAction("email-ra");
	}

	@Override
	public void close() {
	}

	private String generateOtpCode(AuthenticationSessionModel authSession, Map<String, String> config) {
		String code = secretGenerator.randomString(Integer.parseInt(config.get(LENGTH)), SecretGenerator.DIGITS);
		authSession.setAuthNote(CODE, code);
		authSession.setAuthNote(EXPIRATION_DATE, Long.toString(System.currentTimeMillis() + (getTtl(config) * 1000L)));
		return code;
	}

	private Integer getTtl(Map<String, String> config) {
		return Integer.parseInt(config.get(TTL));
	}
}
