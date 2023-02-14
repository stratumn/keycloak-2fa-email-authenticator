# Keycloak OTP email provider

This Keycloak otp email provider provides an authenticator that sends an email containing a password valid for a certain amount of time.

Forked from https://github.com/dasniko/keycloak-2fa-sms-authenticator

## Installation

Make sure you have java 11 installed in your machint. To install this provider in your keycloak, you need first to build the jar file running the following command:

```
mvn install
```

You'll find the jar file uner the `target` directory. Then you need to place this jar file under the `providers` folder of you keycloak. Finally you can start you keycloak server that will automatically detect this new provider at build time and add it to you keycloak.

## Configuration

Once the installation is done and the server started, you'll find this new authenticator that you can add to your authentication flow. The display name of this provider is `EMAIL Authentication`.

Some configuration is required in order for this provider to work. These variables must be set:

- alias (required): that is a name you give to your provider
- ttl (default 300): time to live in seconds for the otp code
- length (default 6): number of digits of the otp code
