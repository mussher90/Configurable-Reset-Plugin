package matuss.keycloak;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;

public class ForgottenPasswordJourneyAuthenticatorFactory implements AuthenticatorFactory {

    public static final String SITE_KEY = "site.key";
    public static final String SITE_SECRET = "secret";

    @Override
    public String getDisplayType() {
        return "Configurable Forgotten Password Form";
    }

    @Override
    public String getReferenceCategory() {
        return "Forgotten Password";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{
                AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.ALTERNATIVE,
                AuthenticationExecutionModel.Requirement.CONDITIONAL,
                AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Configures additional fields to be given during forgotten password journey";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Arrays.asList(
                new ProviderConfigProperty("emailRequired", "Email required", "Whether user must give correct email address during forgotten password journey.", ProviderConfigProperty.BOOLEAN_TYPE, true),
                new ProviderConfigProperty("phoneNumberRequired", "Phone number required", "Whether user must give correct phone number during forgotten password journey.", ProviderConfigProperty.BOOLEAN_TYPE, true),
                new ProviderConfigProperty(SITE_KEY, "Recaptcha Site Key", "Google Recaptcha Site Key", ProviderConfigProperty.STRING_TYPE, null),
                new ProviderConfigProperty(SITE_SECRET, "Recaptcha Secret", "Google Recaptcha Secret", ProviderConfigProperty.STRING_TYPE, null),
                new ProviderConfigProperty("recaptchaRequired", "Recaptcha Required", "Whether page should be protected by reCaptcha.", ProviderConfigProperty.BOOLEAN_TYPE, true)
        );
    }

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return new ForgottenPasswordJourneyAuthenticator();
    }

    @Override
    public void init(Config.Scope scope) {

    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "forgotten-password-journey";
    }
}
