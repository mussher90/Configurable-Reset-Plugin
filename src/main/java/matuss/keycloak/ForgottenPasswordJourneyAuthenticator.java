package matuss.keycloak;

import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;
import org.keycloak.util.JsonSerialization;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class ForgottenPasswordJourneyAuthenticator implements Authenticator {

    private static final String TPL_CODE = "configurable-rest-cred.ftl";
    public static final String G_RECAPTCHA_RESPONSE = "g-recaptcha-response";
    public static final String SITE_KEY = "site.key";
    public static final String SITE_SECRET = "secret";
    public static final String USE_RECAPTCHA_NET = "useRecaptchaNet";
    private static final Logger LOG = Logger.getLogger(ForgottenPasswordJourneyAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {

        AuthenticatorConfigModel config = context.getAuthenticatorConfig();

        LoginFormsProvider form = createResetCredentialsForm(context);

        if (config == null || config.getConfig() == null
                || config.getConfig().get(SITE_KEY) == null
                || config.getConfig().get(SITE_SECRET) == null
        ) {
            form.addError(new FormMessage(null, Messages.RECAPTCHA_NOT_CONFIGURED));
            return;
        }

        try {
            context.challenge(form.createForm(TPL_CODE));
        } catch (Exception e) {
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                    form.setError("somethingFuckedUp", e.getMessage())
                            .createErrorPage(Response.Status.BAD_REQUEST));
        }

    }

    @Override
    public void action(AuthenticationFlowContext context) {

        Boolean correctEmail;
        Boolean correctPhoneNumber;
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        Map<String, String> config = context.getAuthenticatorConfig().getConfig();
        KeycloakSession session = context.getSession();
        LoginFormsProvider form = createResetCredentialsForm(context);

        UserModel user = session.users().getUserByUsername(context.getRealm(), formData.getFirst("username"));

        if(user != null && user.isEnabled()){
            context.setUser(user);
        }

        Boolean emailRequired = Boolean.valueOf(config.get("emailRequired"));
        Boolean phoneNumberRequired = Boolean.valueOf(config.get("phoneNumberRequired"));
        Boolean recaptchaRequired = Boolean.valueOf(config.get("recaptchaRequired"));


        if(emailRequired){
            String email = user.getEmail();
            String formEmail = formData.getFirst("email");
            correctEmail = formEmail.equals(email);

            LOG.info(String.format("The email entered is correct: %s", correctEmail));

            if(!correctEmail){
                LOG.info(String.format("Failed email"));
                context.clearUser();
                context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, form.setError("forgottenPasswordDetailsError", null).createForm(TPL_CODE));
                return;
            }
        }

        if(phoneNumberRequired){
            String phoneNumber = user.getFirstAttribute("phoneNumber");
            String formPhoneNumber = formData.getFirst("phoneNumber");
            correctPhoneNumber = formPhoneNumber.equals(phoneNumber);

            LOG.info(String.format("The phone number entered is correct: %s", correctPhoneNumber));

            if(!correctPhoneNumber){
                LOG.info(String.format("Failed phone number"));
                context.clearUser();
                context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, form.setError("forgottenPasswordDetailsError", null).createForm(TPL_CODE));
                return;
            }
        }

        if(recaptchaRequired){
            String secret = config.get(SITE_SECRET);
            String captcha = formData.getFirst(G_RECAPTCHA_RESPONSE);
            boolean success = false;
            success = validateRecaptcha(context, success, captcha, secret);
            if(!success){
                LOG.info("Recaptcha failed");
                context.clearUser();
                context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, form.setError("somethingFuckedUp", null).createForm(TPL_CODE));
                return;
            }
        }

        LOG.info("Should send email...");
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
    }

    @Override
    public void close() {

    }

    private String getRecaptchaDomain(Map<String,String> config) {
        Boolean useRecaptcha = Optional.ofNullable(config)
                .map(cfg -> Boolean.valueOf(cfg.get(USE_RECAPTCHA_NET)))
                .orElse(false);
        if (useRecaptcha) {
            return "recaptcha.net";
        }

        return "google.com";
    }

    protected boolean validateRecaptcha(AuthenticationFlowContext context, boolean success, String captcha, String secret) {
        CloseableHttpClient httpClient = context.getSession().getProvider(HttpClientProvider.class).getHttpClient();
        HttpPost post = new HttpPost("https://www." + getRecaptchaDomain(context.getAuthenticatorConfig().getConfig()) + "/recaptcha/api/siteverify");
        List<NameValuePair> formparams = new LinkedList<>();
        formparams.add(new BasicNameValuePair("secret", secret));
        formparams.add(new BasicNameValuePair("response", captcha));
        formparams.add(new BasicNameValuePair("remoteip", context.getConnection().getRemoteAddr()));
        try {
            UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, "UTF-8");
            post.setEntity(form);
            try (CloseableHttpResponse response = httpClient.execute(post)) {
                InputStream content = response.getEntity().getContent();
                try {
                    Map json = JsonSerialization.readValue(content, Map.class);
                    Object val = json.get("success");
                    success = Boolean.TRUE.equals(val);
                } finally {
                    EntityUtils.consumeQuietly(response.getEntity());
                }
            }
        } catch (Exception e) {
            ServicesLogger.LOGGER.recaptchaFailed(e);
        }
        return success;
    }

    private LoginFormsProvider createResetCredentialsForm(AuthenticationFlowContext context){
        Map<String,String> config = context.getAuthenticatorConfig().getConfig();
        LoginFormsProvider form = context.form();

        Boolean emailRequired = Boolean.valueOf(config.get("emailRequired"));
        Boolean phoneNumberRequired = Boolean.valueOf(config.get("phoneNumberRequired"));
        Boolean recaptchaRequired = Boolean.valueOf(config.get("recaptchaRequired"));
        String siteKey = config.get(SITE_KEY);
        String recaptchaDomain = getRecaptchaDomain(config);
        RealmModel realm = context.getRealm();
        String userLanguageTag = context.getSession().getContext().resolveLocale(context.getUser()).toLanguageTag();

        form.setAttribute("recaptchaRequired", recaptchaRequired);
        form.setAttribute("recaptchaSiteKey", siteKey);
        form.addScript("https://www." + recaptchaDomain + "/recaptcha/api.js?hl=" + userLanguageTag);


        form.setAttribute("emailRequired", emailRequired);
        form.setAttribute("phoneNumberRequired", phoneNumberRequired);
        form.setAttribute("realm", realm);

        LOG.info(String.format("email required: %s\n  phone number required: %s", emailRequired, phoneNumberRequired));

        return form;
    }

}
