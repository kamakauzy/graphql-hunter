package graphqlhunter.auth;

import graphqlhunter.GraphQLHunterModels;
import graphqlhunter.GraphQLHunterCore;
import graphqlhunter.auth.config.AuthConfigurationLoader;
import graphqlhunter.auth.config.AuthProfileDefinition;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthFoundationTest
{
    @Test
    void loadsYamlBackedAuthProfiles()
    {
        assertTrue(AuthConfigurationLoader.configuration().profiles.containsKey("bearer"));
        assertEquals("bearer", AuthConfigurationLoader.configuration().profiles.get("bearer").type);
    }

    @Test
    void bearerProfileInjectsAuthorizationHeader()
    {
        GraphQLHunterModels.AuthSettings settings = new GraphQLHunterModels.AuthSettings();
        settings.mode = "profile";
        settings.profileName = "bearer";
        settings.authVars.put("access_token", "secret-token");

        AuthManager manager = AuthManager.fromState(settings, null);

        assertEquals("Bearer secret-token", manager.requestHeaders().get("Authorization"));
    }

    @Test
    void runtimeOnlySecretsOverridePersistedBearerValues()
    {
        GraphQLHunterModels.AuthSettings settings = new GraphQLHunterModels.AuthSettings();
        settings.mode = "profile";
        settings.profileName = "bearer";
        settings.authVars.put("access_token", "persisted-token");
        settings.runtimeOnlySecrets.put("access_token", "runtime-token");

        AuthManager manager = AuthManager.fromState(settings, null);

        assertEquals("Bearer runtime-token", manager.requestHeaders().get("Authorization"));
    }

    @Test
    void missingBearerTokenFailsFast()
    {
        GraphQLHunterModels.AuthSettings settings = new GraphQLHunterModels.AuthSettings();
        settings.mode = "profile";
        settings.profileName = "bearer";

        AuthManager manager = AuthManager.fromState(settings, null);

        assertThrows(IllegalStateException.class, manager::requestHeaders);
    }

    @Test
    void missingProfileFailsFastInsteadOfDowngradingToNoAuth()
    {
        GraphQLHunterModels.AuthSettings settings = new GraphQLHunterModels.AuthSettings();
        settings.mode = "profile";
        settings.profileName = "does_not_exist";

        assertThrows(IllegalStateException.class, () -> AuthManager.fromState(settings, null));
    }

    @Test
    void unsupportedProfileTypeFailsFast()
    {
        AuthProfileDefinition definition = new AuthProfileDefinition();
        definition.type = "unsupported_type";
        AuthConfigurationLoader.configuration().profiles.put("unsupported_profile", definition);
        GraphQLHunterModels.AuthSettings settings = new GraphQLHunterModels.AuthSettings();
        settings.mode = "profile";
        settings.profileName = "unsupported_profile";

        assertThrows(IllegalStateException.class, () -> AuthManager.fromState(settings, null));
    }

    @Test
    void loadsProfileFromExternalAuthConfigPath() throws Exception
    {
        Path config = Files.createTempFile("gqlh-auth", ".yaml");
        try
        {
            Files.writeString(config, """
                profiles:
                  external_bearer:
                    type: bearer
                    header_name: Authorization
                    var: access_token
                    prefix: Bearer
                """);
            GraphQLHunterModels.AuthSettings settings = new GraphQLHunterModels.AuthSettings();
            settings.mode = "profile";
            settings.profileName = "external_bearer";
            settings.authConfigPath = config.toString();
            settings.authVars.put("access_token", "external-token");

            AuthManager manager = AuthManager.fromState(settings, null);

            assertEquals("Bearer external-token", manager.requestHeaders().get("Authorization"));
        }
        finally
        {
            Files.deleteIfExists(config);
        }
    }

    @Test
    void authFailureDetectionMatchesBroaderKeywordSet()
    {
        GraphQLHunterCore.GraphQLResponse response = new GraphQLHunterCore.GraphQLResponse();
        response.statusCode = 200;
        response.json = Map.of("errors", List.of(Map.of("message", "Access denied: token expired")));
        response.body = graphqlhunter.GraphQLHunterJson.write(response.json);

        assertTrue(new BearerTokenProvider("Authorization", "Bearer", "tok").isAuthFailure(response));
    }

    @Test
    void redactorMasksSensitiveHeaders()
    {
        AuthRedactor redactor = new AuthRedactor();
        Map<String, String> redacted = redactor.redactHeaders(
            Map.of("Authorization", "Bearer abcdefghijklmnop", "Content-Type", "application/json"),
            java.util.Set.of()
        );

        assertTrue(redacted.get("Authorization").contains("***REDACTED***"));
        assertEquals("application/json", redacted.get("Content-Type"));
    }

    @Test
    void scriptedTokenAuthProfileAcquiresAndInjectsHeader()
    {
        GraphQLHunterModels.AuthSettings settings = new GraphQLHunterModels.AuthSettings();
        settings.mode = "profile";
        settings.profileName = "token_auth";
        settings.authVars.put("email", "user@example.com");
        settings.authVars.put("password", "pw123");

        AuthManager manager = AuthManager.fromState(settings, null);
        GraphQLHunterCore.GraphQLClient client = new GraphQLHunterCore.GraphQLClient(
            "https://api.example.com/graphql",
            Map.of(),
            new FakeSessionTransport(),
            null,
            manager
        );

        manager.ensurePrepared(client);

        assertEquals("tok123", client.flowClient().getCookie("sessionid"));
        assertEquals("tok123", manager.requestHeaders().get("Token"));
    }

    @Test
    void cookieSessionProfileExtractsCsrfHeader()
    {
        GraphQLHunterModels.AuthSettings settings = new GraphQLHunterModels.AuthSettings();
        settings.mode = "profile";
        settings.profileName = "cookie_session_with_csrf";
        settings.authVars.put("username", "u");
        settings.authVars.put("password", "p");

        AuthManager manager = AuthManager.fromState(settings, null);
        GraphQLHunterCore.GraphQLClient client = new GraphQLHunterCore.GraphQLClient(
            "https://api.example.com/graphql",
            Map.of(),
            new FakeSessionTransport(),
            null,
            manager
        );

        manager.ensurePrepared(client);

        assertEquals("csrf123", manager.requestHeaders().get("x-csrf-token"));
    }

    @Test
    void oauthClientCredentialsProfileAcquiresBearerToken()
    {
        GraphQLHunterModels.AuthSettings settings = new GraphQLHunterModels.AuthSettings();
        settings.mode = "profile";
        settings.profileName = "oauth2_client_credentials";
        settings.authVars.put("client_id", "cid");
        settings.authVars.put("client_secret", "sec");
        settings.authVars.put("scope", "read");

        AuthManager manager = AuthManager.fromState(settings, null);
        GraphQLHunterCore.GraphQLClient client = new GraphQLHunterCore.GraphQLClient(
            "https://api.example.com/graphql",
            Map.of(),
            new FakeSessionTransport(),
            null,
            manager
        );

        manager.ensurePrepared(client);

        assertEquals("Bearer oauth-token", manager.requestHeaders().get("Authorization"));
    }

    @Test
    void oauthRefreshTokenProfileAcquiresBearerToken()
    {
        GraphQLHunterModels.AuthSettings settings = new GraphQLHunterModels.AuthSettings();
        settings.mode = "profile";
        settings.profileName = "oauth2_refresh_token";
        settings.authVars.put("client_id", "cid");
        settings.authVars.put("client_secret", "sec");
        settings.authVars.put("refresh_token", "refresh123");

        AuthManager manager = AuthManager.fromState(settings, null);
        GraphQLHunterCore.GraphQLClient client = new GraphQLHunterCore.GraphQLClient(
            "https://api.example.com/graphql",
            Map.of(),
            new FakeSessionTransport(),
            null,
            manager
        );

        manager.ensurePrepared(client);

        assertEquals("Bearer oauth-token", manager.requestHeaders().get("Authorization"));
    }

    @Test
    void oauthClientCredentialsSupportsBasicAuthMethod()
    {
        AuthProfileDefinition definition = new AuthProfileDefinition();
        definition.type = "oauth2_client_credentials";
        definition.tokenUrl = "https://issuer.example.com/oauth/token";
        definition.authMethod = "basic";
        definition.clientIdVar = "client_id";
        definition.clientSecretVar = "client_secret";

        RecordingTransport transport = new RecordingTransport();
        GraphQLHunterCore.GraphQLClient client = new GraphQLHunterCore.GraphQLClient(
            "https://api.example.com/graphql",
            Map.of(),
            transport,
            null
        );
        OAuth2Provider provider = new OAuth2Provider(definition, new LinkedHashMap<>(Map.of(
            "client_id", "cid",
            "client_secret", "sec"
        )));

        provider.prepare(new AuthExecutionContext(client, null));

        assertTrue(transport.lastHeaders.containsKey("Authorization"));
        assertTrue(transport.lastHeaders.get("Authorization").startsWith("Basic "));
        assertTrue(!transport.lastForm.containsKey("client_secret"));
        assertEquals("Bearer oauth-token", provider.headersForRequest().get("Authorization"));
    }

    @Test
    void oauthAuthCodeMissingCodeFailsFast()
    {
        AuthProfileDefinition definition = new AuthProfileDefinition();
        definition.type = "oauth2_auth_code";
        definition.tokenUrl = "https://issuer.example.com/oauth/token";
        definition.authorizeUrl = "https://issuer.example.com/authorize";
        definition.redirectUri = "http://localhost/callback";
        definition.clientIdVar = "client_id";

        OAuth2Provider provider = new OAuth2Provider(definition, new LinkedHashMap<>(Map.of("client_id", "cid")));

        IllegalStateException exception = assertThrows(
            IllegalStateException.class,
            () -> provider.prepare(new AuthExecutionContext(new GraphQLHunterCore.GraphQLClient(
                "https://api.example.com/graphql",
                Map.of(),
                new RecordingTransport(),
                null
            ), null))
        );
        assertTrue(exception.getMessage().contains("Missing auth code"));
    }

    @Test
    void oauthDeviceCodePollsUntilTokenAvailable()
    {
        AuthProfileDefinition definition = new AuthProfileDefinition();
        definition.type = "oauth2_device_code";
        definition.tokenUrl = "https://issuer.example.com/oauth/token";
        definition.deviceAuthorizationUrl = "https://issuer.example.com/oauth/device/code";
        definition.clientIdVar = "client_id";

        DeviceCodeTransport transport = new DeviceCodeTransport();
        GraphQLHunterCore.GraphQLClient client = new GraphQLHunterCore.GraphQLClient(
            "https://api.example.com/graphql",
            Map.of(),
            transport,
            null
        );
        OAuth2Provider provider = new OAuth2Provider(definition, new LinkedHashMap<>(Map.of("client_id", "cid")));

        provider.prepare(new AuthExecutionContext(client, null));

        assertTrue(transport.tokenPolls.get() >= 2);
        assertEquals("Bearer oauth-token", provider.headersForRequest().get("Authorization"));
    }

    private static class FakeSessionTransport implements GraphQLHunterCore.SessionAwareTransport
    {
        private final Map<String, String> cookies = new LinkedHashMap<>();

        @Override
        public GraphQLHunterCore.GraphQLResponse postJson(String url, Map<String, String> headers, Object body)
        {
            if (body instanceof Map<?, ?> payload && String.valueOf(payload.get("query")).contains("tokenAuth"))
            {
                cookies.put("sessionid", "tok123");
                return response(Map.of("data", Map.of("tokenAuth", Map.of("token", "tok123", "refreshToken", "ref456"))));
            }
            return response(Map.of("data", Map.of("__typename", "Query")));
        }

        @Override
        public GraphQLHunterCore.GraphQLResponse executeHttp(String method, String url, Map<String, String> headers, Object jsonBody, Map<String, String> formBody, String dataBody)
        {
            if (url.contains("/oauth/token"))
            {
                return response(Map.of(
                    "access_token", "oauth-token",
                    "token_type", "Bearer",
                    "expires_in", 3600,
                    "refresh_token", "refresh456"
                ), new LinkedHashMap<>());
            }
            if (url.contains("/oauth/device/code"))
            {
                return response(Map.of(
                    "device_code", "device123",
                    "user_code", "user123",
                    "verification_uri", "https://issuer.example.com/verify"
                ), new LinkedHashMap<>());
            }
            cookies.put("sessionid", "tok123");
            return response(Map.of("ok", true), Map.of("x-csrf-token", java.util.List.of("csrf123")));
        }

        @Override
        public String getCookie(String name)
        {
            return cookies.get(name);
        }

        protected GraphQLHunterCore.GraphQLResponse response(Object body)
        {
            return response(body, new LinkedHashMap<>());
        }

        protected GraphQLHunterCore.GraphQLResponse response(Object body, Map<String, java.util.List<String>> headers)
        {
            GraphQLHunterCore.GraphQLResponse response = new GraphQLHunterCore.GraphQLResponse();
            response.statusCode = 200;
            response.body = graphqlhunter.GraphQLHunterJson.write(body);
            response.json = body;
            response.headers = new LinkedHashMap<>(headers);
            response.elapsedMillis = 5L;
            return response;
        }
    }

    private static final class RecordingTransport extends FakeSessionTransport
    {
        private final Map<String, String> lastHeaders = new LinkedHashMap<>();
        private final Map<String, String> lastForm = new LinkedHashMap<>();

        @Override
        public GraphQLHunterCore.GraphQLResponse executeHttp(String method, String url, Map<String, String> headers, Object jsonBody, Map<String, String> formBody, String dataBody)
        {
            lastHeaders.clear();
            lastHeaders.putAll(headers);
            lastForm.clear();
            if (formBody != null)
            {
                lastForm.putAll(formBody);
            }
            return super.executeHttp(method, url, headers, jsonBody, formBody, dataBody);
        }
    }

    private static final class DeviceCodeTransport extends FakeSessionTransport
    {
        private final AtomicInteger tokenPolls = new AtomicInteger();

        @Override
        public GraphQLHunterCore.GraphQLResponse executeHttp(String method, String url, Map<String, String> headers, Object jsonBody, Map<String, String> formBody, String dataBody)
        {
            if (url.contains("/oauth/token"))
            {
                int poll = tokenPolls.incrementAndGet();
                if (poll == 1)
                {
                    return response(Map.of(
                        "error", "authorization_pending",
                        "error_description", "Still waiting for user verification"
                    ), new LinkedHashMap<>());
                }
                return response(Map.of(
                    "access_token", "oauth-token",
                    "token_type", "Bearer",
                    "expires_in", 3600
                ), new LinkedHashMap<>());
            }
            return super.executeHttp(method, url, headers, jsonBody, formBody, dataBody);
        }
    }
}
