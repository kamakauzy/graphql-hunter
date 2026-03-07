package graphqlhunter.auth;

import graphqlhunter.GraphQLHunterModels;
import graphqlhunter.GraphQLHunterCore;
import graphqlhunter.auth.config.AuthConfigurationLoader;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
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

    private static final class FakeSessionTransport implements GraphQLHunterCore.SessionAwareTransport
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
            cookies.put("sessionid", "tok123");
            return response(Map.of("ok", true), Map.of("x-csrf-token", java.util.List.of("csrf123")));
        }

        @Override
        public String getCookie(String name)
        {
            return cookies.get(name);
        }

        private GraphQLHunterCore.GraphQLResponse response(Object body)
        {
            return response(body, new LinkedHashMap<>());
        }

        private GraphQLHunterCore.GraphQLResponse response(Object body, Map<String, java.util.List<String>> headers)
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
}
