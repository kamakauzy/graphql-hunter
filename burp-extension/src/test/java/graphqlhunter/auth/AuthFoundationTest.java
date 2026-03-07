package graphqlhunter.auth;

import graphqlhunter.GraphQLHunterModels;
import graphqlhunter.auth.config.AuthConfigurationLoader;
import org.junit.jupiter.api.Test;

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
}
