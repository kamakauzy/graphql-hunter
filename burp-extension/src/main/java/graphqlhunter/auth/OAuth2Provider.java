package graphqlhunter.auth;

import graphqlhunter.auth.config.AuthProfileDefinition;
import graphqlhunter.auth.flow.FlowStepResult;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public final class OAuth2Provider implements AuthProvider
{
    private final AuthProfileDefinition definition;
    private final Map<String, String> variables;
    private OAuthToken token;

    public OAuth2Provider(AuthProfileDefinition definition, Map<String, String> variables)
    {
        this.definition = definition;
        this.variables = new LinkedHashMap<>(variables);
    }

    @Override
    public void prepare(AuthExecutionContext context)
    {
        if (token != null && !token.isExpired())
        {
            return;
        }
        acquireToken(context, false);
    }

    @Override
    public Map<String, String> headersForRequest()
    {
        if (token == null)
        {
            return Map.of();
        }
        return Map.of("Authorization", token.tokenType + " " + token.accessToken);
    }

    @Override
    public boolean canRefresh()
    {
        return true;
    }

    @Override
    public boolean refresh(AuthExecutionContext context)
    {
        try
        {
            acquireToken(context, true);
            return true;
        }
        catch (RuntimeException exception)
        {
            if (context.logger() != null)
            {
                context.logger().warn("OAuth refresh failed: " + exception.getMessage());
            }
            return false;
        }
    }

    @Override
    public Set<String> sensitiveHeaderNames()
    {
        return Set.of("Authorization");
    }

    private void acquireToken(AuthExecutionContext context, boolean force)
    {
        String type = definition.type == null ? "" : definition.type;
        switch (type)
        {
            case "oauth2_client_credentials" -> clientCredentials(context);
            case "oauth2_refresh_token" -> refreshToken(context);
            case "oauth2_auth_code" -> authCode(context);
            case "oauth2_device_code" -> deviceCode(context);
            default -> throw new IllegalStateException("Unsupported OAuth profile type: " + type);
        }
    }

    private void clientCredentials(AuthExecutionContext context)
    {
        Map<String, String> form = baseOAuthForm();
        form.put("grant_type", "client_credentials");
        handleTokenResponse(requestToken(context, definition.tokenUrl, form));
    }

    private void refreshToken(AuthExecutionContext context)
    {
        Map<String, String> form = baseOAuthForm();
        form.put("grant_type", "refresh_token");
        form.put("refresh_token", variable(definition.refreshTokenVar, "refresh_token"));
        handleTokenResponse(requestToken(context, definition.tokenUrl, form));
    }

    private void authCode(AuthExecutionContext context)
    {
        Map<String, String> form = baseOAuthForm();
        form.put("grant_type", "authorization_code");
        form.put("code", variable(definition.codeVar, "oauth_code"));
        if (definition.redirectUri != null && !definition.redirectUri.isBlank())
        {
            form.put("redirect_uri", definition.redirectUri);
        }
        handleTokenResponse(requestToken(context, definition.tokenUrl, form));
    }

    private void deviceCode(AuthExecutionContext context)
    {
        Map<String, String> deviceForm = new LinkedHashMap<>();
        deviceForm.put("client_id", variable(definition.clientIdVar, "client_id"));
        if (definition.scopeVar != null && !definition.scopeVar.isBlank() && variables.containsKey(definition.scopeVar))
        {
            deviceForm.put("scope", variables.get(definition.scopeVar));
        }
        FlowStepResult deviceResponse = requestToken(context, definition.deviceAuthorizationUrl, deviceForm);
        if (!(deviceResponse.json() instanceof Map<?, ?> deviceJson))
        {
            throw new IllegalStateException("OAuth device authorization did not return JSON");
        }
        Object deviceCode = deviceJson.get("device_code");
        if (deviceCode == null)
        {
            throw new IllegalStateException("OAuth device authorization missing device_code");
        }

        Map<String, String> tokenForm = baseOAuthForm();
        tokenForm.put("grant_type", "urn:ietf:params:oauth:grant-type:device_code");
        tokenForm.put("device_code", String.valueOf(deviceCode));
        tokenForm.put("client_id", variable(definition.clientIdVar, "client_id"));
        handleTokenResponse(requestToken(context, definition.tokenUrl, tokenForm));
    }

    private Map<String, String> baseOAuthForm()
    {
        LinkedHashMap<String, String> form = new LinkedHashMap<>();
        if (definition.clientIdVar != null && !definition.clientIdVar.isBlank())
        {
            form.put("client_id", variable(definition.clientIdVar, "client_id"));
        }
        if (definition.clientSecretVar != null && !definition.clientSecretVar.isBlank())
        {
            form.put("client_secret", variable(definition.clientSecretVar, "client_secret"));
        }
        if (definition.scopeVar != null && !definition.scopeVar.isBlank() && variables.containsKey(definition.scopeVar))
        {
            form.put("scope", variables.get(definition.scopeVar));
        }
        if (definition.audienceVar != null && !definition.audienceVar.isBlank() && variables.containsKey(definition.audienceVar))
        {
            form.put("audience", variables.get(definition.audienceVar));
        }
        return form;
    }

    private FlowStepResult requestToken(AuthExecutionContext context, String url, Map<String, String> form)
    {
        if (url == null || url.isBlank())
        {
            throw new IllegalStateException("OAuth profile missing token URL");
        }
        return context.client().flowClient().executeHttp(
            "POST",
            url,
            Map.of("Content-Type", "application/x-www-form-urlencoded"),
            null,
            form,
            null
        );
    }

    @SuppressWarnings("unchecked")
    private void handleTokenResponse(FlowStepResult result)
    {
        if (!(result.json() instanceof Map<?, ?> rawJson))
        {
            throw new IllegalStateException("OAuth token endpoint did not return JSON");
        }
        Map<String, Object> json = (Map<String, Object>) rawJson;
        Object accessToken = json.get("access_token");
        if (accessToken == null)
        {
            throw new IllegalStateException("OAuth token response missing access_token");
        }
        String tokenType = String.valueOf(json.getOrDefault("token_type", "Bearer"));
        Instant expiresAt = null;
        Object expiresIn = json.get("expires_in");
        if (expiresIn != null)
        {
            try
            {
                expiresAt = Instant.now().plusSeconds(Long.parseLong(String.valueOf(expiresIn)));
            }
            catch (NumberFormatException ignored)
            {
                expiresAt = null;
            }
        }
        token = new OAuthToken(String.valueOf(accessToken), tokenType, expiresAt);
        variables.put("access_token", token.accessToken);
        if (json.get("refresh_token") != null)
        {
            variables.put("refresh_token", String.valueOf(json.get("refresh_token")));
        }
    }

    private String variable(String configuredName, String defaultName)
    {
        String key = configuredName == null || configuredName.isBlank() ? defaultName : configuredName;
        return variables.getOrDefault(key, "");
    }

    private record OAuthToken(String accessToken, String tokenType, Instant expiresAt)
    {
        boolean isExpired()
        {
            return expiresAt != null && Instant.now().isAfter(expiresAt.minusSeconds(30));
        }
    }
}
