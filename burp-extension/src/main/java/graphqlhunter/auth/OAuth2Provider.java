package graphqlhunter.auth;

import graphqlhunter.auth.config.AuthProfileDefinition;
import graphqlhunter.auth.flow.FlowStepResult;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Locale;
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
        if (token == null || token.isExpired())
        {
            throw new IllegalStateException("OAuth token not available or expired; did acquisition fail?");
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
        handleTokenResponse(
            requestToken(
                context,
                definition.tokenUrl,
                form,
                authMethod(),
                optionalVariable(definition.clientIdVar, "client_id"),
                optionalVariable(definition.clientSecretVar, "client_secret")
            )
        );
    }

    private void refreshToken(AuthExecutionContext context)
    {
        Map<String, String> form = baseOAuthForm();
        form.put("grant_type", "refresh_token");
        form.put("refresh_token", requiredVariable(definition.refreshTokenVar, "refresh_token", "refresh_token"));
        handleTokenResponse(
            requestToken(
                context,
                definition.tokenUrl,
                form,
                authMethod(),
                optionalVariable(definition.clientIdVar, "client_id"),
                optionalVariable(definition.clientSecretVar, "client_secret")
            )
        );
    }

    private void authCode(AuthExecutionContext context)
    {
        Map<String, String> form = baseOAuthForm();
        form.put("grant_type", "authorization_code");
        String codeVariableName = definition.codeVar == null || definition.codeVar.isBlank() ? "oauth_code" : definition.codeVar;
        String code = optionalVariable(definition.codeVar, "oauth_code");
        String redirectUri = definition.redirectUri != null && !definition.redirectUri.isBlank()
            ? definition.redirectUri
            : optionalVariable(null, "redirect_uri");
        if (code.isBlank())
        {
            String clientId = optionalVariable(definition.clientIdVar, "client_id");
            if (context.logger() != null && definition.authorizeUrl != null && !definition.authorizeUrl.isBlank()
                && !clientId.isBlank() && !redirectUri.isBlank())
            {
                String authorizeUrl = definition.authorizeUrl
                    + (definition.authorizeUrl.contains("?") ? "&" : "?")
                    + "response_type=code&client_id=" + urlEncode(clientId)
                    + "&redirect_uri=" + urlEncode(redirectUri);
                String scope = optionalVariable(definition.scopeVar, "scope");
                if (!scope.isBlank())
                {
                    authorizeUrl += "&scope=" + urlEncode(scope);
                }
                context.logger().warn("OAuth auth-code flow requires a code. Open this URL and provide " + codeVariableName + " via runtime auth variables:");
                context.logger().warn(authorizeUrl);
            }
            throw new IllegalStateException("Missing auth code. Provide " + codeVariableName + " before scanning.");
        }
        form.put("code", code);
        if (!redirectUri.isBlank())
        {
            form.put("redirect_uri", redirectUri);
        }
        handleTokenResponse(
            requestToken(
                context,
                definition.tokenUrl,
                form,
                authMethod(),
                optionalVariable(definition.clientIdVar, "client_id"),
                optionalVariable(definition.clientSecretVar, "client_secret")
            )
        );
    }

    private void deviceCode(AuthExecutionContext context)
    {
        if (definition.deviceAuthorizationUrl == null || definition.deviceAuthorizationUrl.isBlank())
        {
            throw new IllegalStateException("oauth2_device_code requires device_authorization_url");
        }
        String clientId = requiredVariable(definition.clientIdVar, "client_id", "client_id");
        Map<String, String> deviceForm = new LinkedHashMap<>();
        deviceForm.put("client_id", clientId);
        String scope = optionalVariable(definition.scopeVar, "scope");
        if (!scope.isBlank())
        {
            deviceForm.put("scope", scope);
        }
        FlowStepResult deviceResponse = requestToken(context, definition.deviceAuthorizationUrl, deviceForm, "body", null, null);
        if (!(deviceResponse.json() instanceof Map<?, ?> deviceJson))
        {
            throw new IllegalStateException("OAuth device authorization did not return JSON");
        }
        Object deviceCode = deviceJson.get("device_code");
        if (deviceCode == null)
        {
            throw new IllegalStateException("OAuth device authorization missing device_code");
        }
        int intervalSeconds = parseInteger(deviceJson.get("interval"), 5);
        int expiresIn = parseInteger(deviceJson.get("expires_in"), 600);
        if (context.logger() != null)
        {
            Object verificationUrl = deviceJson.containsKey("verification_uri_complete")
                ? deviceJson.get("verification_uri_complete")
                : deviceJson.get("verification_uri");
            if (verificationUrl != null)
            {
                context.logger().warn("OAuth device-code flow: visit " + verificationUrl);
            }
            if (deviceJson.get("user_code") != null)
            {
                context.logger().warn("OAuth device-code user code: " + deviceJson.get("user_code"));
            }
        }

        Instant deadline = Instant.now().plusSeconds(expiresIn);
        int currentInterval = Math.max(1, intervalSeconds);
        while (Instant.now().isBefore(deadline))
        {
            Map<String, String> tokenForm = baseOAuthForm();
            tokenForm.put("grant_type", "urn:ietf:params:oauth:grant-type:device_code");
            tokenForm.put("device_code", String.valueOf(deviceCode));
            if ("body".equals(authMethod()))
            {
                tokenForm.put("client_id", clientId);
            }
            try
            {
                handleTokenResponse(
                    requestToken(
                        context,
                        definition.tokenUrl,
                        tokenForm,
                        authMethod(),
                        clientId,
                        optionalVariable(definition.clientSecretVar, "client_secret")
                    )
                );
                return;
            }
            catch (IllegalStateException exception)
            {
                String message = exception.getMessage() == null ? "" : exception.getMessage().toLowerCase(Locale.ROOT);
                if (message.contains("authorization_pending"))
                {
                    sleepSeconds(currentInterval);
                    continue;
                }
                if (message.contains("slow_down"))
                {
                    currentInterval += 5;
                    sleepSeconds(currentInterval);
                    continue;
                }
                throw exception;
            }
        }
        throw new IllegalStateException("Device flow timed out waiting for user authorization");
    }

    private Map<String, String> baseOAuthForm()
    {
        LinkedHashMap<String, String> form = new LinkedHashMap<>();
        String scope = optionalVariable(definition.scopeVar, "scope");
        if (!scope.isBlank())
        {
            form.put("scope", scope);
        }
        String audience = optionalVariable(definition.audienceVar, "audience");
        if (!audience.isBlank())
        {
            form.put("audience", audience);
        }
        return form;
    }

    private FlowStepResult requestToken(
        AuthExecutionContext context,
        String url,
        Map<String, String> form,
        String authMethod,
        String clientId,
        String clientSecret
    )
    {
        if (url == null || url.isBlank())
        {
            throw new IllegalStateException("OAuth profile missing token URL");
        }
        LinkedHashMap<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        LinkedHashMap<String, String> requestForm = new LinkedHashMap<>(form);
        switch ((authMethod == null || authMethod.isBlank() ? "body" : authMethod).toLowerCase(Locale.ROOT))
        {
            case "basic" -> {
                if (clientId == null || clientId.isBlank() || clientSecret == null || clientSecret.isBlank())
                {
                    throw new IllegalStateException("OAuth basic auth requires client_id and client_secret");
                }
                headers.put("Authorization", "Basic " + basicAuth(clientId, clientSecret));
            }
            case "body" -> {
                if (clientId != null && !clientId.isBlank())
                {
                    requestForm.put("client_id", clientId);
                }
                if (clientSecret != null && !clientSecret.isBlank())
                {
                    requestForm.put("client_secret", clientSecret);
                }
            }
            default -> throw new IllegalStateException("Unknown OAuth auth_method: " + authMethod);
        }
        return context.client().flowClient().executeHttp(
            "POST",
            url,
            headers,
            null,
            requestForm,
            null
        );
    }

    @SuppressWarnings("unchecked")
    private void handleTokenResponse(FlowStepResult result)
    {
        if (result.statusCode() >= 400 && !(result.json() instanceof Map<?, ?>))
        {
            throw new IllegalStateException("OAuth token endpoint returned non-JSON (status " + result.statusCode() + ")");
        }
        if (!(result.json() instanceof Map<?, ?> rawJson))
        {
            throw new IllegalStateException("OAuth token endpoint did not return JSON");
        }
        Map<String, Object> json = (Map<String, Object>) rawJson;
        if (result.statusCode() >= 400 || json.get("error") != null)
        {
            throw new IllegalStateException("OAuth token error: " + oauthError(json));
        }
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

    private String authMethod()
    {
        return definition.authMethod == null || definition.authMethod.isBlank() ? "body" : definition.authMethod.trim().toLowerCase(Locale.ROOT);
    }

    private String requiredVariable(String configuredName, String defaultName, String label)
    {
        String value = optionalVariable(configuredName, defaultName);
        if (value.isBlank())
        {
            throw new IllegalStateException("Missing " + label + " for OAuth profile");
        }
        return value;
    }

    private String optionalVariable(String configuredName, String defaultName)
    {
        String key = configuredName == null || configuredName.isBlank() ? defaultName : configuredName;
        return variables.getOrDefault(key, "");
    }

    private String basicAuth(String clientId, String clientSecret)
    {
        return Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
    }

    private int parseInteger(Object value, int defaultValue)
    {
        if (value == null)
        {
            return defaultValue;
        }
        try
        {
            return Integer.parseInt(String.valueOf(value));
        }
        catch (NumberFormatException ignored)
        {
            return defaultValue;
        }
    }

    private void sleepSeconds(int seconds)
    {
        try
        {
            Thread.sleep(Math.max(1, seconds) * 1000L);
        }
        catch (InterruptedException interruptedException)
        {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("OAuth device-code polling interrupted", interruptedException);
        }
    }

    private String oauthError(Map<String, Object> json)
    {
        String error = String.valueOf(json.getOrDefault("error", "unknown_error"));
        Object description = json.get("error_description");
        return description == null ? error : error + " - " + description;
    }

    private String urlEncode(String value)
    {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private record OAuthToken(String accessToken, String tokenType, Instant expiresAt)
    {
        boolean isExpired()
        {
            return expiresAt != null && Instant.now().isAfter(expiresAt.minusSeconds(30));
        }
    }
}
