package graphqlhunter.auth;

import graphqlhunter.GraphQLHunterCore;
import graphqlhunter.GraphQLHunterLogger;
import graphqlhunter.GraphQLHunterModels;
import graphqlhunter.auth.config.AuthConfigurationLoader;
import graphqlhunter.auth.config.AuthProfileDefinition;

import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class AuthManager
{
    private final AuthProvider provider;
    private final boolean detectFailures;
    private final AuthRedactor redactor;
    private final GraphQLHunterLogger logger;
    private boolean prepared;

    private AuthManager(AuthProvider provider, boolean detectFailures, GraphQLHunterLogger logger)
    {
        this.provider = provider;
        this.detectFailures = detectFailures;
        this.redactor = new AuthRedactor();
        this.logger = logger;
    }

    public static AuthManager none(GraphQLHunterLogger logger)
    {
        return new AuthManager(null, true, logger);
    }

    public static AuthManager fromState(GraphQLHunterModels.AuthSettings settings, GraphQLHunterLogger logger)
    {
        if (settings == null)
        {
            return none(logger);
        }

        AuthProvider provider = switch ((settings.mode == null ? "none" : settings.mode).toLowerCase(Locale.ROOT))
        {
            case "static_headers" -> new StaticHeadersProvider(settings.staticHeaders, Set.of("Authorization", "Cookie", "Token", "x-api-key"));
            case "imported_headers" -> new StaticHeadersProvider(settings.importedAuthHeaders, Set.of("Authorization", "Cookie", "Token", "x-api-key"));
            case "profile" -> providerFromProfile(settings, logger);
            default -> null;
        };

        return new AuthManager(provider, settings.detectFailures, logger);
    }

    private static AuthProvider providerFromProfile(GraphQLHunterModels.AuthSettings settings, GraphQLHunterLogger logger)
    {
        AuthProfileDefinition definition = AuthConfigurationLoader.configuration().profiles.get(settings.profileName);
        if (definition == null)
        {
            if (logger != null)
            {
                logger.warn("Auth profile not found: " + settings.profileName);
            }
            return null;
        }

        return switch (definition.type)
        {
            case "bearer" -> new BearerTokenProvider(
                definition.headerName,
                definition.prefix,
                mergedVariables(settings).getOrDefault(definition.var == null || definition.var.isBlank() ? "access_token" : definition.var, "")
            );
            case "api_key" -> new ApiKeyProvider(
                definition.headerName,
                mergedVariables(settings).getOrDefault(definition.var == null || definition.var.isBlank() ? "api_key" : definition.var, "")
            );
            case "oauth2_client_credentials", "oauth2_refresh_token", "oauth2_auth_code", "oauth2_device_code" -> new OAuth2Provider(definition, mergedVariables(settings));
            case "scripted" -> new ScriptedProvider(definition, mergedVariables(settings));
            case "cookie_session" -> new CookieSessionProvider(definition, mergedVariables(settings));
            default -> {
                if (logger != null)
                {
                    logger.warn("Auth profile type is not implemented yet in Burp parity foundation: " + definition.type);
                }
                yield null;
            }
        };
    }

    private static Map<String, String> mergedVariables(GraphQLHunterModels.AuthSettings settings)
    {
        java.util.LinkedHashMap<String, String> merged = new java.util.LinkedHashMap<>();
        merged.putAll(settings.authVars);
        merged.putAll(settings.runtimeOnlySecrets);
        return merged;
    }

    public void ensurePrepared(GraphQLHunterCore.GraphQLClient client)
    {
        if (prepared || provider == null)
        {
            return;
        }
        provider.prepare(new AuthExecutionContext(client, logger));
        prepared = true;
    }

    public Map<String, String> requestHeaders()
    {
        return provider == null ? Map.of() : provider.headersForRequest();
    }

    public boolean maybeRefreshAndRetry(GraphQLHunterCore.GraphQLClient client, GraphQLHunterCore.GraphQLResponse response)
    {
        if (provider == null)
        {
            return false;
        }
        if (!provider.isAuthFailure(response))
        {
            return false;
        }
        if (detectFailures && logger != null)
        {
            logger.warn("Possible auth failure detected; attempting one refresh/retry if supported.");
        }
        return provider.canRefresh() && provider.refresh(new AuthExecutionContext(client, logger));
    }

    public Map<String, String> redactHeaders(Map<String, String> headers)
    {
        return redactor.redactHeaders(headers, provider == null ? Set.of() : provider.sensitiveHeaderNames());
    }

    public GraphQLHunterModels.Finding sanitizeFinding(GraphQLHunterModels.Finding finding)
    {
        return redactor.sanitizeFinding(finding, provider == null ? Set.of() : provider.sensitiveHeaderNames());
    }
}
