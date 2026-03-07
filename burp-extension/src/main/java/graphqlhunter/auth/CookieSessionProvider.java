package graphqlhunter.auth;

import graphqlhunter.auth.config.AuthProfileDefinition;
import graphqlhunter.auth.flow.FlowRunner;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public final class CookieSessionProvider implements AuthProvider
{
    private final AuthProfileDefinition definition;
    private final Map<String, String> variables;
    private final FlowRunner flowRunner = new FlowRunner();
    private boolean prepared;

    public CookieSessionProvider(AuthProfileDefinition definition, Map<String, String> variables)
    {
        this.definition = definition;
        this.variables = new LinkedHashMap<>(variables);
    }

    @Override
    public void prepare(AuthExecutionContext context)
    {
        if (prepared)
        {
            return;
        }
        flowRunner.run(context.client().flowClient(), definition.loginSteps, variables);
        prepared = true;
    }

    @Override
    public Map<String, String> headersForRequest()
    {
        if (definition.csrf == null || definition.csrf.isEmpty())
        {
            return Map.of();
        }
        String headerName = String.valueOf(definition.csrf.getOrDefault("header_name", ""));
        String variableName = String.valueOf(definition.csrf.getOrDefault("var", "csrf_token"));
        if (headerName.isBlank())
        {
            return Map.of();
        }
        String value = variables.get(variableName);
        if (value == null || value.isBlank())
        {
            return Map.of();
        }
        return Map.of(headerName, value);
    }

    @Override
    public Set<String> sensitiveHeaderNames()
    {
        if (definition.csrf == null || definition.csrf.isEmpty())
        {
            return Set.of();
        }
        String headerName = String.valueOf(definition.csrf.getOrDefault("header_name", ""));
        return headerName.isBlank() ? Set.of() : Set.of(headerName);
    }
}
