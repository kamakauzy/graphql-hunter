package graphqlhunter.auth;

import graphqlhunter.auth.config.AuthProfileDefinition;
import graphqlhunter.auth.flow.FlowRunner;
import graphqlhunter.auth.flow.TemplateRenderer;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public final class ScriptedProvider implements AuthProvider
{
    private final AuthProfileDefinition definition;
    private final Map<String, String> variables;
    private final FlowRunner flowRunner = new FlowRunner();
    private boolean prepared;

    public ScriptedProvider(AuthProfileDefinition definition, Map<String, String> variables)
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
        flowRunner.run(context.client().flowClient(), definition.acquireSteps, variables);
        prepared = true;
    }

    @Override
    public Map<String, String> headersForRequest()
    {
        Object rendered = TemplateRenderer.render(definition.injectHeaders, variables);
        if (!(rendered instanceof Map<?, ?> map))
        {
            return Map.of();
        }
        LinkedHashMap<String, String> headers = new LinkedHashMap<>();
        map.forEach((key, value) -> headers.put(String.valueOf(key), value == null ? "" : String.valueOf(value)));
        return headers;
    }

    @Override
    public Set<String> sensitiveHeaderNames()
    {
        return Set.copyOf(definition.sensitiveHeaders);
    }
}
