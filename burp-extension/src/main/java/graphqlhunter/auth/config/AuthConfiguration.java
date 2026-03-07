package graphqlhunter.auth.config;

import java.util.LinkedHashMap;
import java.util.Map;

public final class AuthConfiguration
{
    public Map<String, AuthProfileDefinition> profiles = new LinkedHashMap<>();
}
