package graphqlhunter.auth;

import java.util.Map;
import java.util.Set;

public final class ApiKeyProvider implements AuthProvider
{
    private final String headerName;
    private final String value;

    public ApiKeyProvider(String headerName, String value)
    {
        this.headerName = headerName == null || headerName.isBlank() ? "x-api-key" : headerName;
        this.value = value;
    }

    @Override
    public Map<String, String> headersForRequest()
    {
        if (value == null || value.isBlank())
        {
            throw new IllegalStateException("API key missing. Provide the configured api_key variable before scanning.");
        }
        return Map.of(headerName, value);
    }

    @Override
    public Set<String> sensitiveHeaderNames()
    {
        return Set.of(headerName);
    }
}
