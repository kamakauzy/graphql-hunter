package graphqlhunter.auth;

import java.util.Map;
import java.util.Set;

public final class BearerTokenProvider implements AuthProvider
{
    private final String headerName;
    private final String prefix;
    private final String token;

    public BearerTokenProvider(String headerName, String prefix, String token)
    {
        this.headerName = headerName == null || headerName.isBlank() ? "Authorization" : headerName;
        this.prefix = prefix == null || prefix.isBlank() ? "Bearer " : (prefix.endsWith(" ") ? prefix : prefix + " ");
        this.token = token;
    }

    @Override
    public Map<String, String> headersForRequest()
    {
        if (token == null || token.isBlank())
        {
            throw new IllegalStateException("Bearer token missing. Provide the configured access token variable before scanning.");
        }
        return Map.of(headerName, prefix + token);
    }

    @Override
    public Set<String> sensitiveHeaderNames()
    {
        return Set.of(headerName);
    }
}
