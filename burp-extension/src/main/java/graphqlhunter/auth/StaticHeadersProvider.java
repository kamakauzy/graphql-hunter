package graphqlhunter.auth;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public final class StaticHeadersProvider implements AuthProvider
{
    private final Map<String, String> headers;
    private final Set<String> sensitiveHeaders;

    public StaticHeadersProvider(Map<String, String> headers, Set<String> sensitiveHeaders)
    {
        this.headers = new LinkedHashMap<>(headers);
        this.sensitiveHeaders = sensitiveHeaders;
    }

    @Override
    public Map<String, String> headersForRequest()
    {
        return new LinkedHashMap<>(headers);
    }

    @Override
    public Set<String> sensitiveHeaderNames()
    {
        return sensitiveHeaders;
    }
}
