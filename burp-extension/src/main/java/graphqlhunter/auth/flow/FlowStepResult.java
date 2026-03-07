package graphqlhunter.auth.flow;

import java.util.LinkedHashMap;
import java.util.Map;

public record FlowStepResult(
    int statusCode,
    Map<String, String> headers,
    String text,
    Object json
)
{
    public FlowStepResult
    {
        headers = headers == null ? new LinkedHashMap<>() : new LinkedHashMap<>(headers);
        text = text == null ? "" : text;
    }
}
