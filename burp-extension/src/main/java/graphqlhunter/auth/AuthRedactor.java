package graphqlhunter.auth;

import graphqlhunter.GraphQLHunterModels;

import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

public final class AuthRedactor
{
    private static final Set<String> DEFAULT_SENSITIVE_HEADERS = Set.of(
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "token",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
        "csrf-token",
        "xsrf-token",
        "password",
        "pass",
        "passwd",
        "client_secret",
        "refresh_token",
        "access_token",
        "id_token",
        "device_code",
        "code"
    );

    private static final Pattern BEARER_PATTERN = Pattern.compile("\\bBearer\\s+([A-Za-z0-9\\-._~+/]+=*)", Pattern.CASE_INSENSITIVE);
    private static final Pattern JWT_PATTERN = Pattern.compile("\\b(eyJ[A-Za-z0-9\\-_]+)\\.([A-Za-z0-9\\-_]{5,})\\.([A-Za-z0-9\\-_]{5,})\\b");

    public Map<String, String> redactHeaders(Map<String, String> headers, Set<String> extraSensitiveHeaders)
    {
        LinkedHashSet<String> sensitive = new LinkedHashSet<>(DEFAULT_SENSITIVE_HEADERS);
        if (extraSensitiveHeaders != null)
        {
            sensitive.addAll(extraSensitiveHeaders);
        }

        LinkedHashMap<String, String> redacted = new LinkedHashMap<>();
        headers.forEach((key, value) ->
        {
            if (key == null)
            {
                return;
            }
            if (sensitive.contains(key.toLowerCase(Locale.ROOT)))
            {
                redacted.put(key, mask(value));
            }
            else
            {
                redacted.put(key, value);
            }
        });
        return redacted;
    }

    public String redactText(String text)
    {
        if (text == null || text.isBlank())
        {
            return text;
        }
        return JWT_PATTERN.matcher(BEARER_PATTERN.matcher(text).replaceAll("Bearer ***REDACTED***"))
            .replaceAll("***REDACTED_JWT***");
    }

    public GraphQLHunterModels.Finding sanitizeFinding(GraphQLHunterModels.Finding finding, Set<String> extraSensitiveHeaders)
    {
        Set<String> sensitive = new LinkedHashSet<>(DEFAULT_SENSITIVE_HEADERS);
        if (extraSensitiveHeaders != null)
        {
            sensitive.addAll(extraSensitiveHeaders);
        }
        GraphQLHunterModels.Finding copy = new GraphQLHunterModels.Finding();
        copy.title = finding.title;
        copy.scanner = finding.scanner;
        copy.severity = finding.severity;
        copy.status = finding.status;
        copy.description = asText(redactObject(finding.description, sensitive));
        copy.impact = asText(redactObject(finding.impact, sensitive));
        copy.remediation = asText(redactObject(finding.remediation, sensitive));
        copy.proof = asText(redactObject(finding.proof, sensitive));
        copy.requestSnippet = asText(redactObject(finding.requestSnippet, sensitive));
        finding.evidence.forEach((key, value) -> copy.evidence.put(key, redactObject(value, sensitive)));
        return copy;
    }

    public Object redactObject(Object value, Set<String> sensitiveKeys)
    {
        Set<String> sensitive = sensitiveKeys == null ? DEFAULT_SENSITIVE_HEADERS : sensitiveKeys;
        if (value instanceof Map<?, ?> map)
        {
            LinkedHashMap<String, Object> redacted = new LinkedHashMap<>();
            map.forEach((key, entryValue) ->
            {
                String keyText = String.valueOf(key);
                if (sensitive.contains(keyText.toLowerCase(Locale.ROOT)))
                {
                    redacted.put(keyText, mask(String.valueOf(entryValue)));
                }
                else
                {
                    redacted.put(keyText, redactObject(entryValue, sensitive));
                }
            });
            return redacted;
        }
        if (value instanceof List<?> list)
        {
            List<Object> redacted = new ArrayList<>();
            list.forEach(item -> redacted.add(redactObject(item, sensitive)));
            return redacted;
        }
        if (value instanceof String text)
        {
            return redactText(text);
        }
        return value;
    }

    private String asText(Object value)
    {
        return value == null ? null : String.valueOf(value);
    }

    private String mask(String value)
    {
        if (value == null)
        {
            return null;
        }
        if (value.length() <= 8)
        {
            return "***REDACTED***";
        }
        return value.substring(0, 3) + "***REDACTED***" + value.substring(value.length() - 3);
    }
}
