package graphqlhunter.auth;

import graphqlhunter.GraphQLHunterModels;

import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
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
        GraphQLHunterModels.Finding copy = new GraphQLHunterModels.Finding();
        copy.title = finding.title;
        copy.scanner = finding.scanner;
        copy.severity = finding.severity;
        copy.status = finding.status;
        copy.description = redactText(finding.description);
        copy.impact = redactText(finding.impact);
        copy.remediation = redactText(finding.remediation);
        copy.proof = redactText(finding.proof);
        copy.requestSnippet = redactText(finding.requestSnippet);
        finding.evidence.forEach((key, value) -> copy.evidence.put(key, redactText(String.valueOf(value))));
        return copy;
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
