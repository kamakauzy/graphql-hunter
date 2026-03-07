package graphqlhunter.discovery;

import graphqlhunter.importer.ImportedRequest;
import graphqlhunter.importer.RequestImporter;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class AutoDiscover
{
    private static final Pattern JWT_PATTERN = Pattern.compile("eyJ[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+");

    public DiscoveryResult analyzeNotes(String notesText)
    {
        DiscoveryResult result = new DiscoveryResult();

        extractUrl(notesText, result);
        extractCredentials(notesText, result);
        extractTokens(notesText, result);
        extractHeaders(notesText, result);
        detectAuthMethod(notesText, result);
        result.recommendations = recommendations(result);
        return result;
    }

    public DiscoveryResult analyzeRequestCollection(List<ImportedRequest> importedRequests)
    {
        DiscoveryResult result = new DiscoveryResult();
        if (importedRequests == null)
        {
            return result;
        }

        for (ImportedRequest request : importedRequests)
        {
            if (request.url != null && !request.url.isBlank() && result.url == null)
            {
                result.url = request.url;
            }
            request.headers.forEach((key, value) ->
            {
                if (key.equalsIgnoreCase("Authorization") || key.equalsIgnoreCase("Token") || key.equalsIgnoreCase("X-API-Key"))
                {
                    result.headers.putIfAbsent(key, value);
                }
            });

            if (request.query != null && request.query.toLowerCase(Locale.ROOT).contains("mutation"))
            {
                result.mutations.add(Map.of(
                    "name", request.name,
                    "url", request.url,
                    "query", request.query
                ));
            }
            else if (request.query != null && !request.query.isBlank())
            {
                result.queries.add(Map.of(
                    "name", request.name,
                    "url", request.url,
                    "query", request.query
                ));
            }
        }

        detectAuthMethod("", result);
        result.recommendations = recommendations(result);
        return result;
    }

    public DiscoveryResult autoDiscover(String name, String content)
    {
        try
        {
            List<ImportedRequest> requests = RequestImporter.autoDetect(name, content);
            return analyzeRequestCollection(requests);
        }
        catch (Exception ignored)
        {
            return analyzeNotes(content);
        }
    }

    private void extractUrl(String notes, DiscoveryResult result)
    {
        for (Pattern pattern : List.of(
            Pattern.compile("https?://[^\\s]+", Pattern.CASE_INSENSITIVE),
            Pattern.compile("url[:\\s]+([^\\s\\n]+)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("endpoint[:\\s]+([^\\s\\n]+)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("graphql[:\\s]+([^\\s\\n]+)", Pattern.CASE_INSENSITIVE)
        ))
        {
            Matcher matcher = pattern.matcher(notes);
            while (matcher.find())
            {
                String candidate = matcher.group(0).startsWith("http") ? matcher.group(0) : matcher.group(1);
                if (candidate.toLowerCase(Locale.ROOT).contains("graphql"))
                {
                    result.url = candidate;
                    return;
                }
            }
        }
    }

    private void extractCredentials(String notes, DiscoveryResult result)
    {
        putIfMatch(notes, result.credentials, "email", Pattern.compile("email[:\\s]+([^\\s\\n@]+@[^\\s\\n]+)", Pattern.CASE_INSENSITIVE));
        putIfMatch(notes, result.credentials, "password", Pattern.compile("(?:password|pwd|pass)[:\\s]+([^\\s\\n]+)", Pattern.CASE_INSENSITIVE));
        putIfMatch(notes, result.credentials, "pdt_uid", Pattern.compile("(?:pdt[_\\s]?uid|pdtUid)[:\\s]+([A-Za-z0-9]+)", Pattern.CASE_INSENSITIVE));
        putIfMatch(notes, result.credentials, "patient_uid", Pattern.compile("(?:patient[_\\s]?uid|patientUid)[:\\s]+([A-Za-z0-9]+)", Pattern.CASE_INSENSITIVE));
        putIfMatch(notes, result.credentials, "careteams_uid", Pattern.compile("(?:careteams[_\\s]?uid|careteamsUid)[:\\s]+([A-Za-z0-9]+)", Pattern.CASE_INSENSITIVE));
    }

    private void extractTokens(String notes, DiscoveryResult result)
    {
        Matcher jwtMatcher = JWT_PATTERN.matcher(notes);
        if (jwtMatcher.find())
        {
            result.tokens.put("access_token", jwtMatcher.group());
        }
        putIfMatch(notes, result.tokens, "refresh_token", Pattern.compile("(?:refresh[_\\s]?token|refreshToken)[:\\s]+([A-Za-z0-9._-]+)", Pattern.CASE_INSENSITIVE));
    }

    private void extractHeaders(String notes, DiscoveryResult result)
    {
        Matcher matcher = Pattern.compile("(Token|Authorization|X-API-Key|apikey)[:\\s]+([^\\n]+)", Pattern.CASE_INSENSITIVE).matcher(notes);
        while (matcher.find())
        {
            String headerName = matcher.group(1);
            if ("apikey".equalsIgnoreCase(headerName))
            {
                headerName = "X-API-Key";
            }
            result.headers.put(headerName, matcher.group(2).trim());
        }
    }

    private void detectAuthMethod(String notes, DiscoveryResult result)
    {
        if (notes.toLowerCase(Locale.ROOT).contains("tokenauth")
            || (result.credentials.containsKey("email") && result.credentials.containsKey("password")))
        {
            result.authMethod = "tokenAuth";
        }
        else if (result.tokens.containsKey("access_token") || result.headers.containsKey("Authorization"))
        {
            result.authMethod = "token_header";
        }
    }

    private Map<String, Object> recommendations(DiscoveryResult result)
    {
        LinkedHashMap<String, Object> recommendations = new LinkedHashMap<>();
        if (result.authMethod != null && result.authMethod.equals("tokenAuth"))
        {
            recommendations.put("auth_profile", "token_auth");
            List<String> authVars = new ArrayList<>();
            if (result.credentials.containsKey("email"))
            {
                authVars.add("email=" + result.credentials.get("email"));
            }
            if (result.credentials.containsKey("password"))
            {
                authVars.add("password=" + result.credentials.get("password"));
            }
            recommendations.put("auth_vars", authVars);
        }
        else if (!result.headers.isEmpty())
        {
            List<String> headers = new ArrayList<>();
            result.headers.forEach((key, value) -> headers.add(key + ": " + value));
            recommendations.put("headers", headers);
        }
        if (result.url != null)
        {
            recommendations.put("url", result.url);
        }
        return recommendations;
    }

    private void putIfMatch(String notes, Map<String, String> target, String key, Pattern pattern)
    {
        Matcher matcher = pattern.matcher(notes);
        if (matcher.find())
        {
            target.put(key, matcher.group(1));
        }
    }
}
