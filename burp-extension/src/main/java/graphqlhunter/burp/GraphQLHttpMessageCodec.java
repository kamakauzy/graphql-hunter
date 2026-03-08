package graphqlhunter.burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import graphqlhunter.GraphQLHunterCore;
import graphqlhunter.GraphQLHunterJson;
import graphqlhunter.GraphQLHunterModels;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

public final class GraphQLHttpMessageCodec
{
    public enum TransportKind
    {
        JSON,
        BATCH_JSON,
        GET,
        FORM_URLENCODED,
        APPLICATION_GRAPHQL,
        MULTIPART,
        UNKNOWN
    }

    public record DecodedRequest(
        HttpRequest originalRequest,
        GraphQLHunterModels.ScanRequest request,
        TransportKind transportKind,
        boolean editable
    )
    {
    }

    public record DecodedResponse(
        HttpRequestResponse originalResponse,
        String prettyText
    )
    {
    }

    private GraphQLHttpMessageCodec()
    {
    }

    public static Optional<DecodedRequest> decodeRequest(HttpRequest request)
    {
        Map<String, String> headers = new LinkedHashMap<>();
        request.headers().forEach(header -> headers.put(header.name(), header.value()));
        Optional<GraphQLHunterModels.ScanRequest> parsed = GraphQLHunterCore.parseRequest(
            "burp-editor",
            request.url(),
            request.method(),
            headers,
            request.bodyToString()
        );
        if (parsed.isEmpty())
        {
            return Optional.empty();
        }
        GraphQLHunterModels.ScanRequest scanRequest = parsed.get();
        TransportKind kind = detectTransportKind(request, scanRequest);
        boolean editable = kind == TransportKind.JSON
            || kind == TransportKind.GET
            || kind == TransportKind.FORM_URLENCODED
            || kind == TransportKind.APPLICATION_GRAPHQL;
        return Optional.of(new DecodedRequest(request, scanRequest, kind, editable));
    }

    public static HttpRequest encodeEditedRequest(
        DecodedRequest decoded,
        String query,
        String variablesJson,
        String operationName
    )
    {
        if (!decoded.editable())
        {
            return decoded.originalRequest();
        }
        Object variables = parseVariables(variablesJson);
        String trimmedQuery = query == null ? "" : query.trim();
        String trimmedOperationName = operationName == null ? "" : operationName.trim();

        return switch (decoded.transportKind())
        {
            case JSON -> encodeJson(decoded.originalRequest(), trimmedQuery, variables, trimmedOperationName);
            case GET -> encodeGet(decoded.originalRequest(), trimmedQuery, variables, trimmedOperationName);
            case FORM_URLENCODED -> encodeForm(decoded.originalRequest(), trimmedQuery, variables, trimmedOperationName);
            case APPLICATION_GRAPHQL -> decoded.originalRequest()
                .withBody(trimmedQuery)
                .withUpdatedHeader("Content-Type", "application/graphql");
            default -> decoded.originalRequest();
        };
    }

    public static Optional<DecodedResponse> decodeResponse(HttpRequestResponse requestResponse)
    {
        if (requestResponse == null || !decodeRequest(requestResponse.request()).isPresent() || !requestResponse.hasResponse())
        {
            return Optional.empty();
        }
        String text = requestResponse.response().bodyToString();
        try
        {
            Object parsed = GraphQLHunterJson.mapper().readValue(text, Object.class);
            if (parsed instanceof Map<?, ?> map
                && (map.containsKey("data") || map.containsKey("errors") || map.containsKey("extensions")))
            {
                return Optional.of(new DecodedResponse(requestResponse, GraphQLHunterJson.write(parsed)));
            }
        }
        catch (Exception ignored)
        {
        }
        return Optional.empty();
    }

    private static TransportKind detectTransportKind(HttpRequest request, GraphQLHunterModels.ScanRequest scanRequest)
    {
        String contentType = scanRequest.contentType == null ? "" : scanRequest.contentType.toLowerCase(Locale.ROOT);
        if (contentType.contains("multipart/form-data"))
        {
            return TransportKind.MULTIPART;
        }
        if (scanRequest.batch || (scanRequest.rawBody != null && scanRequest.rawBody.trim().startsWith("[")))
        {
            return TransportKind.BATCH_JSON;
        }
        if ("GET".equalsIgnoreCase(request.method()))
        {
            return TransportKind.GET;
        }
        if (contentType.contains("application/x-www-form-urlencoded"))
        {
            return TransportKind.FORM_URLENCODED;
        }
        if (contentType.contains("application/graphql"))
        {
            return TransportKind.APPLICATION_GRAPHQL;
        }
        if (contentType.contains("application/json") || !contentType.isBlank())
        {
            return TransportKind.JSON;
        }
        return TransportKind.UNKNOWN;
    }

    private static HttpRequest encodeJson(HttpRequest original, String query, Object variables, String operationName)
    {
        LinkedHashMap<String, Object> payload = new LinkedHashMap<>();
        payload.put("query", query);
        if (!(variables instanceof Map<?, ?> map && map.isEmpty()))
        {
            payload.put("variables", variables);
        }
        if (operationName != null && !operationName.isBlank())
        {
            payload.put("operationName", operationName);
        }
        return original
            .withMethod("POST")
            .withBody(GraphQLHunterJson.write(payload))
            .withUpdatedHeader("Content-Type", "application/json");
    }

    private static HttpRequest encodeGet(HttpRequest original, String query, Object variables, String operationName)
    {
        URI uri = URI.create(original.url());
        LinkedHashMap<String, String> params = parseQueryString(uri.getRawQuery());
        params.put("query", query);
        if (!(variables instanceof Map<?, ?> map && map.isEmpty()))
        {
            params.put("variables", writeCompactJson(variables));
        }
        else
        {
            params.remove("variables");
        }
        if (operationName != null && !operationName.isBlank())
        {
            params.put("operationName", operationName);
        }
        else
        {
            params.remove("operationName");
        }
        String rebuilt = buildQueryString(params);
        String path = uri.getRawPath() == null || uri.getRawPath().isBlank() ? "/" : uri.getRawPath();
        return original.withMethod("GET").withPath(rebuilt.isBlank() ? path : path + "?" + rebuilt);
    }

    private static HttpRequest encodeForm(HttpRequest original, String query, Object variables, String operationName)
    {
        LinkedHashMap<String, String> params = new LinkedHashMap<>();
        params.put("query", query);
        if (!(variables instanceof Map<?, ?> map && map.isEmpty()))
        {
            params.put("variables", writeCompactJson(variables));
        }
        if (operationName != null && !operationName.isBlank())
        {
            params.put("operationName", operationName);
        }
        return original
            .withMethod("POST")
            .withBody(buildQueryString(params))
            .withUpdatedHeader("Content-Type", "application/x-www-form-urlencoded");
    }

    private static Object parseVariables(String variablesJson)
    {
        if (variablesJson == null || variablesJson.isBlank())
        {
            return new LinkedHashMap<String, Object>();
        }
        try
        {
            return GraphQLHunterJson.mapper().readValue(variablesJson, Object.class);
        }
        catch (Exception ignored)
        {
            return new LinkedHashMap<String, Object>();
        }
    }

    private static LinkedHashMap<String, String> parseQueryString(String query)
    {
        LinkedHashMap<String, String> params = new LinkedHashMap<>();
        if (query == null || query.isBlank())
        {
            return params;
        }
        for (String pair : query.split("&"))
        {
            String[] parts = pair.split("=", 2);
            String key = java.net.URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
            String value = parts.length > 1 ? java.net.URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : "";
            params.put(key, value);
        }
        return params;
    }

    private static String buildQueryString(Map<String, String> params)
    {
        return params.entrySet().stream()
            .map(entry -> URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8) + "=" + URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8))
            .reduce((left, right) -> left + "&" + right)
            .orElse("");
    }

    private static String writeCompactJson(Object value)
    {
        try
        {
            return GraphQLHunterJson.mapper().writeValueAsString(value);
        }
        catch (Exception exception)
        {
            return "{}";
        }
    }
}
