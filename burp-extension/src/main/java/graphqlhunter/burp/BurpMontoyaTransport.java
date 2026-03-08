package graphqlhunter.burp;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import graphqlhunter.GraphQLHunterCore;
import graphqlhunter.GraphQLHunterJson;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

public final class BurpMontoyaTransport implements GraphQLHunterCore.SessionAwareTransport
{
    interface RequestSender
    {
        HttpRequestResponse send(String rawRequest, URI uri);
    }

    private final RequestSender sender;

    public BurpMontoyaTransport(Http http)
    {
        this((rawRequest, uri) ->
        {
            boolean secure = "https".equalsIgnoreCase(uri.getScheme());
            int port = uri.getPort() == -1 ? (secure ? 443 : 80) : uri.getPort();
            HttpService service = HttpService.httpService(uri.getHost(), port, secure);
            HttpRequest request = HttpRequest.httpRequest(service, rawRequest);
            return http.sendRequest(request);
        });
    }

    BurpMontoyaTransport(RequestSender sender)
    {
        this.sender = sender;
    }

    @Override
    public GraphQLHunterCore.GraphQLResponse postJson(String url, Map<String, String> headers, Object body)
    {
        return executeHttp("POST", url, headers, body, null, null);
    }

    @Override
    public GraphQLHunterCore.GraphQLResponse executeHttp(
        String method,
        String url,
        Map<String, String> headers,
        Object jsonBody,
        Map<String, String> formBody,
        String dataBody
    )
    {
        try
        {
            URI uri = URI.create(url);
            String path = uri.getRawPath() == null || uri.getRawPath().isBlank() ? "/" : uri.getRawPath();
            if (uri.getRawQuery() != null && !uri.getRawQuery().isBlank())
            {
                path += "?" + uri.getRawQuery();
            }

            String body = "";
            LinkedHashMap<String, String> mergedHeaders = new LinkedHashMap<>(headers);
            if (jsonBody != null)
            {
                body = GraphQLHunterJson.mapper().writeValueAsString(jsonBody);
                mergedHeaders.putIfAbsent("Content-Type", "application/json");
            }
            else if (formBody != null && !formBody.isEmpty())
            {
                body = formBody.entrySet().stream()
                    .map(entry -> java.net.URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8) + "=" + java.net.URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8))
                    .collect(Collectors.joining("&"));
                mergedHeaders.putIfAbsent("Content-Type", "application/x-www-form-urlencoded");
            }
            else if (dataBody != null)
            {
                body = dataBody;
            }

            mergedHeaders.putIfAbsent("Host", uri.getAuthority());
            mergedHeaders.put("Content-Length", String.valueOf(body.getBytes(StandardCharsets.UTF_8).length));

            StringBuilder raw = new StringBuilder();
            raw.append(method == null || method.isBlank() ? "POST" : method.toUpperCase(Locale.ROOT))
                .append(' ')
                .append(path)
                .append(" HTTP/1.1\r\n");
            mergedHeaders.forEach((key, value) -> raw.append(key).append(": ").append(value).append("\r\n"));
            raw.append("\r\n").append(body);

            HttpRequestResponse response = sender.send(raw.toString(), uri);

            GraphQLHunterCore.GraphQLResponse gqlResponse = new GraphQLHunterCore.GraphQLResponse();
            gqlResponse.statusCode = response.hasResponse() ? response.response().statusCode() : 0;
            gqlResponse.body = response.hasResponse() ? response.response().bodyToString() : "";
            gqlResponse.headers = new LinkedHashMap<>();
            if (response.hasResponse())
            {
                response.response().headers().forEach(header ->
                    gqlResponse.headers.computeIfAbsent(header.name(), ignored -> new java.util.ArrayList<>()).add(header.value())
                );
                try
                {
                    gqlResponse.json = GraphQLHunterJson.mapper().readValue(gqlResponse.body, Object.class);
                }
                catch (Exception ignored)
                {
                    gqlResponse.json = null;
                }
            }
            gqlResponse.elapsedMillis = 0L;
            return gqlResponse;
        }
        catch (Exception exception)
        {
            GraphQLHunterCore.GraphQLResponse response = new GraphQLHunterCore.GraphQLResponse();
            response.statusCode = 0;
            response.body = exception.getMessage();
            return response;
        }
    }

    @Override
    public String getCookie(String name)
    {
        return null;
    }
}
