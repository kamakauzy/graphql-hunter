package graphqlhunter.burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GraphQLHttpMessageCodecTest
{
    @Test
    void decodesJsonRequestAsEditable()
    {
        HttpRequest request = request(
            "POST",
            "https://api.example.com/graphql",
            "/graphql",
            "{\"query\":\"query Viewer { viewer { id } }\",\"variables\":{\"id\":\"1\"},\"operationName\":\"Viewer\"}",
            List.of(header("Content-Type", "application/json"))
        );

        GraphQLHttpMessageCodec.DecodedRequest decoded = GraphQLHttpMessageCodec.decodeRequest(request).orElseThrow();

        assertEquals(GraphQLHttpMessageCodec.TransportKind.JSON, decoded.transportKind());
        assertTrue(decoded.editable());
        assertEquals("Viewer", decoded.request().operationName);
    }

    @Test
    void detectsMultipartAsReadOnly()
    {
        HttpRequest request = request(
            "POST",
            "https://api.example.com/graphql",
            "/graphql",
            "------Boundary\r\nContent-Disposition: form-data; name=\"operations\"\r\n\r\n{\"query\":\"mutation Upload($file: Upload!) { upload(file: $file) { ok } }\",\"variables\":{\"file\":null}}\r\n------Boundary--",
            List.of(header("Content-Type", "multipart/form-data; boundary=----Boundary"))
        );

        GraphQLHttpMessageCodec.DecodedRequest decoded = GraphQLHttpMessageCodec.decodeRequest(request).orElseThrow();

        assertEquals(GraphQLHttpMessageCodec.TransportKind.MULTIPART, decoded.transportKind());
        assertFalse(decoded.editable());
    }

    @Test
    void encodesEditedGetRequestPreservingQueryTransport()
    {
        HttpRequest request = request(
            "GET",
            "https://api.example.com/graphql?query=query%20Viewer%20%7B%20viewer%20%7B%20id%20%7D%20%7D&operationName=Viewer",
            "/graphql?query=query%20Viewer%20%7B%20viewer%20%7B%20id%20%7D%20%7D&operationName=Viewer",
            "",
            List.of()
        );

        GraphQLHttpMessageCodec.DecodedRequest decoded = GraphQLHttpMessageCodec.decodeRequest(request).orElseThrow();
        HttpRequest edited = GraphQLHttpMessageCodec.encodeEditedRequest(
            decoded,
            "query Viewer { viewer { name } }",
            "{\"id\":\"2\"}",
            "Viewer"
        );

        assertTrue(edited.path().contains("query="));
        assertTrue(edited.path().contains("operationName=Viewer"));
        assertTrue(edited.path().contains("variables="));
    }

    @Test
    void decodesGraphqlResponseBody()
    {
        HttpRequest request = request(
            "POST",
            "https://api.example.com/graphql",
            "/graphql",
            "{\"query\":\"{ __typename }\"}",
            List.of(header("Content-Type", "application/json"))
        );
        HttpResponse response = response(
            200,
            "{\"data\":{\"__typename\":\"Query\"},\"extensions\":{\"trace\":true}}",
            List.of(header("Content-Type", "application/json"))
        );

        assertTrue(GraphQLHttpMessageCodec.decodeResponse(requestResponse(request, response)).isPresent());
    }

    private HttpRequest request(String method, String url, String path, String body, List<HttpHeader> headers)
    {
        Map<String, Object> state = new LinkedHashMap<>();
        state.put("method", method);
        state.put("url", url);
        state.put("path", path);
        state.put("body", body);
        state.put("headers", new ArrayList<>(headers));
        return (HttpRequest) Proxy.newProxyInstance(
            HttpRequest.class.getClassLoader(),
            new Class<?>[]{HttpRequest.class},
            (proxy, m, args) -> switch (m.getName())
            {
                case "method" -> state.get("method");
                case "url" -> state.get("url");
                case "path", "pathWithoutQuery" -> state.get("path");
                case "bodyToString" -> state.get("body");
                case "headers" -> state.get("headers");
                case "withBody" ->
                {
                    state.put("body", String.valueOf(args[0]));
                    yield proxy;
                }
                case "withUpdatedHeader" ->
                {
                    @SuppressWarnings("unchecked")
                    List<HttpHeader> existing = (List<HttpHeader>) state.get("headers");
                    String name = String.valueOf(args[0]);
                    String value = String.valueOf(args[1]);
                    existing.removeIf(header -> header.name().equalsIgnoreCase(name));
                    existing.add(header(name, value));
                    yield proxy;
                }
                case "withMethod" ->
                {
                    state.put("method", String.valueOf(args[0]));
                    yield proxy;
                }
                case "withPath" ->
                {
                    String newPath = String.valueOf(args[0]);
                    state.put("path", newPath);
                    state.put("url", "https://api.example.com" + newPath);
                    yield proxy;
                }
                case "headerValue" ->
                {
                    @SuppressWarnings("unchecked")
                    List<HttpHeader> existing = (List<HttpHeader>) state.get("headers");
                    String name = String.valueOf(args[0]);
                    yield existing.stream().filter(header -> header.name().equalsIgnoreCase(name)).map(HttpHeader::value).findFirst().orElse("");
                }
                case "hasHeader" ->
                {
                    @SuppressWarnings("unchecked")
                    List<HttpHeader> existing = (List<HttpHeader>) state.get("headers");
                    String name = args[0] instanceof String text ? text : ((HttpHeader) args[0]).name();
                    yield existing.stream().anyMatch(header -> header.name().equalsIgnoreCase(name));
                }
                case "bodyOffset" -> 0;
                case "query" -> "";
                case "parameters", "markers" -> List.of();
                case "hasParameters", "contains", "isInScope" -> false;
                case "contentType", "parameter", "parameterValue", "fileExtension", "httpVersion", "body", "toByteArray", "httpService" -> null;
                case "toString" -> method + " " + url;
                default -> null;
            }
        );
    }

    private HttpResponse response(int statusCode, String body, List<HttpHeader> headers)
    {
        return (HttpResponse) Proxy.newProxyInstance(
            HttpResponse.class.getClassLoader(),
            new Class<?>[]{HttpResponse.class},
            (proxy, m, args) -> switch (m.getName())
            {
                case "statusCode" -> (short) statusCode;
                case "bodyToString" -> body;
                case "headers" -> headers;
                case "headerValue" ->
                {
                    String name = String.valueOf(args[0]);
                    yield headers.stream().filter(header -> header.name().equalsIgnoreCase(name)).map(HttpHeader::value).findFirst().orElse("");
                }
                case "hasHeader" ->
                {
                    String name = args[0] instanceof String text ? text : ((HttpHeader) args[0]).name();
                    yield headers.stream().anyMatch(header -> header.name().equalsIgnoreCase(name));
                }
                case "bodyOffset" -> 0;
                case "cookies", "markers" -> List.of();
                case "contains", "hasCookie" -> false;
                case "reasonPhrase", "httpVersion", "body", "toByteArray", "mimeType", "statedMimeType", "inferredMimeType", "cookie", "cookieValue" -> null;
                case "toString" -> body;
                default -> null;
            }
        );
    }

    private HttpRequestResponse requestResponse(HttpRequest request, HttpResponse response)
    {
        return (HttpRequestResponse) Proxy.newProxyInstance(
            HttpRequestResponse.class.getClassLoader(),
            new Class<?>[]{HttpRequestResponse.class},
            (proxy, m, args) -> switch (m.getName())
            {
                case "request" -> request;
                case "response" -> response;
                case "hasResponse" -> true;
                case "url" -> request.url();
                case "statusCode" -> response.statusCode();
                case "requestMarkers", "responseMarkers" -> List.of();
                case "contains" -> false;
                case "contentType", "annotations", "timingData", "httpService", "copyToTempFile" -> null;
                default -> null;
            }
        );
    }

    private HttpHeader header(String name, String value)
    {
        return (HttpHeader) Proxy.newProxyInstance(
            HttpHeader.class.getClassLoader(),
            new Class<?>[]{HttpHeader.class},
            (proxy, m, args) -> switch (m.getName())
            {
                case "name" -> name;
                case "value" -> value;
                case "toString" -> name + ": " + value;
                default -> null;
            }
        );
    }
}
