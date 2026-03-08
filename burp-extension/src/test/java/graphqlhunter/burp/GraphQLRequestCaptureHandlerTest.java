package graphqlhunter.burp;

import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.message.HttpHeader;
import graphqlhunter.GraphQLHunterModels;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GraphQLRequestCaptureHandlerTest
{
    @Test
    void capturesGraphqlRequestFromAllowedToolSource()
    {
        List<GraphQLHunterModels.ScanRequest> captured = new ArrayList<>();
        GraphQLRequestCaptureHandler handler = new GraphQLRequestCaptureHandler(
            captured::add,
            ignored -> null,
            ignored -> null
        );

        handler.handleHttpRequestToBeSent(request(
            ToolType.PROXY,
            "POST",
            "https://api.example.com/graphql",
            "{\"query\":\"{ __typename }\"}",
            List.of(header("Content-Type", "application/json"))
        ));

        assertEquals(1, captured.size());
        assertTrue(captured.getFirst().query.contains("__typename"));
    }

    @Test
    void ignoresNonGraphqlTraffic()
    {
        List<GraphQLHunterModels.ScanRequest> captured = new ArrayList<>();
        GraphQLRequestCaptureHandler handler = new GraphQLRequestCaptureHandler(
            captured::add,
            ignored -> null,
            ignored -> null
        );

        handler.handleHttpRequestToBeSent(request(
            ToolType.PROXY,
            "POST",
            "https://api.example.com/rest",
            "{\"hello\":\"world\"}",
            List.of(header("Content-Type", "application/json"))
        ));

        assertTrue(captured.isEmpty());
    }

    private HttpRequestToBeSent request(ToolType toolType, String method, String url, String body, List<HttpHeader> headers)
    {
        ToolSource toolSource = (ToolSource) Proxy.newProxyInstance(
            ToolSource.class.getClassLoader(),
            new Class<?>[]{ToolSource.class},
            (proxy, m, args) -> switch (m.getName())
            {
                case "toolType" -> toolType;
                case "isFromTool" ->
                {
                    Object[] values = args == null || args.length == 0 ? new Object[0] : (Object[]) args[0];
                    for (Object arg : values)
                    {
                        if (arg == toolType)
                        {
                            yield true;
                        }
                    }
                    yield false;
                }
                default -> null;
            }
        );

        return (HttpRequestToBeSent) Proxy.newProxyInstance(
            HttpRequestToBeSent.class.getClassLoader(),
            new Class<?>[]{HttpRequestToBeSent.class},
            (proxy, m, args) -> switch (m.getName())
            {
                case "toolSource" -> toolSource;
                case "method" -> method;
                case "url" -> url;
                case "bodyToString" -> body;
                case "headers" -> headers;
                case "hasHeader" ->
                {
                    String headerName = args[0] instanceof String text ? text : ((HttpHeader) args[0]).name();
                    yield headers.stream().anyMatch(header -> header.name().equalsIgnoreCase(headerName));
                }
                case "headerValue" ->
                {
                    String headerName = String.valueOf(args[0]);
                    yield headers.stream()
                        .filter(header -> header.name().equalsIgnoreCase(headerName))
                        .map(HttpHeader::value)
                        .findFirst()
                        .orElse("");
                }
                case "path" -> "/graphql";
                case "pathWithoutQuery" -> "/graphql";
                case "httpVersion" -> "HTTP/1.1";
                case "bodyOffset" -> 0;
                case "annotations" -> null;
                case "isInScope" -> true;
                case "contentType" -> null;
                case "parameters", "markers" -> List.of();
                case "hasParameters", "contains" -> false;
                case "toByteArray", "body", "httpService" -> null;
                case "toString" -> method + " " + url;
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
