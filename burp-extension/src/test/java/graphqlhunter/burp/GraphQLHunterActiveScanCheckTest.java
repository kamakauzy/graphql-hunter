package graphqlhunter.burp;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;

class GraphQLHunterActiveScanCheckTest
{
    @Test
    void emitsIssuesForSafeActiveSubset()
    {
        GraphQLHunterActiveScanCheck check = new GraphQLHunterActiveScanCheck(
            testPublisher(),
            ignored -> new BurpMontoyaTransport((rawRequest, uri) ->
            {
                String body = rawRequest.substring(rawRequest.indexOf("\r\n\r\n") + 4);
                HttpResponse sentResponse;
                if (body.contains("IntrospectionQuery"))
                {
                    sentResponse = response(
                        200,
                        "{\"data\":{\"__schema\":{\"queryType\":{\"name\":\"Query\"},\"mutationType\":null,\"types\":[]}}}",
                        List.of(header("Content-Type", "application/json"))
                    );
                }
                else if (body.trim().startsWith("["))
                {
                    sentResponse = response(
                        200,
                        "[{\"data\":{\"__typename\":\"Query\"}},{\"data\":{\"__schema\":{\"queryType\":{\"name\":\"Query\"}}}},{\"data\":{\"__type\":{\"name\":\"Query\"}}}]",
                        List.of(header("Content-Type", "application/json"))
                    );
                }
                else
                {
                    sentResponse = response(
                        200,
                        "{\"data\":{\"__typename\":\"Query\"}}",
                        List.of(header("Content-Type", "application/json"))
                    );
                }
                HttpRequest sent = request(
                    "POST",
                    uri.toString(),
                    uri.getRawPath() == null || uri.getRawPath().isBlank() ? "/" : uri.getRawPath(),
                    body,
                    List.of(header("Content-Type", "application/json"))
                );
                return requestResponse(sent, sentResponse);
            })
        );
        HttpRequest request = request(
            "POST",
            "https://api.example.com/graphql",
            "/graphql",
            "{\"query\":\"{ __typename }\"}",
            List.of(header("Content-Type", "application/json"))
        );
        HttpResponse response = response(
            200,
            "{\"data\":{\"__typename\":\"Query\"}}",
            List.of(header("Content-Type", "application/json"))
        );
        assertFalse(check.issuesFor(requestResponse(request, response), null).isEmpty());
    }

    private static final class FakeSiteMap implements burp.api.montoya.sitemap.SiteMap
    {
        @Override
        public java.util.List<HttpRequestResponse> requestResponses(burp.api.montoya.sitemap.SiteMapFilter filter) { return java.util.List.of(); }
        @Override
        public java.util.List<HttpRequestResponse> requestResponses() { return java.util.List.of(); }
        @Override
        public java.util.List<burp.api.montoya.scanner.audit.issues.AuditIssue> issues(burp.api.montoya.sitemap.SiteMapFilter filter) { return java.util.List.of(); }
        @Override
        public java.util.List<burp.api.montoya.scanner.audit.issues.AuditIssue> issues() { return java.util.List.of(); }
        @Override
        public void add(HttpRequestResponse requestResponse) {}
        @Override
        public void add(burp.api.montoya.scanner.audit.issues.AuditIssue auditIssue) {}
    }

    private HttpRequest request(String method, String url, String path, String body, List<HttpHeader> headers)
    {
        return (HttpRequest) Proxy.newProxyInstance(
            HttpRequest.class.getClassLoader(),
            new Class<?>[]{HttpRequest.class},
            (proxy, m, args) -> switch (m.getName())
            {
                case "method" -> method;
                case "url" -> url;
                case "path", "pathWithoutQuery" -> path;
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
                case "parameters", "markers" -> List.of();
                case "hasParameters", "contains", "isInScope" -> false;
                case "contentType", "parameter", "parameterValue", "fileExtension", "httpVersion", "body", "toByteArray", "httpService" -> null;
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

    private BurpIssuePublisher testPublisher()
    {
        return new BurpIssuePublisher(
            new FakeSiteMap(),
            null,
            LocalAuditIssue::new,
            (request, finding) -> List.of()
        );
    }

    private static final class LocalAuditIssue implements burp.api.montoya.scanner.audit.issues.AuditIssue
    {
        private final String name;
        private final String detail;
        private final String remediation;
        private final String baseUrl;
        private final burp.api.montoya.scanner.audit.issues.AuditIssueSeverity severity;
        private final burp.api.montoya.scanner.audit.issues.AuditIssueConfidence confidence;

        private LocalAuditIssue(
            String name,
            String detail,
            String remediation,
            String baseUrl,
            burp.api.montoya.scanner.audit.issues.AuditIssueSeverity severity,
            burp.api.montoya.scanner.audit.issues.AuditIssueConfidence confidence,
            String background,
            String remediationBackground,
            List<HttpRequestResponse> requestResponses
        )
        {
            this.name = name;
            this.detail = detail;
            this.remediation = remediation;
            this.baseUrl = baseUrl;
            this.severity = severity;
            this.confidence = confidence;
        }

        @Override public String name() { return name; }
        @Override public String detail() { return detail; }
        @Override public String remediation() { return remediation; }
        @Override public burp.api.montoya.http.HttpService httpService() { return null; }
        @Override public String baseUrl() { return baseUrl; }
        @Override public burp.api.montoya.scanner.audit.issues.AuditIssueSeverity severity() { return severity; }
        @Override public burp.api.montoya.scanner.audit.issues.AuditIssueConfidence confidence() { return confidence; }
        @Override public List<HttpRequestResponse> requestResponses() { return List.of(); }
        @Override public List<burp.api.montoya.collaborator.Interaction> collaboratorInteractions() { return List.of(); }
        @Override public burp.api.montoya.scanner.audit.issues.AuditIssueDefinition definition() { return null; }
    }
}
