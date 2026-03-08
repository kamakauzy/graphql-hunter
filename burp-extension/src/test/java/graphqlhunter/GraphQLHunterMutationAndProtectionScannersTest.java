package graphqlhunter;

import graphqlhunter.GraphQLHunterCore.GraphQLClient;
import graphqlhunter.GraphQLHunterCore.GraphQLResponse;
import graphqlhunter.GraphQLHunterModels.Finding;
import graphqlhunter.GraphQLHunterModels.ScanRequest;
import graphqlhunter.GraphQLHunterModels.ScanSettings;
import graphqlhunter.config.ConfigurationLoader;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertTrue;

class GraphQLHunterMutationAndProtectionScannersTest
{
    @Test
    void mutationFuzzerSurfacesDangerousMutationReviewCandidates()
    {
        GraphQLHunterScanners.ScanContext context = context(Map.of("Authorization", "Bearer token"), new ProtectionTransport());

        List<Finding> findings = new GraphQLHunterScanners.MutationFuzzerScanner().scan(context);

        assertTrue(findings.stream().anyMatch(finding -> finding.title.contains("Dangerous") || finding.title.contains("IDOR") || finding.title.contains("Mass Assignment")));
    }

    @Test
    void rateLimitingScannerDetectsTrueConcurrentThrottling()
    {
        GraphQLHunterScanners.ScanContext context = context(Map.of(), new ConcurrentProtectionTransport());

        List<Finding> findings = new GraphQLHunterScanners.RateLimitingScanner().scan(context);

        assertTrue(findings.stream().anyMatch(finding -> finding.title.equals("Rate Limiting Detected")));
    }

    @Test
    void csrfScannerDetectsCrossSiteOriginAcceptance()
    {
        GraphQLHunterScanners.ScanContext context = context(Map.of("Cookie", "sid=abc123"), new ProtectionTransport());

        List<Finding> findings = new GraphQLHunterScanners.CsrfScanner().scan(context);

        assertTrue(findings.stream().anyMatch(finding -> finding.title.contains("Origin Header Not Validated")));
    }

    @Test
    void csrfScannerSuppressesImportedOriginAndRefererForMissingOriginProbe()
    {
        GraphQLHunterScanners.ScanContext context = context(
            Map.of(
                "Cookie", "sid=abc123",
                "Origin", "https://api.example.com",
                "Referer", "https://api.example.com/app"
            ),
            new ProtectionTransport()
        );

        List<Finding> findings = new GraphQLHunterScanners.CsrfScanner().scan(context);

        assertTrue(findings.stream().anyMatch(finding -> finding.title.contains("Missing Origin Header Validation")));
    }

    @Test
    void authExposureScannerDetectsLoginRateLimiting()
    {
        GraphQLHunterScanners.ScanContext context = context(Map.of(), new LoginProtectionTransport());

        List<Finding> findings = new GraphQLHunterScanners.AuthExposureScanner().scan(context);

        assertTrue(findings.stream().anyMatch(finding -> finding.title.contains("Rate Limiting Detected")));
    }

    @Test
    void fileUploadScannerDetectsUploadSurface()
    {
        GraphQLHunterScanners.ScanContext context = context(Map.of(), new ProtectionTransport());

        List<Finding> findings = new GraphQLHunterScanners.FileUploadScanner().scan(context);

        assertTrue(findings.stream().anyMatch(finding -> finding.title.contains("File Upload Mutation Detected")));
    }

    private GraphQLHunterScanners.ScanContext context(Map<String, String> headers, GraphQLHunterCore.SessionAwareTransport transport)
    {
        ScanRequest request = new ScanRequest();
        request.url = "https://api.example.com/graphql";
        request.headers.putAll(headers);
        ScanSettings settings = new ScanSettings();
        settings.profileName = GraphQLHunterModels.ScanProfile.STANDARD.name();
        GraphQLClient client = new GraphQLClient(request.url, request.headers, transport, null);
        return new GraphQLHunterScanners.ScanContext(
            request,
            ConfigurationLoader.scanConfiguration(settings),
            client,
            null,
            ConfigurationLoader.payloads()
        );
    }

    private static class ProtectionTransport implements GraphQLHunterCore.SessionAwareTransport
    {
        @Override
        public GraphQLResponse postJson(String url, Map<String, String> headers, Object body)
        {
            if (body instanceof Map<?, ?> payload)
            {
                String query = String.valueOf(payload.get("query"));
                if (query.contains("IntrospectionQuery"))
                {
                    return response(GraphQLHunterJson.readMap("""
                        {
                          "data": {
                            "__schema": {
                              "queryType": { "name": "Query" },
                              "mutationType": { "name": "Mutation" },
                              "types": [
                                {
                                  "kind": "OBJECT",
                                  "name": "Query",
                                  "fields": [
                                    {
                                      "name": "viewer",
                                      "args": [],
                                      "type": { "kind": "OBJECT", "name": "Viewer" }
                                    }
                                  ]
                                },
                                {
                                  "kind": "OBJECT",
                                  "name": "Mutation",
                                  "fields": [
                                    {
                                      "name": "deleteUser",
                                      "args": [
                                        { "name": "id", "type": { "kind": "SCALAR", "name": "ID" } }
                                      ],
                                      "type": { "kind": "OBJECT", "name": "MutationResponse" }
                                    },
                                    {
                                      "name": "updateUser",
                                      "args": [
                                        { "name": "input", "type": { "kind": "OBJECT", "name": "UpdateUserInput" } }
                                      ],
                                      "type": { "kind": "OBJECT", "name": "MutationResponse" }
                                    },
                                    {
                                      "name": "uploadPaste",
                                      "args": [
                                        { "name": "filename", "type": { "kind": "SCALAR", "name": "String" } },
                                        { "name": "content", "type": { "kind": "SCALAR", "name": "String" } }
                                      ],
                                      "type": { "kind": "OBJECT", "name": "MutationResponse" }
                                    },
                                    {
                                      "name": "loginUser",
                                      "args": [
                                        { "name": "email", "type": { "kind": "SCALAR", "name": "String" } },
                                        { "name": "password", "type": { "kind": "SCALAR", "name": "String" } }
                                      ],
                                      "type": { "kind": "OBJECT", "name": "MutationResponse" }
                                    }
                                  ]
                                },
                                {
                                  "kind": "OBJECT",
                                  "name": "Viewer",
                                  "fields": [
                                    { "name": "id", "args": [], "type": { "kind": "SCALAR", "name": "ID" } }
                                  ]
                                },
                                {
                                  "kind": "OBJECT",
                                  "name": "MutationResponse",
                                  "fields": [
                                    { "name": "ok", "args": [], "type": { "kind": "SCALAR", "name": "Boolean" } }
                                  ]
                                },
                                {
                                  "kind": "OBJECT",
                                  "name": "UpdateUserInput",
                                  "inputFields": [
                                    { "name": "role", "type": { "kind": "SCALAR", "name": "String" } },
                                    { "name": "name", "type": { "kind": "SCALAR", "name": "String" } }
                                  ]
                                },
                                { "kind": "SCALAR", "name": "ID" },
                                { "kind": "SCALAR", "name": "String" },
                                { "kind": "SCALAR", "name": "Boolean" }
                              ]
                            }
                          }
                        }
                        """), 5L);
                }
            }
            if (body instanceof Map<?, ?> payload)
            {
                String query = String.valueOf(payload.get("query"));
                if (query.startsWith("mutation"))
                {
                    String origin = headers.getOrDefault("Origin", headers.getOrDefault("origin", ""));
                    String referer = headers.getOrDefault("Referer", headers.getOrDefault("referer", ""));
                    if ("https://api.example.com".equals(origin) || referer.startsWith("https://api.example.com"))
                    {
                        return response(Map.of("errors", List.of(Map.of("message", "Origin validated"))), 5L);
                    }
                    return response(Map.of("data", Map.of("ok", true)), 5L);
                }
            }
            return response(Map.of("data", Map.of("__typename", "Query")), 5L);
        }

        @Override
        public GraphQLResponse executeHttp(String method, String url, Map<String, String> headers, Object jsonBody, Map<String, String> formBody, String dataBody)
        {
            return response(Map.of("ok", true), 5L);
        }

        @Override
        public String getCookie(String name)
        {
            return "sessionid".equals(name) ? "cookie123" : null;
        }

        protected GraphQLResponse response(Object body, long elapsedMillis)
        {
            GraphQLResponse response = new GraphQLResponse();
            response.statusCode = 200;
            response.body = GraphQLHunterJson.write(body);
            response.json = body;
            response.headers = new LinkedHashMap<>();
            response.elapsedMillis = elapsedMillis;
            return response;
        }
    }

    private static final class ConcurrentProtectionTransport extends ProtectionTransport
    {
        private final AtomicInteger inflight = new AtomicInteger();

        @Override
        public GraphQLResponse postJson(String url, Map<String, String> headers, Object body)
        {
            if (body instanceof Map<?, ?> payload && "{ __typename }".equals(String.valueOf(payload.get("query"))))
            {
                int current = inflight.incrementAndGet();
                try
                {
                    try
                    {
                        Thread.sleep(25L);
                    }
                    catch (InterruptedException interruptedException)
                    {
                        Thread.currentThread().interrupt();
                    }
                    if (current >= 4)
                    {
                        GraphQLResponse response = new GraphQLResponse();
                        response.statusCode = 429;
                        response.body = GraphQLHunterJson.write(Map.of("errors", List.of(Map.of("message", "Too Many Requests"))));
                        response.json = Map.of("errors", List.of(Map.of("message", "Too Many Requests")));
                        response.headers = new LinkedHashMap<>();
                        response.elapsedMillis = 25L;
                        return response;
                    }
                }
                finally
                {
                    inflight.decrementAndGet();
                }
            }
            return super.postJson(url, headers, body);
        }
    }

    private static final class LoginProtectionTransport extends ProtectionTransport
    {
        private final AtomicInteger attempts = new AtomicInteger();

        @Override
        public GraphQLResponse postJson(String url, Map<String, String> headers, Object body)
        {
            if (body instanceof Map<?, ?> payload)
            {
                String query = String.valueOf(payload.get("query"));
                if (query.contains("loginUser"))
                {
                    int count = attempts.incrementAndGet();
                    if (count >= 4)
                    {
                        GraphQLResponse response = new GraphQLResponse();
                        response.statusCode = 429;
                        response.body = GraphQLHunterJson.write(Map.of("errors", List.of(Map.of("message", "Too Many Requests"))));
                        response.json = Map.of("errors", List.of(Map.of("message", "Too Many Requests")));
                        response.headers = new LinkedHashMap<>();
                        response.elapsedMillis = 5L;
                        return response;
                    }
                    return response(Map.of("errors", List.of(Map.of("message", "Invalid credentials"))), 5L);
                }
            }
            return super.postJson(url, headers, body);
        }
    }
}
