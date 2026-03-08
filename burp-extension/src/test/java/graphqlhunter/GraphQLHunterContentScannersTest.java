package graphqlhunter;

import graphqlhunter.GraphQLHunterCore.GraphQLClient;
import graphqlhunter.GraphQLHunterCore.GraphQLResponse;
import graphqlhunter.GraphQLHunterModels.Finding;
import graphqlhunter.GraphQLHunterModels.ScanRequest;
import graphqlhunter.GraphQLHunterModels.ScanSettings;
import graphqlhunter.config.ConfigurationLoader;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

class GraphQLHunterContentScannersTest
{
    @Test
    void xssScannerMarksReflectedPayloadForManualReview()
    {
        GraphQLHunterScanners.ScanContext context = context(Map.of(), new ContentTransport());

        List<Finding> findings = new GraphQLHunterScanners.XssScanner().scan(context);

        assertTrue(findings.stream().anyMatch(finding -> finding.status == GraphQLHunterModels.FindingStatus.MANUAL_REVIEW));
    }

    @Test
    void jwtScannerDetectsJwtUsageAndLongLifetime()
    {
        String header = jwtToken(InstantEpoch.nowMinus(60), InstantEpoch.nowPlus(60L * 60 * 48));
        GraphQLHunterScanners.ScanContext context = context(Map.of("Authorization", "Bearer " + header), new ContentTransport());

        List<Finding> findings = new GraphQLHunterScanners.JwtScanner().scan(context);

        assertTrue(findings.stream().anyMatch(finding -> finding.title.contains("JWT Token Authentication Detected")));
        assertTrue(findings.stream().anyMatch(finding -> finding.title.contains("Long-Lived JWT")));
    }

    @Test
    void jwtScannerDetectsNoneAlgorithmAcceptance()
    {
        String header = jwtToken(InstantEpoch.nowMinus(60), InstantEpoch.nowPlus(3600));
        GraphQLHunterScanners.ScanContext context = context(Map.of("Authorization", "Bearer " + header), new NoneAlgAcceptingTransport());

        List<Finding> findings = new GraphQLHunterScanners.JwtScanner().scan(context);

        assertTrue(findings.stream().anyMatch(finding -> finding.title.contains("none' Algorithm Vulnerability")));
    }

    private GraphQLHunterScanners.ScanContext context(Map<String, String> headers, GraphQLHunterCore.SessionAwareTransport transport)
    {
        ScanRequest request = new ScanRequest();
        request.url = "https://api.example.com/graphql";
        request.headers.putAll(headers);
        ScanSettings settings = new ScanSettings();
        GraphQLClient client = new GraphQLClient(request.url, request.headers, transport, null);
        return new GraphQLHunterScanners.ScanContext(
            request,
            ConfigurationLoader.scanConfiguration(settings),
            client,
            null,
            ConfigurationLoader.payloads()
        );
    }

    private String jwtToken(long iat, long exp)
    {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(("{\"iat\":" + iat + ",\"exp\":" + exp + "}").getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".signature";
    }

    private static class ContentTransport implements GraphQLHunterCore.SessionAwareTransport
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
                                      "name": "echo",
                                      "args": [
                                        {"name":"message","type":{"kind":"SCALAR","name":"String"}}
                                      ],
                                      "type": {"kind":"OBJECT","name":"EchoResponse"}
                                    }
                                  ]
                                },
                                {
                                  "kind": "OBJECT",
                                  "name": "Mutation",
                                  "fields": [
                                    {
                                      "name": "echoMutation",
                                      "args": [
                                        {"name":"message","type":{"kind":"SCALAR","name":"String"}}
                                      ],
                                      "type": {"kind":"OBJECT","name":"EchoResponse"}
                                    }
                                  ]
                                },
                                {
                                  "kind": "OBJECT",
                                  "name": "EchoResponse",
                                  "fields": [
                                    {"name":"message","args":[],"type":{"kind":"SCALAR","name":"String"}}
                                  ]
                                },
                                {"kind":"SCALAR","name":"String"}
                              ]
                            }
                          }
                        }
                        """), 5L);
                }
                Object variables = payload.get("variables");
                String message = variables instanceof Map<?, ?> map ? String.valueOf(map.get("message")) : "";
                if (query.contains("echoMutation"))
                {
                    return response(Map.of("data", Map.of("echoMutation", Map.of("message", message))), 5L);
                }
                if (query.contains("echo"))
                {
                    return response(Map.of("data", Map.of("echo", Map.of("message", message))), 5L);
                }
            }
            if (body instanceof Map<?, ?> payload && "{ __typename }".equals(String.valueOf(payload.get("query"))))
            {
                if (!headers.containsKey("Authorization"))
                {
                    GraphQLResponse unauthorized = response(Map.of("errors", List.of(Map.of("message", "Unauthorized"))), 5L);
                    unauthorized.statusCode = 401;
                    return unauthorized;
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
            return null;
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

    private static final class NoneAlgAcceptingTransport extends ContentTransport
    {
        @Override
        public GraphQLResponse postJson(String url, Map<String, String> headers, Object body)
        {
            String authorization = headers.getOrDefault("Authorization", "");
            if (authorization.startsWith("Bearer ") && authorization.endsWith(".") && body instanceof Map<?, ?> payload
                && "{ __typename }".equals(String.valueOf(payload.get("query"))))
            {
                return response(Map.of("data", Map.of("__typename", "Query")), 5L);
            }
            return super.postJson(url, headers, body);
        }
    }

    private static final class InstantEpoch
    {
        private static long nowPlus(long delta)
        {
            return java.time.Instant.now().getEpochSecond() + delta;
        }

        private static long nowMinus(long delta)
        {
            return java.time.Instant.now().getEpochSecond() - delta;
        }
    }
}
