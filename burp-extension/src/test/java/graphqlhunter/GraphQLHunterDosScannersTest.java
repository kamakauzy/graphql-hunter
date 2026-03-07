package graphqlhunter;

import graphqlhunter.GraphQLHunterCore.GraphQLClient;
import graphqlhunter.GraphQLHunterCore.GraphQLResponse;
import graphqlhunter.GraphQLHunterModels.AuthSettings;
import graphqlhunter.GraphQLHunterModels.Finding;
import graphqlhunter.GraphQLHunterModels.ScanRequest;
import graphqlhunter.GraphQLHunterModels.ScanSettings;
import graphqlhunter.config.ConfigurationLoader;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

class GraphQLHunterDosScannersTest
{
    @Test
    void dosScannerFlagsMissingDepthOrComplexityControls()
    {
        GraphQLHunterScanners.ScanContext context = context();

        List<Finding> findings = new GraphQLHunterScanners.DoSScanner().scan(context);

        assertTrue(findings.stream().anyMatch(finding -> finding.title.contains("Depth Limit") || finding.title.contains("Complexity")));
    }

    @Test
    void aliasingScannerFlagsLargeAliasAcceptance()
    {
        GraphQLHunterScanners.ScanContext context = context();

        List<Finding> findings = new GraphQLHunterScanners.AliasingScanner().scan(context);

        assertTrue(findings.stream().anyMatch(finding -> finding.title.contains("Aliasing") || finding.title.contains("Aliased")));
    }

    @Test
    void circularScannerFlagsSelfReferentialType()
    {
        GraphQLHunterScanners.ScanContext context = context();

        List<Finding> findings = new GraphQLHunterScanners.CircularQueryScanner().scan(context);

        assertTrue(findings.stream().anyMatch(finding -> finding.title.contains("Circular")));
    }

    private GraphQLHunterScanners.ScanContext context()
    {
        ScanRequest request = new ScanRequest();
        request.url = "https://api.example.com/graphql";
        ScanSettings settings = new ScanSettings();
        settings.profileName = GraphQLHunterModels.ScanProfile.DEEP.name();
        GraphQLClient client = new GraphQLClient(
            request.url,
            Map.of(),
            new FakeDosTransport(),
            null
        );
        return new GraphQLHunterScanners.ScanContext(
            request,
            ConfigurationLoader.scanConfiguration(settings),
            client,
            null,
            ConfigurationLoader.payloads()
        );
    }

    private static final class FakeDosTransport implements GraphQLHunterCore.SessionAwareTransport
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
                              "types": [
                                {
                                  "kind": "OBJECT",
                                  "name": "Query",
                                  "fields": [
                                    { "name": "viewer", "args": [], "type": { "kind": "OBJECT", "name": "Node" } }
                                  ]
                                },
                                {
                                  "kind": "OBJECT",
                                  "name": "Node",
                                  "fields": [
                                    { "name": "id", "args": [], "type": { "kind": "SCALAR", "name": "ID" } },
                                    { "name": "children", "args": [], "type": { "kind": "OBJECT", "name": "Node" } }
                                  ]
                                },
                                { "kind": "SCALAR", "name": "ID" },
                                { "kind": "SCALAR", "name": "String" }
                              ]
                            }
                          }
                        }
                        """), 5L);
                }

                if (query.contains("a1: __schema") || query.contains("alias99") || query.contains("call0: viewer"))
                {
                    return response(Map.of("data", Map.of("__typename", "Query")), 3500L);
                }

                if (query.contains("__schema"))
                {
                    long depth = query.chars().filter(ch -> ch == '{').count();
                    if (depth >= 10)
                    {
                        return response(Map.of("data", Map.of("__typename", "Query")), 50L);
                    }
                }
            }
            return response(Map.of("data", Map.of("__typename", "Query")), 50L);
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

        private GraphQLResponse response(Object body, long elapsedMillis)
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
}
