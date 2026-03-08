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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GraphQLHunterScannersTest
{
    @Test
    void introspectionScannerReportsEnabledSchema()
    {
        GraphQLClient client = new GraphQLClient("https://api.example.com/graphql", Map.of(), new FakeTransport(), null);
        GraphQLHunterScanners.ScanContext context = new GraphQLHunterScanners.ScanContext(
            new ScanRequest(),
            ConfigurationLoader.scanConfiguration(new ScanSettings()),
            client,
            null,
            ConfigurationLoader.payloads()
        );

        List<Finding> findings = new GraphQLHunterScanners.IntrospectionScanner().scan(context);

        assertFalse(findings.isEmpty());
        assertTrue(findings.stream().anyMatch(finding -> finding.title.contains("Introspection")));
    }

    @Test
    void injectionLiteScannerFindsSqlErrorProbe()
    {
        ScanRequest request = new ScanRequest();
        request.url = "https://api.example.com/graphql";
        GraphQLClient client = new GraphQLClient(request.url, Map.of(), new FakeTransport(), null);
        GraphQLHunterScanners.ScanContext context = new GraphQLHunterScanners.ScanContext(
            request,
            ConfigurationLoader.scanConfiguration(new ScanSettings()),
            client,
            null,
            ConfigurationLoader.payloads()
        );

        List<Finding> findings = new GraphQLHunterScanners.InjectionLiteScanner().scan(context);

        assertTrue(findings.stream().anyMatch(finding -> finding.title.contains("SQL Injection")));
    }

    @Test
    void batchingScannerFlagsLargeAcceptedBatches()
    {
        ScanRequest request = new ScanRequest();
        request.url = "https://api.example.com/graphql";
        GraphQLClient client = new GraphQLClient(request.url, Map.of(), new FakeTransport(), null);
        GraphQLHunterScanners.ScanContext context = new GraphQLHunterScanners.ScanContext(
            request,
            ConfigurationLoader.scanConfiguration(new ScanSettings()),
            client,
            null,
            ConfigurationLoader.payloads()
        );

        List<Finding> findings = new GraphQLHunterScanners.BatchingScanner().scan(context);

        assertTrue(findings.stream().anyMatch(finding -> finding.title.contains("Large GraphQL Batches Accepted")));
    }

    private static final class FakeTransport implements GraphQLHunterCore.GraphQLTransport
    {
        @Override
        public GraphQLResponse postJson(String url, Map<String, String> headers, Object body)
        {
            if (body instanceof Map<?, ?> map)
            {
                String query = String.valueOf(map.get("query"));
                if (query.contains("IntrospectionQuery"))
                {
                    return response(GraphQLHunterJson.readMap("""
                        {
                          "data": {
                            "__schema": {
                              "queryType": { "name": "Query" },
                              "mutationType": null,
                              "types": [
                                {
                                  "kind": "OBJECT",
                                  "name": "Query",
                                  "fields": [
                                    {
                                      "name": "lookup",
                                      "args": [
                                        {
                                          "name": "term",
                                          "type": { "kind": "NON_NULL", "ofType": { "kind": "SCALAR", "name": "String" } }
                                        }
                                      ],
                                      "type": { "kind": "OBJECT", "name": "LookupResponse" }
                                    }
                                  ]
                                },
                                {
                                  "kind": "OBJECT",
                                  "name": "LookupResponse",
                                  "fields": [
                                    { "name": "message", "args": [], "type": { "kind": "SCALAR", "name": "String" } }
                                  ]
                                },
                                { "kind": "SCALAR", "name": "String" },
                                { "kind": "SCALAR", "name": "ID" },
                                { "kind": "SCALAR", "name": "Boolean" },
                                { "kind": "SCALAR", "name": "Int" },
                                { "kind": "SCALAR", "name": "Float" }
                              ]
                            }
                          }
                        }
                        """));
                }
                if (query.contains("lookup"))
                {
                    Object variables = map.get("variables");
                    String term = variables instanceof Map<?, ?> valueMap ? String.valueOf(valueMap.get("term")) : "";
                    if (term.contains("UNION SELECT") || term.contains("' OR '1'='1"))
                    {
                        return response(Map.of("errors", List.of(Map.of("message", "SQLSTATE syntax error near SELECT"))));
                    }
                    return response(Map.of("data", Map.of("lookup", Map.of("message", "ok"))));
                }
            }

            if (body instanceof List<?>)
            {
                List<Map<String, Object>> results = new java.util.ArrayList<>();
                for (int index = 0; index < ((List<?>) body).size(); index++)
                {
                    results.add(Map.of("data", Map.of("__typename", "Query")));
                }
                return response(results);
            }

            return response(Map.of("data", Map.of("__typename", "Query")));
        }

        private GraphQLResponse response(Object body)
        {
            GraphQLResponse response = new GraphQLResponse();
            response.statusCode = 200;
            response.body = GraphQLHunterJson.write(body);
            response.json = body;
            response.headers = new LinkedHashMap<>();
            response.elapsedMillis = 10L;
            return response;
        }
    }
}
