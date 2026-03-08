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
import static org.junit.jupiter.api.Assertions.assertEquals;
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
    void injectionLiteScannerFindsTimeBasedSqlProbe()
    {
        ScanRequest request = new ScanRequest();
        request.url = "https://api.example.com/graphql";
        GraphQLClient client = new GraphQLClient(request.url, Map.of(), new TimingTransport(), null);
        GraphQLHunterScanners.ScanContext context = new GraphQLHunterScanners.ScanContext(
            request,
            ConfigurationLoader.scanConfiguration(new ScanSettings()),
            client,
            null,
            ConfigurationLoader.payloads()
        );

        List<Finding> findings = new GraphQLHunterScanners.InjectionLiteScanner().scan(context);

        assertTrue(findings.stream().anyMatch(finding -> finding.title.contains("Time-Based SQL Injection")));
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

    @Test
    void injectionLiteScannerFindsBooleanDifferentialSqlProbe()
    {
        ScanRequest request = new ScanRequest();
        request.url = "https://api.example.com/graphql";
        GraphQLClient client = new GraphQLClient(request.url, Map.of(), new BooleanTransport(), null);
        GraphQLHunterScanners.ScanContext context = new GraphQLHunterScanners.ScanContext(
            request,
            ConfigurationLoader.scanConfiguration(new ScanSettings()),
            client,
            null,
            ConfigurationLoader.payloads()
        );

        List<Finding> findings = new GraphQLHunterScanners.InjectionLiteScanner().scan(context);

        assertTrue(findings.stream().anyMatch(finding -> finding.title.contains("Boolean-Differential")));
    }

    @Test
    void runWithContextTracksExecutedAndSkippedScanners()
    {
        ScanRequest request = new ScanRequest();
        request.url = "https://api.example.com/graphql";
        ScanSettings settings = new ScanSettings();
        settings.scannerEnabled.put("introspection", true);
        settings.scannerEnabled.put("info_disclosure", false);
        settings.scannerEnabled.put("auth", false);
        settings.scannerEnabled.put("batching", false);
        settings.scannerEnabled.put("injection", false);
        settings.scannerEnabled.put("dos", false);
        settings.scannerEnabled.put("aliasing", false);
        settings.scannerEnabled.put("circular", false);
        settings.scannerEnabled.put("xss", false);
        settings.scannerEnabled.put("jwt", false);
        settings.scannerEnabled.put("rate_limit", false);
        settings.scannerEnabled.put("csrf", false);
        settings.scannerEnabled.put("file_upload", false);
        settings.scannerEnabled.put("mutation_fuzzing", false);
        GraphQLHunterScanners.ScanContext context = new GraphQLHunterScanners.ScanContext(
            request,
            ConfigurationLoader.scanConfiguration(settings),
            new GraphQLClient(request.url, Map.of(), new FakeTransport(), null),
            null,
            ConfigurationLoader.payloads()
        );

        GraphQLHunterModels.ScanExecutionResult result = GraphQLHunterScanners.runWithContext(context);

        assertEquals(List.of("Introspection"), result.executedScanners);
        assertTrue(result.skippedScanners.stream().anyMatch(skip -> "Information Disclosure".equals(skip.scanner)));
        assertTrue(result.failedScanners.isEmpty());
        assertEquals("completed", result.status);
    }

    private static class FakeTransport implements GraphQLHunterCore.GraphQLTransport
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
                                    },
                                    {
                                      "name": "filterPastes",
                                      "args": [
                                        {
                                          "name": "filter",
                                          "type": { "kind": "SCALAR", "name": "String" }
                                        },
                                        {
                                          "name": "limit",
                                          "type": { "kind": "SCALAR", "name": "Int" }
                                        }
                                      ],
                                      "type": {
                                        "kind": "LIST",
                                        "ofType": { "kind": "OBJECT", "name": "PasteObject" }
                                      }
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
                                {
                                  "kind": "OBJECT",
                                  "name": "PasteObject",
                                  "fields": [
                                    { "name": "title", "args": [], "type": { "kind": "SCALAR", "name": "String" } }
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
                        """), 10L);
                }
                if (query.contains("lookup"))
                {
                    Object variables = map.get("variables");
                    String term = variables instanceof Map<?, ?> valueMap ? String.valueOf(valueMap.get("term")) : "";
                    if (term.contains("WAITFOR") || term.contains("SLEEP(") || term.contains("PG_SLEEP"))
                    {
                        return response(Map.of("data", Map.of("lookup", Map.of("message", "delayed"))), 5200L);
                    }
                    if (term.contains("UNION SELECT") || term.contains("' OR '1'='1"))
                    {
                        return response(Map.of("errors", List.of(Map.of("message", "SQLSTATE syntax error near SELECT"))), 10L);
                    }
                    return response(Map.of("data", Map.of("lookup", Map.of("message", "ok"))), 100L);
                }
                if (query.contains("filterPastes"))
                {
                    Object variables = map.get("variables");
                    String filter = variables instanceof Map<?, ?> valueMap ? String.valueOf(valueMap.get("filter")) : "";
                    if (filter.contains("' OR '1'='1") || filter.contains("' OR 'a'='a"))
                    {
                        return response(Map.of("data", Map.of("filterPastes", List.of(
                            Map.of("title", "One"),
                            Map.of("title", "Two"),
                            Map.of("title", "Three")
                        ))), 100L);
                    }
                    return response(Map.of("data", Map.of("filterPastes", List.of())), 100L);
                }
            }

            if (body instanceof List<?>)
            {
                List<Map<String, Object>> results = new java.util.ArrayList<>();
                for (int index = 0; index < ((List<?>) body).size(); index++)
                {
                    results.add(Map.of("data", Map.of("__typename", "Query")));
                }
                return response(results, 10L);
            }

            return response(Map.of("data", Map.of("__typename", "Query")), 10L);
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

    private static final class TimingTransport extends FakeTransport
    {
        @Override
        public GraphQLResponse postJson(String url, Map<String, String> headers, Object body)
        {
            if (body instanceof Map<?, ?> map)
            {
                String query = String.valueOf(map.get("query"));
                if (query.contains("lookup"))
                {
                    Object variables = map.get("variables");
                    String term = variables instanceof Map<?, ?> valueMap ? String.valueOf(valueMap.get("term")) : "";
                    if (term.contains("WAITFOR") || term.contains("SLEEP(") || term.contains("PG_SLEEP"))
                    {
                        return response(Map.of("data", Map.of("lookup", Map.of("message", "delayed"))), 5200L);
                    }
                    return response(Map.of("data", Map.of("lookup", Map.of("message", "ok"))), 100L);
                }
            }
            return super.postJson(url, headers, body);
        }
    }

    private static final class BooleanTransport extends FakeTransport
    {
    }
}
