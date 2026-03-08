package graphqlhunter;

import graphqlhunter.auth.AuthManager;
import graphqlhunter.GraphQLHunterCore.Operation;
import graphqlhunter.GraphQLHunterModels.AuthSettings;
import graphqlhunter.GraphQLHunterModels.ScanRequest;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GraphQLHunterCoreTest
{
    @Test
    void parsesSingleGraphqlJsonRequest()
    {
        Optional<ScanRequest> parsed = GraphQLHunterCore.parseRequest(
            "test",
            "https://api.example.com/graphql",
            "POST",
            Map.of("Content-Type", "application/json"),
            """
                {
                  "query": "query Viewer($id: ID!) { viewer(id: $id) { id name } }",
                  "variables": { "id": "123" },
                  "operationName": "Viewer"
                }
                """
        );

        assertTrue(parsed.isPresent());
        assertEquals("https://api.example.com/graphql", parsed.get().url);
        assertEquals("Viewer", parsed.get().operationName);
        assertEquals("123", ((Map<?, ?>) parsed.get().variables).get("id"));
        assertTrue(parsed.get().query.contains("viewer"));
    }

    @Test
    void parsesBatchGraphqlJsonRequest()
    {
        Optional<ScanRequest> parsed = GraphQLHunterCore.parseRequest(
            "test",
            "https://api.example.com/graphql",
            "POST",
            Map.of("Content-Type", "application/json"),
            """
                [
                  {"query":"{ __typename }"},
                  {"query":"{ __schema { queryType { name } } }"}
                ]
                """
        );

        assertTrue(parsed.isPresent());
        assertTrue(parsed.get().batch);
        assertEquals("{ __typename }", parsed.get().query);
    }

    @Test
    void buildsSchemaAwareOperation()
    {
        Map<String, Object> schema = sampleSchema();
        Map<String, Object> field = GraphQLHunterCore.getRootFields(schema, "queryType").get(0);

        Operation built = GraphQLHunterCore.buildOperation(schema, field, "query", Map.of("id", "abc"));

        assertTrue(built.testable);
        assertTrue(built.query.contains("query AutoQueryViewer"));
        assertTrue(built.query.contains("viewer(id: $id)"));
        assertEquals("abc", built.variables.get("id"));
    }

    @Test
    void validatesAuthByComparingResponses()
    {
        AuthSettings settings = new AuthSettings();
        settings.mode = "imported_headers";
        settings.importedAuthHeaders.put("Authorization", "Bearer secret");
        GraphQLHunterCore.GraphQLClient client = new GraphQLHunterCore.GraphQLClient(
            "https://api.example.com/graphql",
            Map.of(),
            new AuthValidationTransport(),
            null,
            AuthManager.fromState(settings, null)
        );

        GraphQLHunterCore.AuthValidationResult result = client.validateAuth("{ viewer { id } }", null);

        assertTrue(result.authWorking);
        assertTrue(result.authRequired);
        assertEquals(200, result.statusWithAuth);
        assertEquals(401, result.statusWithoutAuth);
    }

    @Test
    void validateAuthUsesIsolatedAnonymousClient()
    {
        AuthSettings settings = new AuthSettings();
        settings.mode = "imported_headers";
        settings.importedAuthHeaders.put("Authorization", "Bearer secret");
        GraphQLHunterCore.GraphQLClient client = new GraphQLHunterCore.GraphQLClient(
            "https://api.example.com/graphql",
            Map.of(),
            new SessionBleedTransport(false),
            null,
            AuthManager.fromState(settings, null)
        );

        GraphQLHunterCore.AuthValidationResult result = client.validateAuth("{ viewer { id } }", null);

        assertTrue(result.authWorking);
        assertTrue(result.authRequired);
        assertEquals(200, result.statusWithAuth);
        assertEquals(401, result.statusWithoutAuth);
    }

    @Test
    void validateAuthTreatsIdenticalPermissionErrorsAsAmbiguousAuthChecked()
    {
        GraphQLHunterCore.GraphQLClient client = new GraphQLHunterCore.GraphQLClient(
            "https://api.example.com/graphql",
            Map.of(),
            new PermissionErrorTransport(),
            null
        );

        GraphQLHunterCore.AuthValidationResult result = client.validateAuth("{ viewer { id } }", null);

        assertTrue(result.authWorking);
        assertTrue(result.authRequired);
        assertTrue(result.analysis.toLowerCase().contains("permission"));
    }

    @Test
    void validateAuthTreatsDifferentDataAsAuthWorking()
    {
        AuthSettings settings = new AuthSettings();
        settings.mode = "imported_headers";
        settings.importedAuthHeaders.put("Authorization", "Bearer secret");
        GraphQLHunterCore.GraphQLClient client = new GraphQLHunterCore.GraphQLClient(
            "https://api.example.com/graphql",
            Map.of(),
            new DifferentDataTransport(),
            null,
            AuthManager.fromState(settings, null)
        );

        GraphQLHunterCore.AuthValidationResult result = client.validateAuth("{ viewer { id } }", null);

        assertTrue(result.authWorking);
        assertTrue(result.authRequired);
        assertTrue(result.analysis.toLowerCase().contains("differ"));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> sampleSchema()
    {
        return GraphQLHunterJson.readMap("""
            {
              "queryType": { "name": "Query" },
              "types": [
                {
                  "kind": "OBJECT",
                  "name": "Query",
                  "fields": [
                    {
                      "name": "viewer",
                      "args": [
                        {
                          "name": "id",
                          "type": { "kind": "NON_NULL", "ofType": { "kind": "SCALAR", "name": "ID" } }
                        }
                      ],
                      "type": { "kind": "OBJECT", "name": "Viewer" }
                    }
                  ]
                },
                {
                  "kind": "OBJECT",
                  "name": "Viewer",
                  "fields": [
                    { "name": "id", "args": [], "type": { "kind": "SCALAR", "name": "ID" } },
                    { "name": "name", "args": [], "type": { "kind": "SCALAR", "name": "String" } }
                  ]
                },
                { "kind": "SCALAR", "name": "String" },
                { "kind": "SCALAR", "name": "ID" }
              ]
            }
            """);
    }

    private static final class AuthValidationTransport implements GraphQLHunterCore.SessionAwareTransport
    {
        @Override
        public GraphQLHunterCore.GraphQLResponse postJson(String url, Map<String, String> headers, Object body)
        {
            boolean authorized = headers.containsKey("Authorization");
            GraphQLHunterCore.GraphQLResponse response = new GraphQLHunterCore.GraphQLResponse();
            response.statusCode = authorized ? 200 : 401;
            response.json = authorized ? Map.of("data", Map.of("viewer", Map.of("id", "123"))) : Map.of("errors", List.of(Map.of("message", "Unauthorized")));
            response.body = GraphQLHunterJson.write(response.json);
            response.headers = new LinkedHashMap<>();
            response.elapsedMillis = 5L;
            return response;
        }

        @Override
        public GraphQLHunterCore.GraphQLResponse executeHttp(String method, String url, Map<String, String> headers, Object jsonBody, Map<String, String> formBody, String dataBody)
        {
            return postJson(url, headers, jsonBody);
        }

        @Override
        public String getCookie(String name)
        {
            return null;
        }
    }

    private static final class SessionBleedTransport implements GraphQLHunterCore.SessionAwareTransport
    {
        private boolean authenticatedSession;

        private SessionBleedTransport(boolean authenticatedSession)
        {
            this.authenticatedSession = authenticatedSession;
        }

        @Override
        public GraphQLHunterCore.GraphQLResponse postJson(String url, Map<String, String> headers, Object body)
        {
            boolean authorized = headers.containsKey("Authorization");
            if (authorized)
            {
                authenticatedSession = true;
            }
            GraphQLHunterCore.GraphQLResponse response = new GraphQLHunterCore.GraphQLResponse();
            boolean effectiveAuth = authorized || authenticatedSession;
            response.statusCode = effectiveAuth ? 200 : 401;
            response.json = effectiveAuth ? Map.of("data", Map.of("viewer", Map.of("id", "123"))) : Map.of("errors", List.of(Map.of("message", "Unauthorized")));
            response.body = GraphQLHunterJson.write(response.json);
            response.headers = new LinkedHashMap<>();
            response.elapsedMillis = 5L;
            return response;
        }

        @Override
        public GraphQLHunterCore.GraphQLResponse executeHttp(String method, String url, Map<String, String> headers, Object jsonBody, Map<String, String> formBody, String dataBody)
        {
            return postJson(url, headers, jsonBody);
        }

        @Override
        public String getCookie(String name)
        {
            return authenticatedSession ? "cookie123" : null;
        }

        @Override
        public GraphQLHunterCore.SessionAwareTransport freshSession()
        {
            return new SessionBleedTransport(false);
        }
    }

    private static final class PermissionErrorTransport implements GraphQLHunterCore.GraphQLTransport
    {
        @Override
        public GraphQLHunterCore.GraphQLResponse postJson(String url, Map<String, String> headers, Object body)
        {
            GraphQLHunterCore.GraphQLResponse response = new GraphQLHunterCore.GraphQLResponse();
            response.statusCode = 200;
            response.json = Map.of("errors", List.of(Map.of("message", "Permission denied for this resource")));
            response.body = GraphQLHunterJson.write(response.json);
            response.headers = new LinkedHashMap<>();
            response.elapsedMillis = 5L;
            return response;
        }
    }

    private static final class DifferentDataTransport implements GraphQLHunterCore.SessionAwareTransport
    {
        @Override
        public GraphQLHunterCore.GraphQLResponse postJson(String url, Map<String, String> headers, Object body)
        {
            boolean authorized = headers.containsKey("Authorization");
            GraphQLHunterCore.GraphQLResponse response = new GraphQLHunterCore.GraphQLResponse();
            response.statusCode = 200;
            response.json = authorized
                ? Map.of("data", Map.of("viewer", Map.of("id", "123", "role", "admin")))
                : Map.of("data", Map.of("viewer", Map.of("id", "123", "role", "guest")));
            response.body = GraphQLHunterJson.write(response.json);
            response.headers = new LinkedHashMap<>();
            response.elapsedMillis = 5L;
            return response;
        }

        @Override
        public GraphQLHunterCore.GraphQLResponse executeHttp(String method, String url, Map<String, String> headers, Object jsonBody, Map<String, String> formBody, String dataBody)
        {
            return postJson(url, headers, jsonBody);
        }

        @Override
        public String getCookie(String name)
        {
            return null;
        }

        @Override
        public GraphQLHunterCore.SessionAwareTransport freshSession()
        {
            return new DifferentDataTransport();
        }
    }
}
