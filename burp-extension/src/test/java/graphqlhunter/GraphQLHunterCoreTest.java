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
import java.nio.charset.StandardCharsets;

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
    void parsesGraphqlGetRequestFromQueryParameters()
    {
        Optional<ScanRequest> parsed = GraphQLHunterCore.parseRequest(
            "test",
            "https://api.example.com/graphql?query=query%20Viewer%20%7B%20viewer%20%7B%20id%20%7D%20%7D&operationName=Viewer&variables=%7B%22id%22%3A%22123%22%7D",
            "GET",
            Map.of(),
            ""
        );

        assertTrue(parsed.isPresent());
        assertEquals("Viewer", parsed.get().operationName);
        assertTrue(parsed.get().query.contains("viewer"));
        assertEquals("123", ((Map<?, ?>) parsed.get().variables).get("id"));
    }

    @Test
    void parsesFormEncodedGraphqlPostRequest()
    {
        Optional<ScanRequest> parsed = GraphQLHunterCore.parseRequest(
            "test",
            "https://api.example.com/graphql",
            "POST",
            Map.of("Content-Type", "application/x-www-form-urlencoded"),
            "query=query%20Viewer%20%7B%20viewer%20%7B%20id%20%7D%20%7D&operationName=Viewer&variables=%7B%22id%22%3A%22123%22%7D"
        );

        assertTrue(parsed.isPresent());
        assertEquals("Viewer", parsed.get().operationName);
        assertTrue(parsed.get().query.contains("viewer"));
        assertEquals("123", ((Map<?, ?>) parsed.get().variables).get("id"));
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

    @Test
    void querySupportsCaseInsensitiveHeaderSuppression()
    {
        HeaderCaptureTransport transport = new HeaderCaptureTransport();
        GraphQLHunterCore.GraphQLClient client = new GraphQLHunterCore.GraphQLClient(
            "https://api.example.com/graphql",
            Map.of(
                "Origin", "https://api.example.com",
                "Referer", "https://api.example.com/app",
                "Content-Type", "application/json"
            ),
            transport,
            null
        );

        client.query("{ __typename }", null, null, Map.of(), false, java.util.Set.of("origin", "referer"));

        assertFalse(transport.lastHeaders.containsKey("Origin"));
        assertFalse(transport.lastHeaders.containsKey("Referer"));
        assertEquals("application/json", transport.lastHeaders.get("Content-Type"));
    }

    @Test
    void queryWithUploadsUsesGraphqlMultipartSpec()
    {
        MultipartCaptureTransport transport = new MultipartCaptureTransport();
        GraphQLHunterCore.GraphQLClient client = new GraphQLHunterCore.GraphQLClient(
            "https://api.example.com/graphql",
            Map.of("Content-Type", "application/json"),
            transport,
            null
        );

        client.query(
            "mutation Upload($file: Upload!) { upload(file: $file) { ok } }",
            Map.of("file", "upload-placeholder"),
            "Upload",
            Map.of(),
            false,
            java.util.Set.of(),
            Map.of("variables.file", new GraphQLHunterCore.UploadPart("proof.txt", "hello".getBytes(StandardCharsets.UTF_8), "text/plain"))
        );

        assertTrue(transport.lastHeaders.get("Content-Type").contains("multipart/form-data"));
        assertTrue(transport.lastBody.contains("name=\"operations\""));
        assertTrue(transport.lastBody.contains("name=\"map\""));
        assertTrue(transport.lastBody.contains("\"variables.file\""));
        assertTrue(transport.lastBody.contains("filename=\"proof.txt\""));
    }

    @Test
    void findUploadTargetsSupportsNestedInputUploads()
    {
        Map<String, Object> schema = GraphQLHunterJson.readMap("""
            {
              "queryType": { "name": "Query" },
              "mutationType": { "name": "Mutation" },
              "types": [
                {
                  "kind": "OBJECT",
                  "name": "Mutation",
                  "fields": [
                    {
                      "name": "uploadAsset",
                      "args": [
                        {
                          "name": "input",
                          "type": { "kind": "NON_NULL", "ofType": { "kind": "INPUT_OBJECT", "name": "UploadAssetInput" } }
                        }
                      ],
                      "type": { "kind": "OBJECT", "name": "MutationResponse" }
                    }
                  ]
                },
                {
                  "kind": "INPUT_OBJECT",
                  "name": "UploadAssetInput",
                  "inputFields": [
                    { "name": "title", "type": { "kind": "SCALAR", "name": "String" } },
                    { "name": "file", "type": { "kind": "NON_NULL", "ofType": { "kind": "SCALAR", "name": "Upload" } } }
                  ]
                },
                { "kind": "SCALAR", "name": "String" },
                { "kind": "SCALAR", "name": "Upload" }
              ]
            }
            """);
        Map<String, Object> mutation = GraphQLHunterCore.getRootFields(schema, "mutationType").getFirst();

        List<GraphQLHunterCore.UploadTarget> targets = GraphQLHunterCore.findUploadTargets(schema, mutation);

        assertEquals(1, targets.size());
        assertEquals("variables.input.file", targets.getFirst().variablePath);
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

    private static final class HeaderCaptureTransport implements GraphQLHunterCore.GraphQLTransport
    {
        private Map<String, String> lastHeaders = new LinkedHashMap<>();

        @Override
        public GraphQLHunterCore.GraphQLResponse postJson(String url, Map<String, String> headers, Object body)
        {
            lastHeaders = new LinkedHashMap<>(headers);
            GraphQLHunterCore.GraphQLResponse response = new GraphQLHunterCore.GraphQLResponse();
            response.statusCode = 200;
            response.json = Map.of("data", Map.of("__typename", "Query"));
            response.body = GraphQLHunterJson.write(response.json);
            response.headers = new LinkedHashMap<>();
            response.elapsedMillis = 5L;
            return response;
        }
    }

    private static final class MultipartCaptureTransport implements GraphQLHunterCore.SessionAwareTransport
    {
        private Map<String, String> lastHeaders = new LinkedHashMap<>();
        private String lastBody = "";

        @Override
        public GraphQLHunterCore.GraphQLResponse postJson(String url, Map<String, String> headers, Object body)
        {
            throw new AssertionError("Multipart upload path should use executeHttp, not postJson");
        }

        @Override
        public GraphQLHunterCore.GraphQLResponse executeHttp(String method, String url, Map<String, String> headers, Object jsonBody, Map<String, String> formBody, String dataBody)
        {
            lastHeaders = new LinkedHashMap<>(headers);
            lastBody = dataBody;
            GraphQLHunterCore.GraphQLResponse response = new GraphQLHunterCore.GraphQLResponse();
            response.statusCode = 200;
            response.json = Map.of("data", Map.of("upload", Map.of("ok", true)));
            response.body = GraphQLHunterJson.write(response.json);
            response.headers = new LinkedHashMap<>();
            response.elapsedMillis = 5L;
            return response;
        }

        @Override
        public String getCookie(String name)
        {
            return null;
        }
    }
}
