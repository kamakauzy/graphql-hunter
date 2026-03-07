package graphqlhunter;

import graphqlhunter.GraphQLHunterCore.Operation;
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
}
