package graphqlhunter.importer;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RequestImporterTest
{
    @Test
    void parsesCurlCommand()
    {
        ImportedRequest request = RequestImporter.fromCurlCommand(
            "curl -X POST https://api.example.com/graphql -H 'Authorization: Bearer TOKEN' -d '{\"query\":\"mutation MyOp { ping }\",\"variables\":{\"x\":1}}'"
        );

        assertEquals("https://api.example.com/graphql", request.url);
        assertEquals("POST", request.method);
        assertEquals("mutation MyOp { ping }", request.query);
        assertEquals("MyOp", request.operationName);
        assertEquals("Bearer TOKEN", request.headers.get("Authorization"));
    }

    @Test
    void extractsRequestsFromPostmanCollection()
    {
        List<ImportedRequest> requests = RequestImporter.fromPostmanCollectionContent("""
            {
              "info": { "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
              "item": [
                {
                  "name": "Folder A",
                  "item": [
                    {
                      "name": "Lookup",
                      "request": {
                        "method": "POST",
                        "url": {
                          "protocol": "https",
                          "host": ["api","example","com"],
                          "path": ["graphql"]
                        },
                        "header": [
                          { "key": "Authorization", "value": "Bearer X" }
                        ],
                        "body": {
                          "mode": "raw",
                          "raw": "{\\\"query\\\":\\\"query Viewer { viewer { id } }\\\"}"
                        }
                      }
                    }
                  ]
                }
              ]
            }
            """);

        assertEquals(1, requests.size());
        assertEquals("Lookup", requests.getFirst().name);
        assertEquals("Folder A", requests.getFirst().folder);
        assertEquals("https://api.example.com/graphql", requests.getFirst().url);
    }

    @Test
    void autoDetectsTextCurlFormat()
    {
        List<ImportedRequest> requests = RequestImporter.autoDetect(
            "request.txt",
            "curl -X POST https://api.example.com/graphql -d '{\"query\":\"{ __typename }\"}'"
        );

        assertEquals(1, requests.size());
        assertTrue(requests.getFirst().query.contains("__typename"));
    }

    @Test
    void autoDetectsJsonRequestContentWithoutJsonExtension()
    {
        List<ImportedRequest> requests = RequestImporter.autoDetect(
            "request.txt",
            """
            {
              "url": "https://api.example.com/graphql",
              "method": "POST",
              "query": "query Viewer { viewer { id } }",
              "operationName": "Viewer"
            }
            """
        );

        assertEquals(1, requests.size());
        assertEquals("Viewer", requests.getFirst().operationName);
        assertEquals("https://api.example.com/graphql", requests.getFirst().url);
    }

    @Test
    void autoDetectsPostmanCollectionWithoutJsonExtension()
    {
        List<ImportedRequest> requests = RequestImporter.autoDetect(
            "request.txt",
            """
            {
              "info": { "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
              "item": [
                {
                  "name": "Lookup",
                  "request": {
                    "method": "POST",
                    "url": {
                      "protocol": "https",
                      "host": ["api","example","com"],
                      "path": ["graphql"]
                    },
                    "body": {
                      "mode": "raw",
                      "raw": "{\\"query\\":\\"query Viewer { viewer { id } }\\"}"
                    }
                  }
                }
              ]
            }
            """
        );

        assertEquals(1, requests.size());
        assertEquals("Lookup", requests.getFirst().name);
    }

    @Test
    void parsesRawHttpRequest()
    {
        ImportedRequest request = RequestImporter.fromRawHttp("""
            POST /graphql HTTP/1.1
            Host: api.example.com
            Content-Type: application/json

            {"query":"query Viewer { viewer { id } }","variables":{"id":"1"}}
            """);

        assertEquals("http://api.example.com/graphql", request.url);
        assertEquals("POST", request.method);
        assertEquals("query Viewer { viewer { id } }", request.query);
    }
}
