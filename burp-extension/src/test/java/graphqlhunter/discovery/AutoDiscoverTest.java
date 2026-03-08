package graphqlhunter.discovery;

import graphqlhunter.importer.RequestImporter;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AutoDiscoverTest
{
    @Test
    void preservesAuthorizationHeader()
    {
        DiscoveryResult result = new AutoDiscover().analyzeNotes(
            "Authorization: Bearer abc.def.ghi\nurl: https://api.example.com/graphql"
        );

        assertEquals("Bearer abc.def.ghi", result.headers.get("Authorization"));
    }

    @Test
    void extractsDistinctUidKeys()
    {
        DiscoveryResult result = new AutoDiscover().analyzeNotes("""
            pdtUid: PDT123
            patientUid: PAT456
            careteamsUid: CARE789
            """);

        assertEquals("PDT123", result.credentials.get("pdt_uid"));
        assertEquals("PAT456", result.credentials.get("patient_uid"));
        assertEquals("CARE789", result.credentials.get("careteams_uid"));
    }

    @Test
    void analyzesImportedRequests()
    {
        DiscoveryResult result = new AutoDiscover().analyzeRequestCollection(
            RequestImporter.fromPostmanCollectionContent("""
                {
                  "info": { "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
                  "item": [
                    {
                      "name": "ViewerRequest",
                      "request": {
                        "method": "POST",
                        "url": {
                          "protocol": "https",
                          "host": ["api", "example", "com"],
                          "path": ["graphql"]
                        },
                        "header": [{ "key": "Authorization", "value": "Bearer TOKEN123" }],
                        "body": {
                          "mode": "raw",
                          "raw": "{\\\"query\\\":\\\"{ __typename }\\\"}"
                        }
                      }
                    }
                  ]
                }
                """)
        );

        assertEquals("https://api.example.com/graphql", result.url);
        assertEquals("Bearer TOKEN123", result.headers.get("Authorization"));
        assertEquals(1, result.queries.size());
    }

    @Test
    void generatedRecommendationPrefersTokenAuthProfile()
    {
        DiscoveryResult result = new AutoDiscover().analyzeNotes("""
            email: user@example.com
            password: PASSWORD123
            url: https://api.example.com/graphql
            """);

        assertEquals("token_auth", result.recommendations.get("auth_profile"));
        assertTrue(((List<?>) result.recommendations.get("auth_vars")).toString().contains("email=user@example.com"));
    }

    @Test
    void tokenOnlyDiscoveryGeneratesAuthorizationHeaderRecommendation()
    {
        DiscoveryResult result = new AutoDiscover().analyzeNotes("""
            url: https://api.example.com/graphql
            eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature
            """);

        assertTrue(((List<?>) result.recommendations.get("headers")).toString().contains("Authorization: Bearer"));
    }
}
