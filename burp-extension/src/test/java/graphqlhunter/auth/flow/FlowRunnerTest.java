package graphqlhunter.auth.flow;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FlowRunnerTest
{
    @Test
    void rendersTemplatesRecursively()
    {
        @SuppressWarnings("unchecked")
        Map<String, Object> rendered = (Map<String, Object>) TemplateRenderer.render(
            Map.of("a", "{{x}}", "b", List.of(Map.of("c", "hi {{y}}"))),
            Map.of("x", "1", "y", "there")
        );

        assertEquals("1", rendered.get("a"));
        assertEquals("hi there", ((Map<?, ?>) ((List<?>) rendered.get("b")).get(0)).get("c"));
    }

    @Test
    void extractsJsonPathWithIndexes()
    {
        Object extracted = JsonPathExtractor.extract(
            Map.of("data", Map.of("tokens", List.of(Map.of("access_token", "a1")))),
            "data.tokens[0].access_token"
        );

        assertEquals("a1", extracted);
    }

    @Test
    void runsHttpAndGraphqlStepsAndExtractors()
    {
        FlowRunner runner = new FlowRunner();
        FakeFlowClient client = new FakeFlowClient();
        Map<String, String> variables = new LinkedHashMap<>();

        runner.run(
            client,
            List.of(
                Map.of(
                    "type", "http",
                    "method", "GET",
                    "url", "https://example.local/csrf",
                    "extract", List.of(Map.of("var", "csrf_token", "from", "header", "name", "X-CSRF-Token"))
                ),
                Map.of(
                    "type", "graphql",
                    "query", "mutation { login { accessToken } }",
                    "extract", List.of(Map.of("var", "access_token", "from", "json", "path", "data.login.accessToken"))
                ),
                Map.of(
                    "type", "http",
                    "method", "GET",
                    "url", "https://example.local/cookie",
                    "extract", List.of(Map.of("var", "sid", "from", "cookie", "name", "sessionid"))
                )
            ),
            variables
        );

        assertEquals("csrf123", variables.get("csrf_token"));
        assertEquals("tok123", variables.get("access_token"));
        assertEquals("s123", variables.get("sid"));
        assertTrue(client.bypassAuthSeen);
    }

    private static final class FakeFlowClient implements FlowRunner.FlowClient
    {
        private boolean bypassAuthSeen;

        @Override
        public FlowStepResult executeHttp(String method, String url, Map<String, String> headers, Object jsonBody, Map<String, String> formBody, String dataBody)
        {
            return new FlowStepResult(200, Map.of("x-csrf-token", "csrf123"), "{\"ok\":true}", Map.of("ok", true));
        }

        @Override
        public FlowStepResult executeGraphQl(String query, Object variables, String operationName, Map<String, String> headers, boolean bypassAuth)
        {
            bypassAuthSeen = bypassAuth;
            return new FlowStepResult(200, Map.of("h", "v"), "{\"data\":{\"login\":{\"accessToken\":\"tok123\"}}}", Map.of("data", Map.of("login", Map.of("accessToken", "tok123"))));
        }

        @Override
        public String getCookie(String name)
        {
            return "sessionid".equals(name) ? "s123" : null;
        }
    }
}
