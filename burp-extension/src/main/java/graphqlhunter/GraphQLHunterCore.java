package graphqlhunter;

import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

public final class GraphQLHunterCore
{
    public static final String INTROSPECTION_QUERY = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
          }
        }

        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            args {
              name
              type {
                ...TypeRef
              }
            }
            type {
              ...TypeRef
            }
          }
          inputFields {
            name
            type {
              ...TypeRef
            }
          }
          enumValues(includeDeprecated: true) {
            name
          }
        }

        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                }
              }
            }
          }
        }
        """;

    private static final Set<String> STRIPPED_TRANSPORT_HEADERS = Set.of(
        "host",
        "content-length",
        "connection",
        "accept-encoding"
    );

    private static final Set<String> AUTH_HEADERS = Set.of(
        "authorization",
        "cookie",
        "token",
        "x-api-key",
        "x-auth-token",
        "proxy-authorization"
    );

    private GraphQLHunterCore()
    {
    }

    public interface GraphQLTransport
    {
        GraphQLResponse postJson(String url, Map<String, String> headers, Object body) throws IOException, InterruptedException;
    }

    public static final class JavaHttpTransport implements GraphQLTransport
    {
        private final HttpClient httpClient = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NORMAL)
            .connectTimeout(Duration.ofSeconds(20))
            .build();

        @Override
        public GraphQLResponse postJson(String url, Map<String, String> headers, Object body) throws IOException, InterruptedException
        {
            String payload = GraphQLHunterJson.mapper().writeValueAsString(body);
            HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .POST(HttpRequest.BodyPublishers.ofString(payload));

            boolean contentTypeSet = false;
            for (Map.Entry<String, String> entry : headers.entrySet())
            {
                if (entry.getKey() == null || entry.getValue() == null)
                {
                    continue;
                }
                String headerName = entry.getKey().trim();
                if (headerName.isBlank() || STRIPPED_TRANSPORT_HEADERS.contains(headerName.toLowerCase(Locale.ROOT)))
                {
                    continue;
                }
                if ("content-type".equalsIgnoreCase(headerName))
                {
                    contentTypeSet = true;
                }
                builder.header(headerName, entry.getValue());
            }
            if (!contentTypeSet)
            {
                builder.header("Content-Type", "application/json");
            }

            long started = System.nanoTime();
            HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            long elapsedMillis = Duration.ofNanos(System.nanoTime() - started).toMillis();
            return GraphQLResponse.from(response.statusCode(), response.headers(), response.body(), elapsedMillis);
        }
    }

    public static final class GraphQLResponse
    {
        public int statusCode;
        public String body = "";
        public Object json;
        public Map<String, List<String>> headers = new LinkedHashMap<>();
        public long elapsedMillis;

        public static GraphQLResponse from(int statusCode, HttpHeaders headers, String body, long elapsedMillis)
        {
            GraphQLResponse response = new GraphQLResponse();
            response.statusCode = statusCode;
            response.body = body == null ? "" : body;
            response.headers = new LinkedHashMap<>(headers.map());
            response.elapsedMillis = elapsedMillis;
            try
            {
                JsonNode node = GraphQLHunterJson.mapper().readTree(response.body);
                response.json = GraphQLHunterJson.mapper().convertValue(node, Object.class);
            }
            catch (Exception ignored)
            {
                response.json = null;
            }
            return response;
        }

        @SuppressWarnings("unchecked")
        public Map<String, Object> bodyMap()
        {
            if (json instanceof Map<?, ?> map)
            {
                return (Map<String, Object>) map;
            }
            return new LinkedHashMap<>();
        }

        public String errorsText()
        {
            Object errors = bodyMap().get("errors");
            return errors == null ? "" : String.valueOf(errors);
        }

        public boolean hasData()
        {
            Object data = bodyMap().get("data");
            return data instanceof Map<?, ?> || data instanceof List<?>;
        }

        public String headerValue(String name)
        {
            List<String> values = headers.getOrDefault(name, headers.getOrDefault(name.toLowerCase(Locale.ROOT), List.of()));
            return values.isEmpty() ? "" : values.get(0);
        }
    }

    public static final class GraphQLClient
    {
        private final String url;
        private final Map<String, String> headers;
        private final GraphQLTransport transport;
        private final GraphQLHunterLogger logger;
        private Map<String, Object> cachedSchema;

        public GraphQLClient(String url, Map<String, String> headers, GraphQLTransport transport, GraphQLHunterLogger logger)
        {
            this.url = Objects.requireNonNull(url, "url");
            this.headers = new LinkedHashMap<>(headers);
            this.transport = transport;
            this.logger = logger;
        }

        public GraphQLClient withoutAuth()
        {
            Map<String, String> cloned = new LinkedHashMap<>();
            headers.forEach((key, value) ->
            {
                if (!AUTH_HEADERS.contains(key.toLowerCase(Locale.ROOT)))
                {
                    cloned.put(key, value);
                }
            });
            return new GraphQLClient(url, cloned, transport, logger);
        }

        public GraphQLResponse query(String query, Object variables, String operationName)
        {
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("query", query);
            if (variables != null)
            {
                payload.put("variables", variables);
            }
            if (operationName != null && !operationName.isBlank())
            {
                payload.put("operationName", operationName);
            }
            try
            {
                return transport.postJson(url, headers, payload);
            }
            catch (Exception exception)
            {
                if (logger != null)
                {
                    logger.error("GraphQL request failed for " + url, exception);
                }
                GraphQLResponse response = new GraphQLResponse();
                response.statusCode = 0;
                response.body = exception.getMessage();
                return response;
            }
        }

        public GraphQLResponse batchQuery(List<Map<String, Object>> payload)
        {
            try
            {
                return transport.postJson(url, headers, payload);
            }
            catch (Exception exception)
            {
                if (logger != null)
                {
                    logger.error("GraphQL batch request failed for " + url, exception);
                }
                GraphQLResponse response = new GraphQLResponse();
                response.statusCode = 0;
                response.body = exception.getMessage();
                return response;
            }
        }

        public Map<String, Object> introspect()
        {
            if (cachedSchema != null)
            {
                return cachedSchema;
            }

            GraphQLResponse response = query(INTROSPECTION_QUERY, null, "IntrospectionQuery");
            Object data = response.bodyMap().get("data");
            if (data instanceof Map<?, ?> map)
            {
                Object schema = ((Map<?, ?>) map).get("__schema");
                if (schema instanceof Map<?, ?> typedSchema)
                {
                    cachedSchema = castMap(typedSchema);
                }
            }
            return cachedSchema;
        }

        public String url()
        {
            return url;
        }

        public Map<String, String> headers()
        {
            return new LinkedHashMap<>(headers);
        }
    }

    public static Optional<GraphQLHunterModels.ScanRequest> parseRequest(
        String source,
        String url,
        String method,
        Map<String, String> headers,
        String body
    )
    {
        GraphQLHunterModels.ScanRequest request = new GraphQLHunterModels.ScanRequest();
        request.source = source == null ? "manual" : source;
        request.url = url == null ? "" : url;
        request.method = method == null || method.isBlank() ? "POST" : method;
        request.headers = new LinkedHashMap<>(headers);
        request.rawBody = body == null ? "" : body;

        String contentType = headers.entrySet().stream()
            .filter(entry -> "content-type".equalsIgnoreCase(entry.getKey()))
            .map(Map.Entry::getValue)
            .findFirst()
            .orElse("");

        if (contentType.toLowerCase(Locale.ROOT).contains("application/graphql") && body != null && !body.isBlank())
        {
            request.query = body;
            return Optional.of(request);
        }

        if (body == null || body.isBlank())
        {
            return Optional.empty();
        }

        try
        {
            JsonNode node = GraphQLHunterJson.mapper().readTree(body);
            if (node.isObject() && node.has("query"))
            {
                request.query = node.path("query").asText("");
                request.operationName = node.path("operationName").asText("");
                if (node.has("variables") && !node.get("variables").isNull())
                {
                    request.variables = GraphQLHunterJson.mapper().convertValue(node.get("variables"), Object.class);
                }
                return request.query.isBlank() ? Optional.empty() : Optional.of(request);
            }

            if (node.isArray() && node.size() > 0 && node.get(0).isObject() && node.get(0).has("query"))
            {
                request.batch = true;
                request.query = node.get(0).path("query").asText("");
                request.operationName = node.get(0).path("operationName").asText("");
                if (node.get(0).has("variables") && !node.get(0).get("variables").isNull())
                {
                    request.variables = GraphQLHunterJson.mapper().convertValue(node.get(0).get("variables"), Object.class);
                }
                return Optional.of(request);
            }
        }
        catch (Exception ignored)
        {
            // Not JSON; fall through.
        }

        return Optional.empty();
    }

    public static Operation buildOperation(Map<String, Object> schema, Map<String, Object> field, String operationKind, Map<String, Object> overrides)
    {
        List<Map<String, Object>> args = asList(field.get("args"));
        LinkedHashMap<String, Object> variables = new LinkedHashMap<>();
        List<String> variableDefinitions = new ArrayList<>();
        List<String> argumentUses = new ArrayList<>();

        for (Map<String, Object> arg : args)
        {
            String argName = String.valueOf(arg.getOrDefault("name", ""));
            Map<String, Object> argType = asMap(arg.get("type"));
            Object value = overrides != null && overrides.containsKey(argName)
                ? overrides.get(argName)
                : defaultValueForType(schema, argType, 2, new LinkedHashSet<>());
            if (value == null)
            {
                return Operation.untestable("Unable to generate default value for argument '" + argName + "'");
            }
            variables.put(argName, value);
            variableDefinitions.add("$" + argName + ": " + typeSignature(argType));
            argumentUses.add(argName + ": $" + argName);
        }

        String fieldName = String.valueOf(field.getOrDefault("name", "Operation"));
        String operationName = "Auto" + Character.toUpperCase(operationKind.charAt(0)) + operationKind.substring(1) + Character.toUpperCase(fieldName.charAt(0)) + fieldName.substring(1);
        String variablePart = variableDefinitions.isEmpty() ? "" : "(" + String.join(", ", variableDefinitions) + ")";
        String argumentPart = argumentUses.isEmpty() ? "" : "(" + String.join(", ", argumentUses) + ")";
        String selection = minimalSelectionSet(schema, asMap(field.get("type")), 2, new LinkedHashSet<>());
        String selectionPart = selection.isBlank() ? "" : " " + selection;
        String query = operationKind + " " + operationName + variablePart + " { " + fieldName + argumentPart + selectionPart + " }";
        return Operation.testable(query, variables, operationName);
    }

    public static List<Map<String, Object>> getRootFields(Map<String, Object> schema, String rootTypeKey)
    {
        Map<String, Object> root = asMap(schema.get(rootTypeKey));
        String rootName = String.valueOf(root.getOrDefault("name", ""));
        if (rootName.isBlank())
        {
            return List.of();
        }
        for (Map<String, Object> type : asList(schema.get("types")))
        {
            if (rootName.equals(String.valueOf(type.get("name"))))
            {
                return asList(type.get("fields"));
            }
        }
        return List.of();
    }

    public static String extractTypeName(Map<String, Object> typeDef)
    {
        if (typeDef == null || typeDef.isEmpty())
        {
            return "Unknown";
        }
        Object name = typeDef.get("name");
        if (name instanceof String typedName && !typedName.isBlank())
        {
            return typedName;
        }
        return extractTypeName(asMap(typeDef.get("ofType")));
    }

    public static String typeSignature(Map<String, Object> typeDef)
    {
        if (typeDef == null || typeDef.isEmpty())
        {
            return "String";
        }
        String kind = String.valueOf(typeDef.getOrDefault("kind", ""));
        if ("NON_NULL".equals(kind))
        {
            return typeSignature(asMap(typeDef.get("ofType"))) + "!";
        }
        if ("LIST".equals(kind))
        {
            return "[" + typeSignature(asMap(typeDef.get("ofType"))) + "]";
        }
        String name = String.valueOf(typeDef.getOrDefault("name", ""));
        return name.isBlank() ? "String" : name;
    }

    public static Object defaultValueForType(Map<String, Object> schema, Map<String, Object> typeDef, int depth, Set<String> visited)
    {
        if (typeDef == null || typeDef.isEmpty())
        {
            return "test";
        }

        String kind = String.valueOf(typeDef.getOrDefault("kind", ""));
        if ("NON_NULL".equals(kind))
        {
            return defaultValueForType(schema, asMap(typeDef.get("ofType")), depth, visited);
        }
        if ("LIST".equals(kind))
        {
            Object item = defaultValueForType(schema, asMap(typeDef.get("ofType")), depth - 1, visited);
            return item == null ? null : List.of(item);
        }

        String typeName = extractTypeName(typeDef);
        return switch (typeName)
        {
            case "String", "ID" -> "test";
            case "Int" -> 1;
            case "Float" -> 1.0;
            case "Boolean" -> Boolean.TRUE;
            default -> defaultComplexValue(schema, typeName, depth, visited);
        };
    }

    private static Object defaultComplexValue(Map<String, Object> schema, String typeName, int depth, Set<String> visited)
    {
        Map<String, Object> resolvedType = findType(schema, typeName);
        if (resolvedType.isEmpty())
        {
            return null;
        }
        if ("ENUM".equals(String.valueOf(resolvedType.get("kind"))))
        {
            List<Map<String, Object>> enumValues = asList(resolvedType.get("enumValues"));
            return enumValues.isEmpty() ? null : String.valueOf(enumValues.get(0).get("name"));
        }
        if (!"INPUT_OBJECT".equals(String.valueOf(resolvedType.get("kind"))) || depth <= 0 || visited.contains(typeName))
        {
            return null;
        }

        visited.add(typeName);
        LinkedHashMap<String, Object> values = new LinkedHashMap<>();
        for (Map<String, Object> inputField : asList(resolvedType.get("inputFields")))
        {
            Object value = defaultValueForType(schema, asMap(inputField.get("type")), depth - 1, visited);
            if (value != null)
            {
                values.put(String.valueOf(inputField.get("name")), value);
            }
        }
        visited.remove(typeName);
        return values.isEmpty() ? null : values;
    }

    public static String minimalSelectionSet(Map<String, Object> schema, Map<String, Object> typeDef, int depth, Set<String> visited)
    {
        String typeName = extractTypeName(typeDef);
        if (Set.of("String", "ID", "Int", "Float", "Boolean").contains(typeName))
        {
            return "";
        }

        Map<String, Object> resolvedType = findType(schema, typeName);
        if (resolvedType.isEmpty() || depth <= 0 || visited.contains(typeName))
        {
            return "{ __typename }";
        }
        if (!"OBJECT".equals(String.valueOf(resolvedType.get("kind"))))
        {
            return "";
        }

        visited.add(typeName);
        List<String> selections = new ArrayList<>();
        for (String preferred : List.of("id", "uid", "name", "title", "email", "message", "success"))
        {
            for (Map<String, Object> field : asList(resolvedType.get("fields")))
            {
                if (!preferred.equals(String.valueOf(field.get("name"))) || !asList(field.get("args")).isEmpty())
                {
                    continue;
                }
                String nested = minimalSelectionSet(schema, asMap(field.get("type")), depth - 1, visited);
                selections.add(nested.isBlank() ? preferred : preferred + " " + nested);
                if (selections.size() >= 3)
                {
                    break;
                }
            }
            if (selections.size() >= 3)
            {
                break;
            }
        }

        if (selections.isEmpty())
        {
            for (Map<String, Object> field : asList(resolvedType.get("fields")))
            {
                if (!asList(field.get("args")).isEmpty())
                {
                    continue;
                }
                String fieldName = String.valueOf(field.get("name"));
                String nested = minimalSelectionSet(schema, asMap(field.get("type")), depth - 1, visited);
                selections.add(nested.isBlank() ? fieldName : fieldName + " " + nested);
                if (selections.size() >= 3)
                {
                    break;
                }
            }
        }

        visited.remove(typeName);
        return selections.isEmpty() ? "{ __typename }" : "{ " + String.join(" ", selections) + " }";
    }

    private static Map<String, Object> findType(Map<String, Object> schema, String typeName)
    {
        for (Map<String, Object> type : asList(schema.get("types")))
        {
            if (typeName.equals(String.valueOf(type.get("name"))))
            {
                return type;
            }
        }
        return Map.of();
    }

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> asList(Object value)
    {
        if (value instanceof List<?> list)
        {
            List<Map<String, Object>> converted = new ArrayList<>();
            for (Object item : list)
            {
                if (item instanceof Map<?, ?> map)
                {
                    converted.add((Map<String, Object>) map);
                }
            }
            return converted;
        }
        return List.of();
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> asMap(Object value)
    {
        if (value instanceof Map<?, ?> map)
        {
            return (Map<String, Object>) map;
        }
        return Map.of();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMap(Map<?, ?> value)
    {
        return (Map<String, Object>) value;
    }

    public static final class Operation
    {
        public final boolean testable;
        public final String query;
        public final Map<String, Object> variables;
        public final String operationName;
        public final String skipReason;

        private Operation(boolean testable, String query, Map<String, Object> variables, String operationName, String skipReason)
        {
            this.testable = testable;
            this.query = query;
            this.variables = variables;
            this.operationName = operationName;
            this.skipReason = skipReason;
        }

        public static Operation testable(String query, Map<String, Object> variables, String operationName)
        {
            return new Operation(true, query, variables, operationName, "");
        }

        public static Operation untestable(String skipReason)
        {
            return new Operation(false, "", Map.of(), "", skipReason);
        }
    }
}
