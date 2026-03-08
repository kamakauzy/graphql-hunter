package graphqlhunter;

import com.fasterxml.jackson.databind.JsonNode;
import graphqlhunter.auth.AuthManager;
import graphqlhunter.auth.AuthProvider;
import graphqlhunter.auth.flow.FlowRunner;

import java.io.IOException;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.HttpCookie;
import java.net.URI;
import java.net.URLEncoder;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
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
import java.util.UUID;
import java.util.stream.Collectors;

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

    public interface SessionAwareTransport extends GraphQLTransport
    {
        GraphQLResponse executeHttp(
            String method,
            String url,
            Map<String, String> headers,
            Object jsonBody,
            Map<String, String> formBody,
            String dataBody
        ) throws IOException, InterruptedException;

        String getCookie(String name);

        default SessionAwareTransport freshSession()
        {
            return this;
        }
    }

    public static final class JavaHttpTransport implements SessionAwareTransport
    {
        private final CookieManager cookieManager = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        private final HttpClient httpClient = HttpClient.newBuilder()
            .cookieHandler(cookieManager)
            .followRedirects(HttpClient.Redirect.NORMAL)
            .connectTimeout(Duration.ofSeconds(20))
            .build();
        private final int timeoutSeconds;
        private final double delaySeconds;

        public JavaHttpTransport()
        {
            this(30, 0.0);
        }

        public JavaHttpTransport(int timeoutSeconds, double delaySeconds)
        {
            this.timeoutSeconds = timeoutSeconds;
            this.delaySeconds = delaySeconds;
        }

        @Override
        public GraphQLResponse postJson(String url, Map<String, String> headers, Object body) throws IOException, InterruptedException
        {
            return executeHttp("POST", url, headers, body, null, null);
        }

        @Override
        public GraphQLResponse executeHttp(
            String method,
            String url,
            Map<String, String> headers,
            Object jsonBody,
            Map<String, String> formBody,
            String dataBody
        ) throws IOException, InterruptedException
        {
            if (delaySeconds > 0)
            {
                Thread.sleep(Math.round(delaySeconds * 1000));
            }

            HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(timeoutSeconds <= 0 ? 30 : timeoutSeconds));

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

            String verb = method == null || method.isBlank() ? "POST" : method.toUpperCase(Locale.ROOT);
            if (jsonBody != null)
            {
                if (!contentTypeSet)
                {
                    builder.header("Content-Type", "application/json");
                }
                builder.method(verb, HttpRequest.BodyPublishers.ofString(GraphQLHunterJson.mapper().writeValueAsString(jsonBody)));
            }
            else if (formBody != null && !formBody.isEmpty())
            {
                if (!contentTypeSet)
                {
                    builder.header("Content-Type", "application/x-www-form-urlencoded");
                }
                String encoded = formBody.entrySet().stream()
                    .map(entry -> URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8) + "=" + URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8))
                    .collect(Collectors.joining("&"));
                builder.method(verb, HttpRequest.BodyPublishers.ofString(encoded));
            }
            else if (dataBody != null)
            {
                builder.method(verb, HttpRequest.BodyPublishers.ofString(dataBody));
            }
            else
            {
                builder.method(verb, HttpRequest.BodyPublishers.noBody());
            }

            long started = System.nanoTime();
            HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            long elapsedMillis = Duration.ofNanos(System.nanoTime() - started).toMillis();
            return GraphQLResponse.from(response.statusCode(), response.headers(), response.body(), elapsedMillis);
        }

        @Override
        public String getCookie(String name)
        {
            if (name == null || name.isBlank())
            {
                return null;
            }
            for (HttpCookie cookie : cookieManager.getCookieStore().getCookies())
            {
                if (cookie.getName().equals(name))
                {
                    return cookie.getValue();
                }
            }
            return null;
        }

        @Override
        public SessionAwareTransport freshSession()
        {
            return new JavaHttpTransport(timeoutSeconds, delaySeconds);
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

    public static final class AuthValidationResult
    {
        public boolean authWorking;
        public boolean authRequired;
        public int statusWithAuth;
        public int statusWithoutAuth;
        public GraphQLResponse responseWithAuth;
        public GraphQLResponse responseWithoutAuth;
        public String analysis = "";
    }

    public record UploadPart(String filename, byte[] content, String contentType)
    {
        public UploadPart
        {
            filename = filename == null || filename.isBlank() ? "upload.bin" : filename;
            content = content == null ? new byte[0] : content;
            contentType = contentType == null || contentType.isBlank() ? "application/octet-stream" : contentType;
        }
    }

    public static final class UploadTarget
    {
        public String variablePath = "";
        public String argName = "";
        public String typeName = "Upload";
        public boolean list;
    }

    public static final class GraphQLClient
    {
        private final String url;
        private final Map<String, String> headers;
        private final GraphQLTransport transport;
        private final GraphQLHunterLogger logger;
        private final AuthManager authManager;
        private Map<String, Object> cachedSchema;

        public GraphQLClient(String url, Map<String, String> headers, GraphQLTransport transport, GraphQLHunterLogger logger)
        {
            this(url, headers, transport, logger, null);
        }

        public GraphQLClient(String url, Map<String, String> headers, GraphQLTransport transport, GraphQLHunterLogger logger, AuthManager authManager)
        {
            this.url = Objects.requireNonNull(url, "url");
            this.headers = new LinkedHashMap<>(headers);
            this.transport = transport;
            this.logger = logger;
            this.authManager = authManager;
        }

        public GraphQLClient withoutAuth()
        {
            Map<String, String> cloned = new LinkedHashMap<>();
            headers.forEach((key, value) ->
            {
                if (key != null && ("content-type".equalsIgnoreCase(key) || "accept".equalsIgnoreCase(key)))
                {
                    cloned.put(key, value);
                }
            });
            GraphQLTransport anonymousTransport = transport;
            if (transport instanceof SessionAwareTransport sessionAwareTransport)
            {
                anonymousTransport = sessionAwareTransport.freshSession();
            }
            return new GraphQLClient(url, cloned, anonymousTransport, logger, null);
        }

        public GraphQLResponse query(String query, Object variables, String operationName)
        {
            return query(query, variables, operationName, Map.of(), false, Set.of(), Map.of());
        }

        public GraphQLResponse query(String query, Object variables, String operationName, Map<String, String> extraHeaders, boolean bypassAuth)
        {
            return query(query, variables, operationName, extraHeaders, bypassAuth, Set.of(), Map.of());
        }

        public GraphQLResponse query(
            String query,
            Object variables,
            String operationName,
            Map<String, String> extraHeaders,
            boolean bypassAuth,
            Set<String> suppressedHeaders
        )
        {
            return query(query, variables, operationName, extraHeaders, bypassAuth, suppressedHeaders, Map.of());
        }

        public GraphQLResponse query(
            String query,
            Object variables,
            String operationName,
            Map<String, String> extraHeaders,
            boolean bypassAuth,
            Set<String> suppressedHeaders,
            Map<String, UploadPart> uploads
        )
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
                if (authManager != null && !bypassAuth)
                {
                    authManager.ensurePrepared(this);
                }
                GraphQLResponse response;
                if (uploads != null && !uploads.isEmpty())
                {
                    response = executeMultipart(payload, extraHeaders, bypassAuth, suppressedHeaders, uploads);
                }
                else
                {
                    response = transport.postJson(url, mergedHeaders(extraHeaders, bypassAuth, suppressedHeaders), payload);
                }
                if (authManager != null && !bypassAuth && authManager.maybeRefreshAndRetry(this, response))
                {
                    if (uploads != null && !uploads.isEmpty())
                    {
                        response = executeMultipart(payload, extraHeaders, bypassAuth, suppressedHeaders, uploads);
                    }
                    else
                    {
                        response = transport.postJson(url, mergedHeaders(extraHeaders, bypassAuth, suppressedHeaders), payload);
                    }
                }
                return response;
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

        private GraphQLResponse executeMultipart(
            Map<String, Object> payload,
            Map<String, String> extraHeaders,
            boolean bypassAuth,
            Set<String> suppressedHeaders,
            Map<String, UploadPart> uploads
        ) throws IOException, InterruptedException
        {
            if (!(transport instanceof SessionAwareTransport sessionAwareTransport))
            {
                throw new IllegalStateException("Current GraphQL transport does not support multipart upload execution.");
            }
            MultipartRequest multipart = buildMultipartRequest(payload, uploads);
            LinkedHashMap<String, String> headers = new LinkedHashMap<>(mergedHeaders(extraHeaders, bypassAuth, suppressedHeaders));
            headers.entrySet().removeIf(entry -> "content-type".equalsIgnoreCase(entry.getKey()));
            headers.put("Content-Type", "multipart/form-data; boundary=" + multipart.boundary());
            return sessionAwareTransport.executeHttp("POST", url, headers, null, null, multipart.body());
        }

        public GraphQLResponse batchQuery(List<Map<String, Object>> payload)
        {
            try
            {
                if (authManager != null)
                {
                    authManager.ensurePrepared(this);
                }
                GraphQLResponse response = transport.postJson(url, mergedHeaders(Map.of(), false, Set.of()), payload);
                if (authManager != null && authManager.maybeRefreshAndRetry(this, response))
                {
                    response = transport.postJson(url, mergedHeaders(Map.of(), false, Set.of()), payload);
                }
                return response;
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

        public AuthValidationResult validateAuth(String query, Object variables)
        {
            String testQuery = query == null || query.isBlank() ? "{ __typename }" : query;
            GraphQLResponse withAuth = query(testQuery, variables, null);
            GraphQLResponse withoutAuth = withoutAuth().query(testQuery, variables, null);

            AuthValidationResult validation = new AuthValidationResult();
            validation.statusWithAuth = withAuth.statusCode;
            validation.statusWithoutAuth = withoutAuth.statusCode;
            validation.responseWithAuth = withAuth;
            validation.responseWithoutAuth = withoutAuth;

            String withErrors = withAuth.errorsText().toLowerCase(Locale.ROOT);
            String withoutErrors = withoutAuth.errorsText().toLowerCase(Locale.ROOT);
            boolean withAuthFailure = AuthProvider.looksLikeAuthFailure(validation.statusWithAuth, withErrors);
            boolean withoutAuthFailure = AuthProvider.looksLikeAuthFailure(validation.statusWithoutAuth, withoutErrors);

            if ((validation.statusWithoutAuth == 401 || validation.statusWithoutAuth == 403) && validation.statusWithAuth == 200)
            {
                validation.authWorking = true;
                validation.authRequired = true;
                validation.analysis = "Authentication is working: unauthenticated requests are rejected while authenticated requests succeed.";
                return validation;
            }

            if (withoutAuthFailure && !withAuthFailure)
            {
                validation.authWorking = true;
                validation.authRequired = true;
                validation.analysis = "Authentication appears to be working: unauthenticated requests show auth-specific failures.";
                return validation;
            }

            if (validation.statusWithAuth == validation.statusWithoutAuth && withErrors.equals(withoutErrors))
            {
                if (AuthProvider.looksLikePermissionFailure(withErrors))
                {
                    validation.authWorking = true;
                    validation.authRequired = true;
                    validation.analysis = "Authentication appears to be working: permission errors indicate the server is checking authorization, but the token may still be invalid or not required for this path.";
                }
                else if (String.valueOf(withAuth.json).equals(String.valueOf(withoutAuth.json)))
                {
                    validation.authWorking = false;
                    validation.authRequired = false;
                    validation.analysis = "Authentication may not be required: responses matched with and without auth.";
                }
                else
                {
                    validation.authWorking = true;
                    validation.authRequired = true;
                    validation.analysis = "Authentication appears to be working: responses differ with and without auth despite matching status codes.";
                }
                return validation;
            }

            if (validation.statusWithAuth == 200 && validation.statusWithoutAuth == 200)
            {
                Object withData = withAuth.bodyMap().get("data");
                Object withoutData = withoutAuth.bodyMap().get("data");
                if (withData != null && withoutData != null)
                {
                    if (!String.valueOf(withData).equals(String.valueOf(withoutData)))
                    {
                        validation.authWorking = true;
                        validation.authRequired = true;
                        validation.analysis = "Authentication is working: different data was returned with versus without auth.";
                    }
                    else
                    {
                        validation.authWorking = false;
                        validation.authRequired = false;
                        validation.analysis = "Authentication may not be required: identical data was returned with and without auth.";
                    }
                    return validation;
                }
                if (withErrors.equals(withoutErrors))
                {
                    if (AuthProvider.looksLikePermissionFailure(withErrors))
                    {
                        validation.authWorking = true;
                        validation.authRequired = true;
                        validation.analysis = "Authentication appears to be working: matching permission errors indicate auth is being checked.";
                    }
                    else
                    {
                        validation.authWorking = false;
                        validation.authRequired = false;
                        validation.analysis = "Authentication may not be required: matching errors were returned with and without auth.";
                    }
                }
                else
                {
                    validation.authWorking = true;
                    validation.authRequired = true;
                    validation.analysis = "Authentication appears to be working: different error responses were returned with and without auth.";
                }
                return validation;
            }

            if (validation.statusWithAuth == 200 && validation.statusWithoutAuth != 200)
            {
                validation.authWorking = true;
                validation.authRequired = true;
                validation.analysis = "Authentication is working: authenticated request succeeded while unauthenticated request failed.";
                return validation;
            }

            validation.analysis = "Unable to determine auth status. Review the response details manually.";
            return validation;
        }

        public FlowRunner.FlowClient flowClient()
        {
            return new FlowRunner.FlowClient()
            {
                @Override
                public graphqlhunter.auth.flow.FlowStepResult executeHttp(
                    String method,
                    String stepUrl,
                    Map<String, String> stepHeaders,
                    Object jsonBody,
                    Map<String, String> formBody,
                    String dataBody
                )
                {
                    if (!(transport instanceof SessionAwareTransport sessionAwareTransport))
                    {
                        throw new IllegalStateException("Current GraphQL transport does not support generic HTTP flow steps.");
                    }
                    try
                    {
                        GraphQLResponse response = sessionAwareTransport.executeHttp(method, stepUrl, stepHeaders, jsonBody, formBody, dataBody);
                        return new graphqlhunter.auth.flow.FlowStepResult(
                            response.statusCode,
                            flattenHeaders(response.headers),
                            response.body,
                            response.json
                        );
                    }
                    catch (Exception exception)
                    {
                        throw new IllegalStateException("HTTP auth flow step failed", exception);
                    }
                }

                @Override
                public graphqlhunter.auth.flow.FlowStepResult executeGraphQl(
                    String query,
                    Object variables,
                    String operationName,
                    Map<String, String> stepHeaders,
                    boolean bypassAuth
                )
                {
                    GraphQLResponse response = GraphQLClient.this.query(query, variables, operationName, stepHeaders, bypassAuth);
                    return new graphqlhunter.auth.flow.FlowStepResult(
                        response.statusCode,
                        flattenHeaders(response.headers),
                        response.body,
                        response.json
                    );
                }

                @Override
                public String getCookie(String name)
                {
                    if (transport instanceof SessionAwareTransport sessionAwareTransport)
                    {
                        return sessionAwareTransport.getCookie(name);
                    }
                    return null;
                }
            };
        }

        private Map<String, String> flattenHeaders(Map<String, List<String>> headers)
        {
            LinkedHashMap<String, String> flattened = new LinkedHashMap<>();
            headers.forEach((key, values) -> flattened.put(key, values == null || values.isEmpty() ? "" : values.get(0)));
            return flattened;
        }

        private Map<String, String> mergedHeaders(Map<String, String> extraHeaders, boolean bypassAuth, Set<String> suppressedHeaders)
        {
            LinkedHashMap<String, String> merged = new LinkedHashMap<>(headers);
            if (authManager != null && !bypassAuth)
            {
                merged.putAll(authManager.requestHeaders());
            }
            if (extraHeaders != null)
            {
                merged.putAll(extraHeaders);
            }
            if (suppressedHeaders != null && !suppressedHeaders.isEmpty())
            {
                merged.entrySet().removeIf(entry -> suppressedHeaders.stream().anyMatch(name -> name.equalsIgnoreCase(entry.getKey())));
            }
            return merged;
        }

        private MultipartRequest buildMultipartRequest(Map<String, Object> payload, Map<String, UploadPart> uploads)
        {
            @SuppressWarnings("unchecked")
            Map<String, Object> operations = GraphQLHunterJson.mapper().convertValue(payload, Map.class);
            LinkedHashMap<String, List<String>> fileMap = new LinkedHashMap<>();
            LinkedHashMap<String, UploadPart> orderedUploads = new LinkedHashMap<>(uploads);
            int index = 0;
            for (Map.Entry<String, UploadPart> entry : orderedUploads.entrySet())
            {
                String key = String.valueOf(index++);
                setValueAtPath(operations, entry.getKey(), null);
                fileMap.put(key, List.of(entry.getKey()));
            }

            String boundary = "----GraphQLHunter" + UUID.randomUUID().toString().replace("-", "");
            StringBuilder body = new StringBuilder();
            appendMultipartPart(body, boundary, "operations", null, null, GraphQLHunterJson.write(operations));
            appendMultipartPart(body, boundary, "map", null, null, GraphQLHunterJson.write(fileMap));

            index = 0;
            for (UploadPart upload : orderedUploads.values())
            {
                appendMultipartPart(
                    body,
                    boundary,
                    String.valueOf(index++),
                    upload.filename(),
                    upload.contentType(),
                    new String(upload.content(), StandardCharsets.UTF_8)
                );
            }
            body.append("--").append(boundary).append("--\r\n");
            return new MultipartRequest(boundary, body.toString());
        }

        private void appendMultipartPart(
            StringBuilder body,
            String boundary,
            String fieldName,
            String filename,
            String contentType,
            String value
        )
        {
            body.append("--").append(boundary).append("\r\n");
            body.append("Content-Disposition: form-data; name=\"").append(fieldName).append("\"");
            if (filename != null)
            {
                body.append("; filename=\"").append(filename.replace("\"", "_")).append("\"");
            }
            body.append("\r\n");
            if (contentType != null)
            {
                body.append("Content-Type: ").append(contentType).append("\r\n");
            }
            body.append("\r\n");
            body.append(value == null ? "" : value).append("\r\n");
        }

        @SuppressWarnings("unchecked")
        private void setValueAtPath(Map<String, Object> target, String path, Object value)
        {
            String[] tokens = path.split("\\.");
            Object cursor = target;
            for (int index = 0; index < tokens.length - 1; index++)
            {
                String token = tokens[index];
                if (token.matches("\\d+"))
                {
                    cursor = ((List<Object>) cursor).get(Integer.parseInt(token));
                }
                else
                {
                    cursor = ((Map<String, Object>) cursor).get(token);
                }
            }
            String leaf = tokens[tokens.length - 1];
            if (leaf.matches("\\d+"))
            {
                ((List<Object>) cursor).set(Integer.parseInt(leaf), value);
            }
            else
            {
                ((Map<String, Object>) cursor).put(leaf, value);
            }
        }

        private record MultipartRequest(String boundary, String body)
        {
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
        request.contentType = contentTypeValue(headers);
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

        if (contentType.toLowerCase(Locale.ROOT).contains("multipart/form-data") && body != null && !body.isBlank())
        {
            Optional<GraphQLHunterModels.ScanRequest> multipart = parseMultipartGraphQlRequest(request, body);
            if (multipart.isPresent())
            {
                return multipart;
            }
        }

        if ("GET".equalsIgnoreCase(request.method))
        {
            Optional<GraphQLHunterModels.ScanRequest> fromQuery = parseGraphQlQueryParameters(request);
            if (fromQuery.isPresent())
            {
                return fromQuery;
            }
        }

        if (body == null || body.isBlank())
        {
            return Optional.empty();
        }

        if (contentType.toLowerCase(Locale.ROOT).contains("application/x-www-form-urlencoded"))
        {
            Optional<GraphQLHunterModels.ScanRequest> fromForm = parseGraphQlFormBody(request, body);
            if (fromForm.isPresent())
            {
                return fromForm;
            }
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

    private static Optional<GraphQLHunterModels.ScanRequest> parseGraphQlQueryParameters(GraphQLHunterModels.ScanRequest request)
    {
        try
        {
            URI uri = URI.create(request.url);
            Map<String, String> params = parseQueryString(uri.getRawQuery());
            String query = params.getOrDefault("query", "");
            if (query.isBlank())
            {
                return Optional.empty();
            }
            request.query = query;
            request.operationName = params.getOrDefault("operationName", extractOperationName(query));
            if (params.containsKey("variables") && !params.get("variables").isBlank())
            {
                request.variables = GraphQLHunterJson.mapper().readValue(params.get("variables"), Object.class);
            }
            return Optional.of(request);
        }
        catch (Exception ignored)
        {
            return Optional.empty();
        }
    }

    private static Optional<GraphQLHunterModels.ScanRequest> parseGraphQlFormBody(GraphQLHunterModels.ScanRequest request, String body)
    {
        try
        {
            Map<String, String> params = parseQueryString(body);
            String query = params.getOrDefault("query", "");
            if (query.isBlank())
            {
                return Optional.empty();
            }
            request.query = query;
            request.operationName = params.getOrDefault("operationName", extractOperationName(query));
            if (params.containsKey("variables") && !params.get("variables").isBlank())
            {
                request.variables = GraphQLHunterJson.mapper().readValue(params.get("variables"), Object.class);
            }
            return Optional.of(request);
        }
        catch (Exception ignored)
        {
            return Optional.empty();
        }
    }

    private static Map<String, String> parseQueryString(String query)
    {
        LinkedHashMap<String, String> values = new LinkedHashMap<>();
        if (query == null || query.isBlank())
        {
            return values;
        }
        for (String pair : query.split("&"))
        {
            String[] parts = pair.split("=", 2);
            String key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
            String value = parts.length > 1 ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : "";
            values.put(key, value);
        }
        return values;
    }

    private static Optional<GraphQLHunterModels.ScanRequest> parseMultipartGraphQlRequest(GraphQLHunterModels.ScanRequest request, String body)
    {
        java.util.regex.Matcher matcher = java.util.regex.Pattern.compile("name=\"operations\"\\R\\R(.*?)\\R--", java.util.regex.Pattern.DOTALL).matcher(body);
        if (!matcher.find())
        {
            return Optional.empty();
        }
        String operationsJson = matcher.group(1).trim();
        try
        {
            JsonNode node = GraphQLHunterJson.mapper().readTree(operationsJson);
            if (node.isObject() && node.has("query"))
            {
                request.query = node.path("query").asText("");
                request.operationName = node.path("operationName").asText(extractOperationName(request.query));
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
                request.operationName = node.get(0).path("operationName").asText(extractOperationName(request.query));
                if (node.get(0).has("variables") && !node.get(0).get("variables").isNull())
                {
                    request.variables = GraphQLHunterJson.mapper().convertValue(node.get(0).get("variables"), Object.class);
                }
                return Optional.of(request);
            }
        }
        catch (Exception ignored)
        {
        }
        return Optional.empty();
    }

    private static String extractOperationName(String query)
    {
        if (query == null || query.isBlank())
        {
            return "";
        }
        java.util.regex.Matcher matcher = java.util.regex.Pattern.compile("(?:query|mutation|subscription)\\s+(\\w+)").matcher(query);
        return matcher.find() ? matcher.group(1) : "";
    }

    private static String contentTypeValue(Map<String, String> headers)
    {
        if (headers == null)
        {
            return "application/json";
        }
        return headers.entrySet().stream()
            .filter(entry -> "content-type".equalsIgnoreCase(entry.getKey()))
            .map(Map.Entry::getValue)
            .findFirst()
            .orElse("application/json");
    }

    public static List<UploadTarget> findUploadTargets(Map<String, Object> schema, Map<String, Object> field)
    {
        List<UploadTarget> targets = new ArrayList<>();
        for (Map<String, Object> arg : asList(field.get("args")))
        {
            targets.addAll(collectUploadTargets(
                schema,
                asMap(arg.get("type")),
                "variables." + arg.get("name"),
                String.valueOf(arg.get("name")),
                new LinkedHashSet<>()
            ));
        }
        return targets;
    }

    private static List<UploadTarget> collectUploadTargets(
        Map<String, Object> schema,
        Map<String, Object> typeDef,
        String variablePath,
        String argName,
        Set<String> visited
    )
    {
        if (typeDef == null || typeDef.isEmpty())
        {
            return List.of();
        }
        String kind = String.valueOf(typeDef.getOrDefault("kind", ""));
        if ("NON_NULL".equals(kind))
        {
            return collectUploadTargets(schema, asMap(typeDef.get("ofType")), variablePath, argName, visited);
        }
        if ("LIST".equals(kind))
        {
            List<UploadTarget> targets = collectUploadTargets(schema, asMap(typeDef.get("ofType")), variablePath + ".0", argName, visited);
            targets.forEach(target -> target.list = true);
            return targets;
        }
        String typeName = extractTypeName(typeDef);
        if ("Upload".equals(typeName))
        {
            UploadTarget target = new UploadTarget();
            target.variablePath = variablePath;
            target.argName = argName;
            target.typeName = typeName;
            return List.of(target);
        }
        Map<String, Object> resolved = findType(schema, typeName);
        if (resolved.isEmpty() || !"INPUT_OBJECT".equals(String.valueOf(resolved.get("kind"))) || visited.contains(typeName))
        {
            return List.of();
        }
        LinkedHashSet<String> nextVisited = new LinkedHashSet<>(visited);
        nextVisited.add(typeName);
        List<UploadTarget> targets = new ArrayList<>();
        for (Map<String, Object> inputField : asList(resolved.get("inputFields")))
        {
            targets.addAll(collectUploadTargets(
                schema,
                asMap(inputField.get("type")),
                variablePath + "." + inputField.get("name"),
                argName,
                nextVisited
            ));
        }
        return targets;
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
            case "Upload" -> "upload-placeholder";
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
