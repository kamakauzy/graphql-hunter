package graphqlhunter;

import graphqlhunter.GraphQLHunterCore.GraphQLClient;
import graphqlhunter.GraphQLHunterCore.GraphQLResponse;
import graphqlhunter.GraphQLHunterCore.Operation;
import graphqlhunter.GraphQLHunterModels.Finding;
import graphqlhunter.GraphQLHunterModels.AuthSettings;
import graphqlhunter.GraphQLHunterModels.FindingSeverity;
import graphqlhunter.GraphQLHunterModels.FindingStatus;
import graphqlhunter.GraphQLHunterModels.ScanRequest;
import graphqlhunter.auth.AuthManager;
import graphqlhunter.config.ConfigurationLoader;
import graphqlhunter.config.PayloadConfiguration;
import graphqlhunter.config.ScanConfiguration;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

public final class GraphQLHunterScanners
{
    private static final Pattern STACK_TRACE = Pattern.compile(
        "(traceback \\(most recent call last\\)|exception in thread|\\bat\\s+[\\w.$]+\\(|file \".*\", line \\d+|\\.java:\\d+\\))",
        Pattern.CASE_INSENSITIVE | Pattern.MULTILINE
    );
    private static final Pattern SQL_ERRORS = Pattern.compile(
        "(sqlstate|sql syntax|syntax error at or near|postgresql|mysql|sqlite|ora-\\d{5}|unterminated quoted string)",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern NOSQL_ERRORS = Pattern.compile(
        "(mongoerror|mongodb|couchdb|redis.*error|cassandra)",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern COMMAND_ERRORS = Pattern.compile(
        "(command not found|permission denied|/bin/|cannot execute|processexception|sh:|bash:)",
        Pattern.CASE_INSENSITIVE
    );

    private GraphQLHunterScanners()
    {
    }

    public static List<Finding> run(ScanRequest request, ScanConfiguration configuration, AuthSettings authSettings, GraphQLHunterLogger logger)
    {
        AuthManager authManager = AuthManager.fromState(authSettings, logger);
        GraphQLClient client = new GraphQLClient(
            request.url,
            request.headers,
            new GraphQLHunterCore.JavaHttpTransport(configuration.timeoutSeconds, configuration.delaySeconds),
            logger,
            authManager
        );
        ScanContext context = new ScanContext(request, configuration, client, logger, ConfigurationLoader.payloads());
        List<ScannerCheck> checks = new ArrayList<>();
        if (isEnabled(configuration, "introspection"))
        {
            checks.add(new IntrospectionScanner());
        }
        if (isEnabled(configuration, "info_disclosure"))
        {
            checks.add(new InfoDisclosureScanner());
        }
        if (isEnabled(configuration, "auth"))
        {
            checks.add(new AuthExposureScanner());
        }
        if (isEnabled(configuration, "batching"))
        {
            checks.add(new BatchingScanner());
        }
        if (isEnabled(configuration, "injection"))
        {
            checks.add(new InjectionLiteScanner());
        }
        if (configuration.enableDos && isEnabled(configuration, "dos"))
        {
            checks.add(new DoSScanner());
        }
        if (isEnabled(configuration, "aliasing"))
        {
            checks.add(new AliasingScanner());
        }
        if (isEnabled(configuration, "circular"))
        {
            checks.add(new CircularQueryScanner());
        }
        if (isEnabled(configuration, "xss"))
        {
            checks.add(new XssScanner());
        }
        if (isEnabled(configuration, "jwt"))
        {
            checks.add(new JwtScanner());
        }

        List<Finding> findings = new ArrayList<>();
        for (ScannerCheck check : checks)
        {
            try
            {
                findings.addAll(check.scan(context));
            }
            catch (RuntimeException exception)
            {
                if (logger != null)
                {
                    logger.error("Scanner failed: " + check.name(), exception);
                }
            }
        }
        return findings;
    }

    public interface ScannerCheck
    {
        String name();

        List<Finding> scan(ScanContext context);
    }

    public record ScanContext(
        ScanRequest request,
        ScanConfiguration configuration,
        GraphQLClient client,
        GraphQLHunterLogger logger,
        PayloadConfiguration payloads
    )
    {
    }

    public static final class IntrospectionScanner implements ScannerCheck
    {
        @Override
        public String name()
        {
            return "introspection";
        }

        @Override
        public List<Finding> scan(ScanContext context)
        {
            List<Finding> findings = new ArrayList<>();
            Map<String, Object> schema = context.client().introspect();
            if (schema == null || schema.isEmpty())
            {
                return findings;
            }

            Finding enabled = finding(
                "GraphQL Introspection Enabled",
                "introspection",
                FindingSeverity.MEDIUM,
                FindingStatus.CONFIRMED,
                "The endpoint returned a GraphQL schema document via the introspection query.",
                "Attackers can enumerate queries, mutations, types, and fields, which accelerates reconnaissance and exploit development.",
                "Disable introspection in production or restrict it to trusted users and environments."
            );
            enabled.proof = "{ __schema { types { name } } }";
            enabled.requestSnippet = enabled.proof;
            enabled.evidence.put("target", context.request().url);
            findings.add(enabled);

            int typeCount = GraphQLHunterCore.asList(schema.get("types")).size();
            int queryCount = GraphQLHunterCore.getRootFields(schema, "queryType").size();
            int mutationCount = GraphQLHunterCore.getRootFields(schema, "mutationType").size();
            Finding summary = finding(
                "GraphQL Schema Summary Available",
                "introspection",
                FindingSeverity.INFO,
                FindingStatus.CONFIRMED,
                "The extension successfully parsed the schema and summarized the available attack surface.",
                "Schema summaries help prioritize which root operations deserve manual review in Burp.",
                "Review sensitive root operations and use the imported request as a replay baseline for targeted checks."
            );
            summary.evidence.put("types", typeCount);
            summary.evidence.put("queries", queryCount);
            summary.evidence.put("mutations", mutationCount);
            findings.add(summary);
            return findings;
        }
    }

    public static final class InfoDisclosureScanner implements ScannerCheck
    {
        @Override
        public String name()
        {
            return "info_disclosure";
        }

        @Override
        public List<Finding> scan(ScanContext context)
        {
            List<Finding> findings = new ArrayList<>();

            for (String malformedQuery : List.of("{ invalid syntax here }", "{ __typename } extra", "query { }"))
            {
                GraphQLResponse response = context.client().query(malformedQuery, null, null);
                String errors = response.errorsText();
                if (!errors.isBlank() && STACK_TRACE.matcher(errors).find())
                {
                    Finding finding = finding(
                        "Stack Trace Disclosure",
                        name(),
                        FindingSeverity.MEDIUM,
                        FindingStatus.CONFIRMED,
                        "Malformed GraphQL input triggered a stack-trace-like error response.",
                        "Stack traces disclose framework, file-path, and implementation details that help attackers refine follow-up attacks.",
                        "Suppress stack traces in production and return generic client-facing error messages."
                    );
                    finding.proof = malformedQuery;
                    finding.requestSnippet = malformedQuery;
                    finding.evidence.put("errors", abbreviate(errors));
                    findings.add(finding);
                    break;
                }
            }

            GraphQLResponse suggestionResponse = context.client().query("{ __typename nonExistentFieldNameThatDoesNotExist123 }", null, null);
            String suggestionErrors = suggestionResponse.errorsText().toLowerCase(Locale.ROOT);
            if (suggestionErrors.contains("did you mean") || suggestionErrors.contains("suggest"))
            {
                Finding finding = finding(
                    "Field Suggestion Hints Enabled",
                    name(),
                    FindingSeverity.LOW,
                    FindingStatus.CONFIRMED,
                    "Validation errors included field-suggestion hints.",
                    "Field suggestions make schema reconnaissance easier for attackers by turning typo probes into guided discovery.",
                    "Disable field suggestions in production builds where possible."
                );
                finding.evidence.put("errors", abbreviate(suggestionResponse.errorsText()));
                findings.add(finding);
            }

            GraphQLResponse debugResponse = context.client().query("{ __typename }", null, null);
            Map<String, List<String>> debugHeaders = new LinkedHashMap<>();
            debugResponse.headers.forEach((key, value) ->
            {
                if (key != null && (key.toLowerCase(Locale.ROOT).startsWith("x-debug")
                    || key.equalsIgnoreCase("x-apollo-tracing")
                    || key.equalsIgnoreCase("x-graphql-tracing")))
                {
                    debugHeaders.put(key, value);
                }
            });
            if (!debugHeaders.isEmpty() || String.valueOf(debugResponse.bodyMap().get("extensions")).toLowerCase(Locale.ROOT).contains("tracing"))
            {
                Finding finding = finding(
                    "Debug or Tracing Metadata Exposed",
                    name(),
                    FindingSeverity.LOW,
                    FindingStatus.CONFIRMED,
                    "The endpoint returned debugging or tracing metadata in response headers or the GraphQL payload.",
                    "Response metadata can reveal timing, resolver structure, and backend implementation details.",
                    "Disable debug headers and tracing extensions in production."
                );
                finding.evidence.put("headers", debugHeaders);
                finding.evidence.put("extensions", abbreviate(String.valueOf(debugResponse.bodyMap().get("extensions"))));
                findings.add(finding);
            }

            GraphQLResponse verboseResponse = context.client().query("{ __schema { types { name(arg: \"invalid\") } } }", null, null);
            String verboseErrors = verboseResponse.errorsText();
            String lowerVerbose = verboseErrors.toLowerCase(Locale.ROOT);
            if (lowerVerbose.contains("cannot query field") || lowerVerbose.contains("line ") || lowerVerbose.contains("column"))
            {
                Finding finding = finding(
                    "Verbose Validation Errors",
                    name(),
                    FindingSeverity.LOW,
                    FindingStatus.POTENTIAL,
                    "Validation failures reveal detailed schema or parser context in error responses.",
                    "Detailed validation responses can help attackers iterate toward valid malicious requests more quickly.",
                    "Reduce validation verbosity for untrusted users while keeping full diagnostics in server-side logs."
                );
                finding.evidence.put("errors", abbreviate(verboseErrors));
                findings.add(finding);
            }

            return findings;
        }
    }

    public static final class AuthExposureScanner implements ScannerCheck
    {
        @Override
        public String name()
        {
            return "auth_exposure";
        }

        @Override
        public List<Finding> scan(ScanContext context)
        {
            List<Finding> findings = new ArrayList<>();
            boolean hasAuthHeader = context.request().headers.keySet().stream().anyMatch(key ->
                Set.of("authorization", "cookie", "token", "x-api-key", "x-auth-token")
                    .contains(key.toLowerCase(Locale.ROOT))
            );
            GraphQLClient unauthenticatedClient = context.client().withoutAuth();

            Map<String, Object> unauthenticatedSchema = unauthenticatedClient.introspect();
            if (unauthenticatedSchema != null && !unauthenticatedSchema.isEmpty())
            {
                Finding finding = finding(
                    "Unauthenticated Introspection Access",
                    name(),
                    FindingSeverity.HIGH,
                    FindingStatus.CONFIRMED,
                    "The endpoint returned its GraphQL schema after authentication material was stripped from the imported request.",
                    "Anonymous schema access can expose the entire GraphQL attack surface to unauthenticated users.",
                    "Require authentication for introspection or disable it entirely in production."
                );
                finding.proof = "{ __schema { queryType { name } } }";
                findings.add(finding);
            }

            if (hasAuthHeader)
            {
                GraphQLResponse authenticated = context.client().query("{ __typename }", null, null);
                GraphQLResponse unauthenticated = unauthenticatedClient.query("{ __typename }", null, null);
                if (authenticated.hasData() && unauthenticated.hasData() && unauthenticated.statusCode == authenticated.statusCode)
                {
                    Finding finding = finding(
                        "GraphQL Endpoint Still Reachable Without Imported Auth",
                        name(),
                        FindingSeverity.LOW,
                        FindingStatus.POTENTIAL,
                        "Stripping imported authentication material still produced a successful GraphQL response.",
                        "This can indicate missing or inconsistent authentication requirements for at least part of the GraphQL surface.",
                        "Verify which operations truly require authentication and enforce access control consistently."
                    );
                    finding.evidence.put("authenticated_status", authenticated.statusCode);
                    finding.evidence.put("unauthenticated_status", unauthenticated.statusCode);
                    findings.add(finding);
                }
            }

            return findings;
        }
    }

    public static final class BatchingScanner implements ScannerCheck
    {
        @Override
        public String name()
        {
            return "batching";
        }

        @Override
        public List<Finding> scan(ScanContext context)
        {
            List<Finding> findings = new ArrayList<>();
            List<Map<String, Object>> batch = List.of(
                Map.of("query", "{ __typename }"),
                Map.of("query", "{ __schema { queryType { name } } }"),
                Map.of("query", "{ __type(name: \"Query\") { name } }")
            );
            GraphQLResponse response = context.client().batchQuery(batch);
            List<Map<String, Object>> results = GraphQLHunterCore.asList(response.json);
            long successCount = results.stream().filter(result -> result.get("data") != null).count();

            if (successCount > 1)
            {
                Finding finding = finding(
                    "GraphQL Query Batching Enabled",
                    name(),
                    FindingSeverity.MEDIUM,
                    FindingStatus.CONFIRMED,
                    "The endpoint executed multiple GraphQL operations from a single HTTP request.",
                    "Batching can amplify brute-force, rate-limit bypass, and resource-exhaustion attacks if not tightly controlled.",
                    "Disable batching where possible or enforce strict batch-size and complexity limits."
                );
                finding.proof = GraphQLHunterJson.write(batch);
                finding.requestSnippet = finding.proof;
                finding.evidence.put("successful_queries", successCount);
                findings.add(finding);
            }

            return findings;
        }
    }

    public static final class InjectionLiteScanner implements ScannerCheck
    {
        @Override
        public String name()
        {
            return "injection";
        }

        @Override
        public List<Finding> scan(ScanContext context)
        {
            List<Finding> findings = new ArrayList<>();
            if ("QUICK".equalsIgnoreCase(context.configuration().profileName))
            {
                return findings;
            }

            Map<String, Object> schema = context.client().introspect();
            if (schema == null || schema.isEmpty())
            {
                return findings;
            }

            findings.addAll(scanRootFields(context, schema, "query", GraphQLHunterCore.getRootFields(schema, "queryType")));
            if (findings.size() < 2)
            {
                findings.addAll(scanRootFields(context, schema, "mutation", GraphQLHunterCore.getRootFields(schema, "mutationType")));
            }
            return findings;
        }

        private List<Finding> scanRootFields(ScanContext context, Map<String, Object> schema, String operationKind, List<Map<String, Object>> fields)
        {
            List<Finding> findings = new ArrayList<>();
            int checked = 0;
            for (Map<String, Object> field : fields)
            {
                if (checked >= 5)
                {
                    break;
                }
                List<Map<String, Object>> args = GraphQLHunterCore.asList(field.get("args"));
                if (args.isEmpty())
                {
                    continue;
                }

                for (Map<String, Object> arg : args)
                {
                    String typeName = GraphQLHunterCore.extractTypeName(GraphQLHunterCore.asMap(arg.get("type")));
                    if (!Set.of("String", "ID").contains(typeName))
                    {
                        continue;
                    }
                    checked++;
                    String argName = String.valueOf(arg.get("name"));
                    String baselineValue = "ID".equals(typeName) ? "1" : "__gqlh_baseline__";
                    Operation baseline = GraphQLHunterCore.buildOperation(schema, field, operationKind, Map.of(argName, baselineValue));
                    if (!baseline.testable)
                    {
                        continue;
                    }
                    GraphQLResponse baselineResponse = context.client().query(baseline.query, baseline.variables, baseline.operationName);
                    String baselineErrors = baselineResponse.errorsText().toLowerCase(Locale.ROOT);

                    List<String> sqlPayloads = new ArrayList<>();
                    sqlPayloads.addAll(context.payloads().sqlInjection.basic);
                    sqlPayloads.addAll(context.payloads().sqlInjection.unionBased);
                    if (emitPayloadFindings(context, findings, field, operationKind, schema, argName, sqlPayloads, baselineErrors, SQL_ERRORS, "Possible SQL Injection Behavior", FindingSeverity.HIGH))
                    {
                        break;
                    }
                    if (emitPayloadFindings(context, findings, field, operationKind, schema, argName, context.payloads().nosqlInjection, baselineErrors, NOSQL_ERRORS, "Possible NoSQL Injection Behavior", FindingSeverity.HIGH))
                    {
                        break;
                    }
                    if (emitPayloadFindings(context, findings, field, operationKind, schema, argName, context.payloads().commandInjection, baselineErrors, COMMAND_ERRORS, "Possible Command Injection Behavior", FindingSeverity.HIGH))
                    {
                        break;
                    }
                }

                if (findings.size() >= 3)
                {
                    break;
                }
            }
            return findings;
        }

        private boolean emitPayloadFindings(
            ScanContext context,
            List<Finding> findings,
            Map<String, Object> field,
            String operationKind,
            Map<String, Object> schema,
            String argName,
            List<String> payloads,
            String baselineErrors,
            Pattern pattern,
            String title,
            FindingSeverity severity
        )
        {
            for (String payload : payloads)
            {
                Operation probe = GraphQLHunterCore.buildOperation(schema, field, operationKind, Map.of(argName, payload));
                if (!probe.testable)
                {
                    continue;
                }
                GraphQLResponse response = context.client().query(probe.query, probe.variables, probe.operationName);
                String payloadErrors = response.errorsText().toLowerCase(Locale.ROOT);
                if (!payloadErrors.isBlank() && pattern.matcher(payloadErrors).find() && !pattern.matcher(baselineErrors).find())
                {
                    Finding finding = finding(
                        title,
                        name(),
                        severity,
                        FindingStatus.POTENTIAL,
                        "A schema-valid payload probe produced backend error signatures that were not present in the baseline response.",
                        "Backend-specific error signatures can indicate unsafe handling of user-controlled values in database or shell execution paths.",
                        "Validate and sanitize user input, use parameterized queries, and avoid directly composing shell commands from request data."
                    );
                    finding.proof = probe.query;
                    finding.requestSnippet = probe.query;
                    finding.evidence.put("field", field.get("name"));
                    finding.evidence.put("argument", argName);
                    finding.evidence.put("payload", payload);
                    finding.evidence.put("errors", abbreviate(response.errorsText()));
                    findings.add(finding);
                    return true;
                }
            }
            return false;
        }
    }

    private static Finding finding(
        String title,
        String scanner,
        FindingSeverity severity,
        FindingStatus status,
        String description,
        String impact,
        String remediation
    )
    {
        Finding finding = new Finding();
        finding.title = title;
        finding.scanner = scanner;
        finding.severity = severity;
        finding.status = status;
        finding.description = description;
        finding.impact = impact;
        finding.remediation = remediation;
        return finding;
    }

    private static boolean isEnabled(ScanConfiguration configuration, String scannerName)
    {
        return configuration == null || configuration.isScannerEnabled(scannerName);
    }

    private static String abbreviate(String value)
    {
        if (value == null)
        {
            return "";
        }
        return value.length() <= 500 ? value : value.substring(0, 500) + "...";
    }

    public static final class DoSScanner implements ScannerCheck
    {
        @Override
        public String name()
        {
            return "dos";
        }

        @Override
        public List<Finding> scan(ScanContext context)
        {
            List<Finding> findings = new ArrayList<>();
            findings.addAll(testDeepNesting(context));
            findings.addAll(testFieldDuplication(context));
            findings.addAll(testCircularReferences(context));
            findings.addAll(testComplexityLimits(context));
            return findings;
        }

        private List<Finding> testDeepNesting(ScanContext context)
        {
            List<Finding> findings = new ArrayList<>();
            int maxDepth = Math.min(context.configuration().depthLimit + 5, 15);
            for (int depth = 5; depth <= maxDepth; depth++)
            {
                String query = buildNestedQuery(depth);
                GraphQLResponse response = context.client().query(query, null, null);
                String errors = response.errorsText().toLowerCase(Locale.ROOT);
                if (errors.contains("depth") || errors.contains("nested"))
                {
                    Finding finding = finding(
                        "Query Depth Limit Enforced",
                        name(),
                        FindingSeverity.INFO,
                        FindingStatus.CONFIRMED,
                        "The endpoint rejected a deeply nested query with a depth-limit style response.",
                        "Depth limits are a useful control against GraphQL resource-exhaustion attacks.",
                        "No action needed. Keep depth limiting enabled."
                    );
                    finding.evidence.put("depth_limit", depth);
                    findings.add(finding);
                    return findings;
                }
                if (response.hasData() && depth >= 10)
                {
                    Finding finding = finding(
                        "No Query Depth Limit Detected",
                        name(),
                        FindingSeverity.MEDIUM,
                        FindingStatus.POTENTIAL,
                        "The endpoint accepted an intentionally deep query without an explicit depth-limit response.",
                        "Without depth limiting, attackers can craft arbitrarily deep queries that stress parsers and resolvers.",
                        "Implement server-side query depth limits, ideally around 5-7 for production APIs."
                    );
                    finding.evidence.put("depth_tested", depth);
                    finding.proof = query;
                    finding.requestSnippet = query;
                    findings.add(finding);
                    return findings;
                }
            }
            return findings;
        }

        private List<Finding> testFieldDuplication(ScanContext context)
        {
            List<Finding> findings = new ArrayList<>();
            int fieldCount = Math.min(context.configuration().fieldLimit + 10, 50);
            List<String> aliases = new ArrayList<>();
            for (int index = 0; index < fieldCount; index++)
            {
                aliases.add("field" + index + ": __typename");
            }
            String query = "{ " + String.join(" ", aliases) + " }";
            GraphQLResponse response = context.client().query(query, null, null);
            if (response.hasData() && response.elapsedMillis > 2000)
            {
                Finding finding = finding(
                    "Large Query With Field Duplication Accepted",
                    name(),
                    FindingSeverity.LOW,
                    FindingStatus.POTENTIAL,
                    "The endpoint accepted a large query that duplicates the same field many times using aliases.",
                    "Field duplication can multiply resolver work and increase the impact of a single request.",
                    "Add complexity accounting for duplicated fields and aliases."
                );
                finding.evidence.put("field_count", fieldCount);
                finding.evidence.put("elapsed_ms", response.elapsedMillis);
                finding.proof = query;
                finding.requestSnippet = query;
                findings.add(finding);
            }
            return findings;
        }

        private List<Finding> testCircularReferences(ScanContext context)
        {
            List<Finding> findings = new ArrayList<>();
            Map<String, Object> schema = context.client().introspect();
            if (schema == null || schema.isEmpty())
            {
                return findings;
            }
            for (Map<String, Object> type : GraphQLHunterCore.asList(schema.get("types")))
            {
                if (!"OBJECT".equals(String.valueOf(type.get("kind"))))
                {
                    continue;
                }
                String typeName = String.valueOf(type.getOrDefault("name", ""));
                if (typeName.startsWith("__"))
                {
                    continue;
                }
                for (Map<String, Object> field : GraphQLHunterCore.asList(type.get("fields")))
                {
                    if (typeName.equals(GraphQLHunterCore.extractTypeName(GraphQLHunterCore.asMap(field.get("type")))))
                    {
                        Finding finding = finding(
                            "Circular Type Reference Detected",
                            name(),
                            FindingSeverity.INFO,
                            FindingStatus.MANUAL_REVIEW,
                            "The schema contains a self-referential object type.",
                            "Circular object references can become a DoS vector if depth or complexity controls are weak.",
                            "Review self-referential types and ensure depth and complexity limits are enforced."
                        );
                        finding.evidence.put("type", typeName);
                        finding.evidence.put("field", field.get("name"));
                        findings.add(finding);
                        if (findings.size() >= 3)
                        {
                            return findings;
                        }
                        break;
                    }
                }
            }
            return findings;
        }

        private List<Finding> testComplexityLimits(ScanContext context)
        {
            List<Finding> findings = new ArrayList<>();
            String query = """
                {
                  a1: __schema { types { name } }
                  a2: __schema { types { name } }
                  a3: __schema { types { name fields { name } } }
                  a4: __schema { types { name fields { name } } }
                  a5: __schema { types { name fields { name } } }
                }
                """;
            GraphQLResponse response = context.client().query(query, null, null);
            String errors = response.errorsText().toLowerCase(Locale.ROOT);
            if (errors.contains("complexity"))
            {
                Finding finding = finding(
                    "Query Complexity Limit Enforced",
                    name(),
                    FindingSeverity.INFO,
                    FindingStatus.CONFIRMED,
                    "The endpoint rejected a deliberately complex query with a complexity-specific response.",
                    "Complexity limits are an effective control against expensive GraphQL request abuse.",
                    "No action needed. Keep complexity limiting enabled."
                );
                findings.add(finding);
            }
            else if (response.hasData())
            {
                Finding finding = finding(
                    "No Query Complexity Limit Detected",
                    name(),
                    FindingSeverity.LOW,
                    FindingStatus.POTENTIAL,
                    "The endpoint accepted a deliberately complex query without an explicit complexity-limit response.",
                    "Without complexity analysis, expensive GraphQL requests can overload resolver execution paths.",
                    "Add query complexity analysis and reject queries that exceed a defined budget."
                );
                finding.proof = query;
                finding.requestSnippet = query;
                findings.add(finding);
            }
            return findings;
        }

        private String buildNestedQuery(int depth)
        {
            StringBuilder query = new StringBuilder("__schema { ");
            for (int index = 0; index < depth - 1; index++)
            {
                query.append("types { name fields { name type { ");
            }
            query.append("name");
            for (int index = 0; index < depth - 1; index++)
            {
                query.append(" } } }");
            }
            query.append(" }");
            return "{ " + query + " }";
        }
    }

    public static final class AliasingScanner implements ScannerCheck
    {
        @Override
        public String name()
        {
            return "aliasing";
        }

        @Override
        public List<Finding> scan(ScanContext context)
        {
            List<Finding> findings = new ArrayList<>();
            findings.addAll(testFieldAliasing(context));
            findings.addAll(testAliasCost(context));
            return findings;
        }

        private List<Finding> testFieldAliasing(ScanContext context)
        {
            List<Finding> findings = new ArrayList<>();
            for (int count : List.of(10, 50, 100, 200))
            {
                if (count > context.configuration().fieldLimit * 3)
                {
                    break;
                }
                List<String> aliases = new ArrayList<>();
                for (int index = 0; index < count; index++)
                {
                    aliases.add("alias" + index + ": __typename");
                }
                String query = "{ " + String.join(" ", aliases) + " }";
                GraphQLResponse response = context.client().query(query, null, null);
                String errors = response.errorsText().toLowerCase(Locale.ROOT);
                if (response.hasData() && (count >= 100 || response.elapsedMillis > 3000))
                {
                    Finding finding = finding(
                        "Field Aliasing Abuse Possible",
                        name(),
                        FindingSeverity.HIGH,
                        FindingStatus.POTENTIAL,
                        "The endpoint accepted a large query that repeatedly aliases the same field.",
                        "Excessive field aliasing can multiply the cost of a single GraphQL request and enable resource-exhaustion attacks.",
                        "Limit total field aliases and include alias count in query complexity calculations."
                    );
                    finding.evidence.put("alias_count", count);
                    finding.evidence.put("elapsed_ms", response.elapsedMillis);
                    finding.proof = query;
                    finding.requestSnippet = query;
                    findings.add(finding);
                    return findings;
                }
                if (errors.contains("alias") || (errors.contains("field") && errors.contains("limit")))
                {
                    Finding finding = finding(
                        "Field Aliasing Limit Enforced",
                        name(),
                        FindingSeverity.INFO,
                        FindingStatus.CONFIRMED,
                        "The endpoint rejected a high-alias-count query with a limit-style response.",
                        "Alias limits help mitigate resource-exhaustion attacks based on repeated resolver execution.",
                        "No action needed. Keep alias or field-count limiting enabled."
                    );
                    finding.evidence.put("alias_limit", count);
                    findings.add(finding);
                    return findings;
                }
            }
            return findings;
        }

        private List<Finding> testAliasCost(ScanContext context)
        {
            List<Finding> findings = new ArrayList<>();
            Map<String, Object> schema = context.client().introspect();
            if (schema == null || schema.isEmpty())
            {
                return findings;
            }
            List<Map<String, Object>> queries = GraphQLHunterCore.getRootFields(schema, "queryType");
            if (queries.isEmpty())
            {
                return findings;
            }
            String queryName = String.valueOf(queries.getFirst().get("name"));
            List<String> aliases = new ArrayList<>();
            for (int index = 0; index < 20; index++)
            {
                aliases.add("call" + index + ": " + queryName);
            }
            String query = "{ " + String.join(" ", aliases) + " }";
            GraphQLResponse response = context.client().query(query, null, null);
            if (response.hasData() || response.elapsedMillis > 2000)
            {
                Finding finding = finding(
                    "Multiple Aliased Query Calls Accepted",
                    name(),
                    FindingSeverity.LOW,
                    FindingStatus.POTENTIAL,
                    "The endpoint allowed the same root query to be called repeatedly through aliases.",
                    "If the aliased query is expensive, this can amplify backend work within a single request.",
                    "Count aliased root calls toward complexity and consider caching identical resolver work within one request."
                );
                finding.evidence.put("query", queryName);
                finding.evidence.put("alias_count", 20);
                finding.evidence.put("elapsed_ms", response.elapsedMillis);
                finding.proof = query;
                finding.requestSnippet = query;
                findings.add(finding);
            }
            return findings;
        }
    }

    public static final class CircularQueryScanner implements ScannerCheck
    {
        @Override
        public String name()
        {
            return "circular";
        }

        @Override
        public List<Finding> scan(ScanContext context)
        {
            List<Finding> findings = new ArrayList<>();
            Map<String, Object> schema = context.client().introspect();
            if (schema == null || schema.isEmpty())
            {
                return findings;
            }
            for (Map<String, Object> type : GraphQLHunterCore.asList(schema.get("types")))
            {
                if (!"OBJECT".equals(String.valueOf(type.get("kind"))))
                {
                    continue;
                }
                String typeName = String.valueOf(type.getOrDefault("name", ""));
                if (typeName.startsWith("__"))
                {
                    continue;
                }
                for (Map<String, Object> field : GraphQLHunterCore.asList(type.get("fields")))
                {
                    if (typeName.equals(GraphQLHunterCore.extractTypeName(GraphQLHunterCore.asMap(field.get("type")))))
                    {
                        Finding finding = finding(
                            "Circular Reference Detected",
                            name(),
                            FindingSeverity.INFO,
                            FindingStatus.MANUAL_REVIEW,
                            "The schema contains a circular object reference.",
                            "Circular references can enable deeply nested queries when depth or complexity controls are weak.",
                            "Review depth and complexity protections around self-referential object graphs."
                        );
                        finding.evidence.put("type", typeName);
                        finding.evidence.put("field", field.get("name"));
                        findings.add(finding);
                        return findings;
                    }
                }
            }
            return findings;
        }
    }

    public static final class XssScanner implements ScannerCheck
    {
        @Override
        public String name()
        {
            return "xss";
        }

        @Override
        public List<Finding> scan(ScanContext context)
        {
            List<Finding> findings = new ArrayList<>();
            Map<String, Object> schema = context.client().introspect();
            if (schema == null || schema.isEmpty())
            {
                return findings;
            }
            findings.addAll(testFieldFamily(context, schema, "mutation", GraphQLHunterCore.getRootFields(schema, "mutationType")));
            if (findings.size() < 2)
            {
                findings.addAll(testFieldFamily(context, schema, "query", GraphQLHunterCore.getRootFields(schema, "queryType")));
            }
            return findings;
        }

        private List<Finding> testFieldFamily(ScanContext context, Map<String, Object> schema, String operationKind, List<Map<String, Object>> fields)
        {
            List<Finding> findings = new ArrayList<>();
            int testsRun = 0;
            for (Map<String, Object> field : fields)
            {
                if (testsRun >= context.configuration().maxXssTests)
                {
                    break;
                }
                List<Map<String, Object>> args = GraphQLHunterCore.asList(field.get("args"));
                if (args.isEmpty())
                {
                    continue;
                }
                Operation baseline = GraphQLHunterCore.buildOperation(schema, field, operationKind, Map.of());
                if (!baseline.testable)
                {
                    continue;
                }
                GraphQLResponse baselineResponse = context.client().query(baseline.query, baseline.variables, baseline.operationName);
                if (!baselineResponse.errorsText().toLowerCase(Locale.ROOT).contains("validation"))
                {
                    for (Map<String, Object> arg : args)
                    {
                        if (!"String".equals(GraphQLHunterCore.extractTypeName(GraphQLHunterCore.asMap(arg.get("type")))))
                        {
                            continue;
                        }
                        for (String payload : context.payloads().xssPayloads)
                        {
                            Operation probe = GraphQLHunterCore.buildOperation(schema, field, operationKind, Map.of(String.valueOf(arg.get("name")), payload));
                            if (!probe.testable)
                            {
                                continue;
                            }
                            GraphQLResponse response = context.client().query(probe.query, probe.variables, probe.operationName);
                            testsRun++;
                            String serialized = String.valueOf(response.json);
                            String escapedPayload = payload.replace("<", "\\u003c").replace(">", "\\u003e");
                            if (response.hasData() && (serialized.contains(payload) || serialized.contains(escapedPayload)))
                            {
                                Finding finding = finding(
                                    "Potential XSS Review Required",
                                    name(),
                                    FindingSeverity.MEDIUM,
                                    FindingStatus.MANUAL_REVIEW,
                                    "An XSS payload was reflected in successful GraphQL response data.",
                                    "If downstream clients render this value unsafely, reflected or stored XSS may be possible.",
                                    "Review output encoding and sink handling in applications that render this field's value."
                                );
                                finding.evidence.put("operation_kind", operationKind);
                                finding.evidence.put("field", field.get("name"));
                                finding.evidence.put("argument", arg.get("name"));
                                finding.evidence.put("payload", payload);
                                finding.proof = probe.query;
                                finding.requestSnippet = probe.query;
                                findings.add(finding);
                                return findings;
                            }
                            if (testsRun >= context.configuration().maxXssTests)
                            {
                                return findings;
                            }
                        }
                    }
                }
            }
            return findings;
        }
    }

    public static final class JwtScanner implements ScannerCheck
    {
        private static final Pattern JWT_HEADER = Pattern.compile("^Bearer\\s+([A-Za-z0-9-_]+)\\.([A-Za-z0-9-_]+)\\.([A-Za-z0-9-_]+)$");
        private static final Pattern JWT_RAW = Pattern.compile("^([A-Za-z0-9-_]+)\\.([A-Za-z0-9-_]+)\\.([A-Za-z0-9-_]+)$");

        @Override
        public String name()
        {
            return "jwt";
        }

        @Override
        public List<Finding> scan(ScanContext context)
        {
            List<Finding> findings = new ArrayList<>();
            String token = null;
            String headerName = null;
            for (Map.Entry<String, String> entry : context.request().headers.entrySet())
            {
                if ("Authorization".equalsIgnoreCase(entry.getKey()) && JWT_HEADER.matcher(entry.getValue()).matches())
                {
                    token = entry.getValue().substring("Bearer ".length()).trim();
                    headerName = "Authorization";
                    break;
                }
                if ("Token".equalsIgnoreCase(entry.getKey()) && JWT_RAW.matcher(entry.getValue()).matches())
                {
                    token = entry.getValue().trim();
                    headerName = "Token";
                    break;
                }
            }
            if (token == null)
            {
                return findings;
            }

            Finding detected = finding(
                "JWT Token Authentication Detected",
                name(),
                FindingSeverity.INFO,
                FindingStatus.CONFIRMED,
                "The imported request uses a JWT-shaped token for authentication.",
                "JWT-based auth requires strict signature, expiry, issuer, and audience validation.",
                "Ensure JWTs are validated on every request and reject insecure or expired tokens."
            );
            detected.evidence.put("header", headerName);
            findings.add(detected);

            try
            {
                String[] parts = token.split("\\.");
                String payloadJson = new String(Base64.getUrlDecoder().decode(pad(parts[1])), StandardCharsets.UTF_8);
                @SuppressWarnings("unchecked")
                Map<String, Object> payload = GraphQLHunterJson.readMap(payloadJson);
                Object exp = payload.get("exp");
                Object iat = payload.get("iat");
                if (exp != null)
                {
                    long current = java.time.Instant.now().getEpochSecond();
                    long expires = Long.parseLong(String.valueOf(exp));
                    if (expires < current)
                    {
                        Finding finding = finding(
                            "Expired JWT Token Detected",
                            name(),
                            FindingSeverity.MEDIUM,
                            FindingStatus.CONFIRMED,
                            "The imported JWT token appears to be expired based on its exp claim.",
                            "If the server still accepts expired tokens, stale credentials can be replayed indefinitely.",
                            "Ensure the server validates JWT expiration on every request."
                        );
                        finding.evidence.put("exp", expires);
                        finding.evidence.put("current", current);
                        findings.add(finding);
                    }
                    else if (iat != null)
                    {
                        long lifetime = expires - Long.parseLong(String.valueOf(iat));
                        if (lifetime > 24 * 3600)
                        {
                            Finding finding = finding(
                                "Long-Lived JWT Token",
                                name(),
                                FindingSeverity.LOW,
                                FindingStatus.POTENTIAL,
                                "The JWT appears to have a long access-token lifetime based on iat/exp claims.",
                                "Long-lived tokens increase the impact window if a token is compromised.",
                                "Prefer shorter-lived access tokens and refresh-token rotation."
                            );
                            finding.evidence.put("lifetime_seconds", lifetime);
                            findings.add(finding);
                        }
                    }
                }
            }
            catch (Exception ignored)
            {
                // Detection finding above still stands.
            }
            return findings;
        }

        private String pad(String value)
        {
            int padding = (4 - value.length() % 4) % 4;
            return value + "=".repeat(padding);
        }
    }
}
