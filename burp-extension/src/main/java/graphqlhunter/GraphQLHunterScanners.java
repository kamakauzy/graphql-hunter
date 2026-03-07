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

import java.util.ArrayList;
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
        GraphQLClient client = new GraphQLClient(request.url, request.headers, new GraphQLHunterCore.JavaHttpTransport(), logger, authManager);
        ScanContext context = new ScanContext(request, configuration, client, logger, ConfigurationLoader.payloads());
        List<ScannerCheck> checks = List.of(
            new IntrospectionScanner(),
            new InfoDisclosureScanner(),
            new AuthExposureScanner(),
            new BatchingScanner(),
            new InjectionLiteScanner()
        );

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

    private static String abbreviate(String value)
    {
        if (value == null)
        {
            return "";
        }
        return value.length() <= 500 ? value : value.substring(0, 500) + "...";
    }
}
