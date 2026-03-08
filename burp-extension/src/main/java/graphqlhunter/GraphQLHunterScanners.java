package graphqlhunter;

import graphqlhunter.GraphQLHunterCore.GraphQLClient;
import graphqlhunter.GraphQLHunterCore.GraphQLResponse;
import graphqlhunter.GraphQLHunterCore.Operation;
import graphqlhunter.GraphQLHunterModels.ScanExecutionResult;
import graphqlhunter.GraphQLHunterModels.ScannerFailure;
import graphqlhunter.GraphQLHunterModels.ScannerSkip;
import graphqlhunter.GraphQLHunterModels.Finding;
import graphqlhunter.GraphQLHunterModels.AuthSettings;
import graphqlhunter.GraphQLHunterModels.FindingSeverity;
import graphqlhunter.GraphQLHunterModels.FindingStatus;
import graphqlhunter.GraphQLHunterModels.ScanRequest;
import graphqlhunter.auth.AuthManager;
import graphqlhunter.auth.AuthProvider;
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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
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
        return runWithMetadata(request, configuration, authSettings, logger).findings;
    }

    public static ScanExecutionResult runWithMetadata(ScanRequest request, ScanConfiguration configuration, AuthSettings authSettings, GraphQLHunterLogger logger)
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
        return runWithContext(context);
    }

    static ScanExecutionResult runWithContext(ScanContext context)
    {
        ScanRequest request = context.request();
        ScanConfiguration configuration = context.configuration();
        GraphQLHunterLogger logger = context.logger();
        List<PlannedCheck> plan = buildPlan(configuration);
        ScanExecutionResult result = new ScanExecutionResult();
        result.request = request == null ? new ScanRequest() : request.copy();
        result.status = "completed";
        for (PlannedCheck entry : plan)
        {
            if (!entry.enabled())
            {
                result.skippedScanners.add(new ScannerSkip(entry.displayName(), entry.skipReason()));
                continue;
            }
            result.executedScanners.add(entry.displayName());
            try
            {
                result.findings.addAll(entry.check().scan(context));
            }
            catch (RuntimeException exception)
            {
                result.status = "partial";
                result.failedScanners.add(new ScannerFailure(entry.displayName(), exception.getMessage() == null ? exception.getClass().getSimpleName() : exception.getMessage()));
                if (logger != null)
                {
                    logger.error("Scanner failed: " + entry.check().name(), exception);
                }
            }
        }
        return result;
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

    private record PlannedCheck(
        String scannerKey,
        String displayName,
        boolean enabled,
        String skipReason,
        ScannerCheck check
    )
    {
    }

    private static List<PlannedCheck> buildPlan(ScanConfiguration configuration)
    {
        List<PlannedCheck> checks = new ArrayList<>();
        checks.add(plan(configuration, "introspection", "Introspection", true, "disabled by settings", new IntrospectionScanner()));
        checks.add(plan(configuration, "info_disclosure", "Information Disclosure", true, "disabled by settings", new InfoDisclosureScanner()));
        checks.add(plan(configuration, "auth", "Authentication/Authorization", true, "disabled by settings", new AuthExposureScanner()));
        checks.add(plan(configuration, "batching", "Batching Attacks", true, "disabled by settings", new BatchingScanner()));
        checks.add(plan(configuration, "injection", "Injection", true, "disabled by settings", new InjectionLiteScanner()));
        checks.add(plan(configuration, "dos", "DoS Vectors", configuration.enableDos, "disabled by profile or settings", new DoSScanner()));
        checks.add(plan(configuration, "aliasing", "Aliasing Abuse", true, "disabled by settings", new AliasingScanner()));
        checks.add(plan(configuration, "circular", "Circular Queries", true, "disabled by settings", new CircularQueryScanner()));
        checks.add(plan(configuration, "xss", "Cross-Site Scripting (XSS)", true, "disabled by settings", new XssScanner()));
        checks.add(plan(configuration, "jwt", "JWT Security", true, "disabled by settings", new JwtScanner()));
        checks.add(plan(configuration, "rate_limit", "Rate Limiting", configuration.enableRateLimitTesting, "disabled by profile or settings", new RateLimitingScanner()));
        checks.add(plan(configuration, "csrf", "CSRF Protection", configuration.enableCsrfTesting, "disabled by profile or settings", new CsrfScanner()));
        checks.add(plan(configuration, "file_upload", "File Upload", configuration.enableFileUploadTesting, "disabled by profile or settings", new FileUploadScanner()));
        checks.add(plan(configuration, "mutation_fuzzing", "Mutation Fuzzing", true, "disabled by settings", new MutationFuzzerScanner()));
        return checks;
    }

    private static PlannedCheck plan(
        ScanConfiguration configuration,
        String scannerKey,
        String displayName,
        boolean profileEnabled,
        String skipReason,
        ScannerCheck check
    )
    {
        boolean enabled = profileEnabled && isEnabled(configuration, scannerKey);
        return new PlannedCheck(scannerKey, displayName, enabled, enabled ? "" : skipReason, check);
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

            findings.addAll(testLoginBruteForceProtection(context));

            return findings;
        }

        private List<Finding> testLoginBruteForceProtection(ScanContext context)
        {
            if (context.configuration().safeMode)
            {
                return List.of();
            }
            Map<String, Object> schema = context.client().introspect();
            if (schema == null || schema.isEmpty())
            {
                return List.of();
            }
            List<Map<String, Object>> loginMutations = GraphQLHunterCore.getRootFields(schema, "mutationType").stream()
                .filter(field ->
                {
                    String name = String.valueOf(field.getOrDefault("name", "")).toLowerCase(Locale.ROOT);
                    return name.contains("login") || name.contains("signin") || name.contains("auth");
                })
                .toList();
            for (Map<String, Object> mutation : loginMutations)
            {
                List<Map<String, Object>> args = GraphQLHunterCore.asList(mutation.get("args"));
                String userArg = findArgName(args, "email", "username", "user");
                String passwordArg = findArgName(args, "password", "pass");
                if (userArg == null || passwordArg == null)
                {
                    continue;
                }
                int attempts = Math.max(1, context.configuration().bruteForceAttempts);
                Map<Integer, Integer> statusCodes = new LinkedHashMap<>();
                boolean rateLimited = false;
                boolean accountLocked = false;
                boolean captchaRequired = false;
                int triggerAttempt = 0;
                for (int index = 0; index < attempts; index++)
                {
                    Operation probe = GraphQLHunterCore.buildOperation(
                        schema,
                        mutation,
                        "mutation",
                        Map.of(
                            userArg, "test@example.com",
                            passwordArg, "wrongpass" + index
                        )
                    );
                    if (!probe.testable)
                    {
                        return List.of();
                    }
                    GraphQLResponse response = context.client().query(probe.query, probe.variables, probe.operationName);
                    statusCodes.merge(response.statusCode, 1, Integer::sum);
                    String errors = response.errorsText().toLowerCase(Locale.ROOT);
                    if (response.statusCode == 429)
                    {
                        rateLimited = true;
                        triggerAttempt = index + 1;
                        break;
                    }
                    if (errors.contains("lock") || errors.contains("block") || errors.contains("suspended"))
                    {
                        accountLocked = true;
                        triggerAttempt = index + 1;
                        break;
                    }
                    if (errors.contains("captcha") || errors.contains("recaptcha"))
                    {
                        captchaRequired = true;
                        triggerAttempt = index + 1;
                        break;
                    }
                }

                if (rateLimited)
                {
                    Finding finding = finding(
                        "Brute-Force Protection: Rate Limiting Detected",
                        name(),
                        FindingSeverity.INFO,
                        FindingStatus.CONFIRMED,
                        "A login-like mutation returned HTTP 429 after repeated failed attempts.",
                        "Rate limiting helps reduce the impact of password guessing and credential-stuffing attacks.",
                        "Keep login throttling enabled and tune thresholds to match expected user behavior."
                    );
                    finding.evidence.put("mutation", mutation.get("name"));
                    finding.evidence.put("rate_limited_after_attempts", triggerAttempt);
                    finding.evidence.put("total_attempts", attempts);
                    return List.of(finding);
                }
                if (accountLocked)
                {
                    Finding finding = finding(
                        "Brute-Force Protection: Account Lockout Detected",
                        name(),
                        FindingSeverity.INFO,
                        FindingStatus.CONFIRMED,
                        "A login-like mutation indicated account lockout after repeated failed attempts.",
                        "Account lockout can slow or stop brute-force attacks against authentication flows.",
                        "Review lockout duration and abuse resistance to avoid turning it into a denial-of-service vector."
                    );
                    finding.evidence.put("mutation", mutation.get("name"));
                    finding.evidence.put("lockout_after_attempts", triggerAttempt);
                    return List.of(finding);
                }
                if (captchaRequired)
                {
                    Finding finding = finding(
                        "Brute-Force Protection: CAPTCHA Detected",
                        name(),
                        FindingSeverity.INFO,
                        FindingStatus.POTENTIAL,
                        "A login-like mutation indicated a CAPTCHA challenge after repeated failed attempts.",
                        "CAPTCHA can reduce automated credential-stuffing when combined with rate limits and monitoring.",
                        "Verify that CAPTCHA challenges cannot be bypassed and are applied consistently to risky login flows."
                    );
                    finding.evidence.put("mutation", mutation.get("name"));
                    finding.evidence.put("captcha_after_attempts", triggerAttempt);
                    return List.of(finding);
                }

                Finding finding = finding(
                    "Brute-Force Protection Not Detected",
                    name(),
                    FindingSeverity.LOW,
                    FindingStatus.MANUAL_REVIEW,
                    "A login-like mutation did not show rate limiting, lockout, or CAPTCHA signals during repeated failed attempts.",
                    "Without brute-force protections, attackers may be able to automate password guessing or credential-stuffing attacks.",
                    "Review login throttling, account lockout, CAPTCHA, progressive delays, and IP/user-based controls."
                );
                finding.evidence.put("mutation", mutation.get("name"));
                finding.evidence.put("attempts_tested", attempts);
                finding.evidence.put("status_codes", statusCodes);
                return List.of(finding);
            }
            return List.of();
        }

        private String findArgName(List<Map<String, Object>> args, String... needles)
        {
            for (Map<String, Object> arg : args)
            {
                String name = String.valueOf(arg.getOrDefault("name", "")).toLowerCase(Locale.ROOT);
                for (String needle : needles)
                {
                    if (name.contains(needle))
                    {
                        return String.valueOf(arg.get("name"));
                    }
                }
            }
            return null;
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

            findings.addAll(testBatchSizeLimits(context));

            return findings;
        }

        private List<Finding> testBatchSizeLimits(ScanContext context)
        {
            List<Finding> findings = new ArrayList<>();
            int configuredMaximum = Math.max(10, context.configuration().batchSize);
            for (int size : List.of(10, 25, 50, 100))
            {
                if (size > Math.max(25, configuredMaximum * 5))
                {
                    break;
                }
                List<Map<String, Object>> batch = new ArrayList<>();
                for (int index = 0; index < size; index++)
                {
                    batch.add(Map.of("query", "{ __typename }"));
                }
                GraphQLResponse response = context.client().batchQuery(batch);
                String errors = response.errorsText().toLowerCase(Locale.ROOT);
                List<Map<String, Object>> results = GraphQLHunterCore.asList(response.json);
                long successCount = results.stream().filter(result -> result.get("data") != null).count();

                if (errors.contains("batch") && (errors.contains("limit") || errors.contains("too many") || errors.contains("maximum")))
                {
                    Finding finding = finding(
                        "Batch Size Limit Enforced",
                        name(),
                        FindingSeverity.INFO,
                        FindingStatus.CONFIRMED,
                        "The endpoint rejected an oversized GraphQL batch with a limit-style response.",
                        "Batch-size limits reduce the blast radius of request batching abuse and brute-force amplification.",
                        "No action needed. Keep batch-size enforcement aligned with expected client behavior."
                    );
                    finding.evidence.put("batch_limit", size);
                    findings.add(finding);
                    return findings;
                }

                if (successCount >= size && size > configuredMaximum)
                {
                    Finding finding = finding(
                        "Large GraphQL Batches Accepted",
                        name(),
                        FindingSeverity.HIGH,
                        FindingStatus.POTENTIAL,
                        "The endpoint accepted a large batch of GraphQL operations without an obvious size limit.",
                        "Large batches can amplify brute-force, enumeration, and resource-exhaustion attacks within a single request.",
                        "Enforce strict server-side batch-size and complexity limits, especially for authenticated mutations."
                    );
                    finding.evidence.put("batch_size", size);
                    finding.proof = GraphQLHunterJson.write(batch);
                    finding.requestSnippet = finding.proof;
                    findings.add(finding);
                    return findings;
                }
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
                    if ("query".equals(operationKind) && "String".equals(typeName) && context.configuration().enableDeepInjection)
                    {
                        Finding booleanFinding = emitBooleanDifferentialFinding(context, field, operationKind, schema, argName);
                        if (booleanFinding != null)
                        {
                            findings.add(booleanFinding);
                            break;
                        }
                    }
                    if (emitPayloadFindings(context, findings, field, operationKind, schema, argName, context.payloads().nosqlInjection, baselineErrors, NOSQL_ERRORS, "Possible NoSQL Injection Behavior", FindingSeverity.HIGH))
                    {
                        break;
                    }
                    if (emitPayloadFindings(context, findings, field, operationKind, schema, argName, context.payloads().commandInjection, baselineErrors, COMMAND_ERRORS, "Possible Command Injection Behavior", FindingSeverity.HIGH))
                    {
                        break;
                    }
                    if ("query".equals(operationKind) && context.configuration().enableDeepInjection)
                    {
                        Finding timingFinding = emitTimeBasedFinding(context, field, operationKind, schema, argName, baseline);
                        if (timingFinding != null)
                        {
                            findings.add(timingFinding);
                            break;
                        }
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

        private Finding emitBooleanDifferentialFinding(
            ScanContext context,
            Map<String, Object> field,
            String operationKind,
            Map<String, Object> schema,
            String argName
        )
        {
            Map<String, Object> commonOverrides = new LinkedHashMap<>();
            for (Map<String, Object> extraArg : GraphQLHunterCore.asList(field.get("args")))
            {
                if ("limit".equals(String.valueOf(extraArg.get("name")))
                    && "Int".equals(GraphQLHunterCore.extractTypeName(GraphQLHunterCore.asMap(extraArg.get("type")))))
                {
                    commonOverrides.put("limit", 5);
                }
            }

            Map<String, Object> baselineOverrides = new LinkedHashMap<>(commonOverrides);
            baselineOverrides.put(argName, "__gqlh_baseline__");
            Operation baseline = GraphQLHunterCore.buildOperation(schema, field, operationKind, baselineOverrides);
            if (!baseline.testable)
            {
                return null;
            }
            GraphQLResponse baselineResponse = context.client().query(baseline.query, baseline.variables, baseline.operationName);
            if (!isComparableBooleanResponse(baselineResponse))
            {
                return null;
            }

            int baselineCount = extractRootListCount(baselineResponse, String.valueOf(field.get("name")));
            if (baselineCount < 0)
            {
                return null;
            }

            for (String payload : context.payloads().sqlInjection.basic)
            {
                if (!isBooleanSqlPayload(payload))
                {
                    continue;
                }
                String falseControl = falseControlPayload(payload);
                if (falseControl == null)
                {
                    continue;
                }

                Operation trueProbe = GraphQLHunterCore.buildOperation(schema, field, operationKind, override(commonOverrides, argName, payload));
                Operation falseProbe = GraphQLHunterCore.buildOperation(schema, field, operationKind, override(commonOverrides, argName, falseControl));
                if (!trueProbe.testable || !falseProbe.testable)
                {
                    continue;
                }

                GraphQLResponse trueResponse = context.client().query(trueProbe.query, trueProbe.variables, trueProbe.operationName);
                GraphQLResponse falseResponse = context.client().query(falseProbe.query, falseProbe.variables, falseProbe.operationName);
                if (!responsesComparableForBooleanDiff(baselineResponse, falseResponse, trueResponse))
                {
                    continue;
                }

                int trueCount = extractRootListCount(trueResponse, String.valueOf(field.get("name")));
                int falseCount = extractRootListCount(falseResponse, String.valueOf(field.get("name")));
                if (trueCount >= Math.max(baselineCount, falseCount) + 2 && falseCount <= baselineCount + 1)
                {
                    Finding finding = finding(
                        "Potential Boolean-Differential SQL Injection Behavior",
                        name(),
                        FindingSeverity.HIGH,
                        FindingStatus.MANUAL_REVIEW,
                        "A tautology-style SQL payload produced materially broader list results than both the baseline and a false-control payload.",
                        "Boolean-differential responses can indicate that attacker-controlled input is influencing backend query predicates even when no explicit SQL errors are exposed.",
                        "Review how filter arguments are composed into backend queries, use parameterized queries, and verify that tautology-style input does not broaden result sets."
                    );
                    finding.proof = trueProbe.query;
                    finding.requestSnippet = trueProbe.query;
                    finding.evidence.put("field", field.get("name"));
                    finding.evidence.put("argument", argName);
                    finding.evidence.put("payload_true", payload);
                    finding.evidence.put("payload_false", falseControl);
                    finding.evidence.put("baseline_count", baselineCount);
                    finding.evidence.put("false_count", falseCount);
                    finding.evidence.put("true_count", trueCount);
                    return finding;
                }
            }
            return null;
        }

        private Finding emitTimeBasedFinding(
            ScanContext context,
            Map<String, Object> field,
            String operationKind,
            Map<String, Object> schema,
            String argName,
            Operation baseline
        )
        {
            List<Long> baselineSamples = collectTimingSamples(context, baseline, 3);
            if (baselineSamples.isEmpty() || isTimingBaselineNoisy(baselineSamples))
            {
                return null;
            }

            Operation control = GraphQLHunterCore.buildOperation(schema, field, operationKind, Map.of(argName, "__gqlh_control__"));
            List<Long> controlSamples = collectTimingSamples(context, control, 2);
            long baselineMedian = median(baselineSamples);
            long controlMedian = controlSamples.isEmpty() ? baselineMedian : median(controlSamples);

            for (String payload : context.payloads().sqlInjection.timeBased)
            {
                Operation probe = GraphQLHunterCore.buildOperation(schema, field, operationKind, Map.of(argName, payload));
                if (!probe.testable)
                {
                    continue;
                }
                List<Long> payloadSamples = collectTimingSamples(context, probe, 3);
                if (payloadSamples.isEmpty())
                {
                    continue;
                }
                long payloadMedian = median(payloadSamples);
                long expectedDelay = expectedDelayMillis(payload);
                long delta = payloadMedian - Math.max(baselineMedian, controlMedian);
                long threshold = Math.max(2500L, expectedDelay / 2);
                long elevatedSamples = payloadSamples.stream().filter(value -> value >= baselineMedian + threshold).count();
                if (delta >= threshold && controlMedian - baselineMedian < 1000L && elevatedSamples >= 2)
                {
                    Finding finding = finding(
                        "Potential Time-Based SQL Injection Vulnerability",
                        name(),
                        FindingSeverity.HIGH,
                        FindingStatus.POTENTIAL,
                        "A time-based SQL injection payload produced a consistent response delay that was not present in baseline or control requests.",
                        "Time-based delays can indicate that attacker-controlled input is reaching database execution paths even when no error details are exposed.",
                        "Use parameterized queries, validate input, and reject payloads that alter database execution timing."
                    );
                    finding.proof = probe.query;
                    finding.requestSnippet = probe.query;
                    finding.evidence.put("field", field.get("name"));
                    finding.evidence.put("argument", argName);
                    finding.evidence.put("payload", payload);
                    finding.evidence.put("baseline_samples_ms", baselineSamples);
                    finding.evidence.put("control_samples_ms", controlSamples);
                    finding.evidence.put("payload_samples_ms", payloadSamples);
                    finding.evidence.put("baseline_median_ms", baselineMedian);
                    finding.evidence.put("payload_median_ms", payloadMedian);
                    finding.evidence.put("control_median_ms", controlMedian);
                    finding.evidence.put("delta_ms", delta);
                    return finding;
                }
            }
            return null;
        }

        private List<Long> collectTimingSamples(ScanContext context, Operation operation, int count)
        {
            if (operation == null || !operation.testable)
            {
                return List.of();
            }
            List<Long> samples = new ArrayList<>();
            for (int index = 0; index < count; index++)
            {
                GraphQLResponse response = context.client().query(operation.query, operation.variables, operation.operationName);
                if (response.statusCode == 0)
                {
                    return List.of();
                }
                samples.add(response.elapsedMillis);
            }
            return samples;
        }

        private boolean isTimingBaselineNoisy(List<Long> samples)
        {
            long min = samples.stream().mapToLong(Long::longValue).min().orElse(0L);
            long max = samples.stream().mapToLong(Long::longValue).max().orElse(0L);
            return max - min > 1500L;
        }

        private long median(List<Long> samples)
        {
            List<Long> ordered = new ArrayList<>(samples);
            ordered.sort(Long::compareTo);
            return ordered.get(ordered.size() / 2);
        }

        private long expectedDelayMillis(String payload)
        {
            java.util.regex.Matcher matcher = java.util.regex.Pattern.compile("(sleep|pg_sleep)\\((\\d+)\\)|delay '\\d+:\\d+:(\\d+)'", java.util.regex.Pattern.CASE_INSENSITIVE)
                .matcher(payload == null ? "" : payload);
            if (matcher.find())
            {
                String seconds = matcher.group(2) != null ? matcher.group(2) : matcher.group(3);
                try
                {
                    return Long.parseLong(seconds) * 1000L;
                }
                catch (NumberFormatException ignored)
                {
                    return 5000L;
                }
            }
            return 5000L;
        }

        private boolean isBooleanSqlPayload(String payload)
        {
            String lowered = payload == null ? "" : payload.toLowerCase(Locale.ROOT);
            return lowered.contains("1=1") || lowered.contains("'a'='a") || lowered.contains("\"a\"=\"a");
        }

        private String falseControlPayload(String payload)
        {
            if (payload == null)
            {
                return null;
            }
            return payload
                .replace("1=1", "1=2")
                .replace("'a'='a", "'a'='b")
                .replace("\"a\"=\"a", "\"a\"=\"b");
        }

        private Map<String, Object> override(Map<String, Object> commonOverrides, String argName, String payload)
        {
            LinkedHashMap<String, Object> overrides = new LinkedHashMap<>(commonOverrides);
            overrides.put(argName, payload);
            return overrides;
        }

        private boolean isComparableBooleanResponse(GraphQLResponse response)
        {
            return response != null && response.statusCode == 200 && response.hasData() && response.errorsText().isBlank();
        }

        private boolean responsesComparableForBooleanDiff(GraphQLResponse baseline, GraphQLResponse falseResponse, GraphQLResponse trueResponse)
        {
            return isComparableBooleanResponse(baseline)
                && isComparableBooleanResponse(falseResponse)
                && isComparableBooleanResponse(trueResponse)
                && baseline.statusCode == falseResponse.statusCode
                && baseline.statusCode == trueResponse.statusCode;
        }

        private int extractRootListCount(GraphQLResponse response, String fieldName)
        {
            Object data = response.bodyMap().get("data");
            if (!(data instanceof Map<?, ?> map))
            {
                return -1;
            }
            Object value = map.get(fieldName);
            if (!(value instanceof List<?> list))
            {
                return -1;
            }
            return list.size();
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
                        findings.addAll(testExpiredTokenAcceptance(context, headerName, token, expires));
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
            findings.addAll(testNoneAlgorithm(context, headerName));
            return findings;
        }

        private String pad(String value)
        {
            int padding = (4 - value.length() % 4) % 4;
            return value + "=".repeat(padding);
        }

        private List<Finding> testNoneAlgorithm(ScanContext context, String headerName)
        {
            if (headerName == null || headerName.isBlank())
            {
                return List.of();
            }

            String forgedHeader = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
            String forgedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(
                GraphQLHunterJson.write(Map.of(
                    "sub", "1234567890",
                    "name", "GraphQL Hunter",
                    "admin", true,
                    "iat", java.time.Instant.now().getEpochSecond(),
                    "exp", java.time.Instant.now().plusSeconds(3600).getEpochSecond()
                )).getBytes(StandardCharsets.UTF_8)
            );
            String forgedToken = forgedHeader + "." + forgedPayload + ".";
            String headerValue = "Authorization".equalsIgnoreCase(headerName) ? "Bearer " + forgedToken : forgedToken;

            GraphQLResponse unauthenticated = context.client().withoutAuth().query("{ __typename }", null, null);
            GraphQLResponse forged = context.client().query("{ __typename }", null, null, Map.of(headerName, headerValue), false);
            if (forged.hasData() && (!unauthenticated.hasData() || unauthenticated.statusCode != forged.statusCode || containsAuthFailure(unauthenticated.errorsText())))
            {
                Finding finding = finding(
                    "JWT 'none' Algorithm Vulnerability",
                    name(),
                    FindingSeverity.CRITICAL,
                    FindingStatus.CONFIRMED,
                    "The endpoint accepted a forged JWT that declared the 'none' algorithm.",
                    "If signatureless JWTs are accepted, attackers can forge tokens and bypass authentication entirely.",
                    "Reject unsigned JWTs, enforce a strict allowlist of secure algorithms, and validate signatures on every request."
                );
                finding.proof = headerName + ": " + headerValue;
                finding.requestSnippet = "{ __typename }";
                finding.evidence.put("header", headerName);
                finding.evidence.put("forged_token_accepted", true);
                findingsAddContext(finding, forged);
                return List.of(finding);
            }
            return List.of();
        }

        private List<Finding> testExpiredTokenAcceptance(ScanContext context, String headerName, String token, long expires)
        {
            if (headerName == null || headerName.isBlank() || token == null || token.isBlank())
            {
                return List.of();
            }
            GraphQLResponse unauthenticated = context.client().withoutAuth().query("{ __typename }", null, null);
            String headerValue = "Authorization".equalsIgnoreCase(headerName) ? "Bearer " + token : token;
            GraphQLResponse expiredTokenResponse = context.client().withoutAuth().query(
                "{ __typename }",
                null,
                null,
                Map.of(headerName, headerValue),
                true
            );
            if (expiredTokenResponse.hasData()
                && (!unauthenticated.hasData() || unauthenticated.statusCode != expiredTokenResponse.statusCode || containsAuthFailure(unauthenticated.errorsText())))
            {
                Finding finding = finding(
                    "Expired JWT Token Still Accepted",
                    name(),
                    FindingSeverity.HIGH,
                    FindingStatus.CONFIRMED,
                    "The endpoint accepted a benign GraphQL request authenticated only with an already expired JWT.",
                    "If expired JWTs are still honored, attackers may be able to replay stale credentials indefinitely.",
                    "Validate the exp claim on every request and reject expired JWTs immediately."
                );
                finding.proof = "Use expired token in " + headerName + " header";
                finding.requestSnippet = "{ __typename }";
                finding.evidence.put("header", headerName);
                finding.evidence.put("exp", expires);
                findingsAddContext(finding, expiredTokenResponse);
                return List.of(finding);
            }
            return List.of();
        }
    }

    public static final class RateLimitingScanner implements ScannerCheck
    {
        @Override
        public String name()
        {
            return "rate_limiting";
        }

        @Override
        public List<Finding> scan(ScanContext context)
        {
            List<Finding> findings = new ArrayList<>();
            findings.addAll(testConcurrentRequests(context));
            findings.addAll(testRateLimitHeaders(context));
            findings.addAll(testMutationRateLimits(context));
            return findings;
        }

        private List<Finding> testConcurrentRequests(ScanContext context)
        {
            List<Finding> findings = new ArrayList<>();
            int total = Math.max(1, context.configuration().rateLimitRequests);
            int concurrency = Math.max(1, Math.min(context.configuration().rateLimitConcurrency, total));
            int rateLimited = 0;
            int errors = 0;
            Map<Integer, Integer> statusCodes = new LinkedHashMap<>();
            ExecutorService executor = Executors.newFixedThreadPool(concurrency);
            CountDownLatch startGate = new CountDownLatch(1);
            List<Future<GraphQLResponse>> futures = new ArrayList<>();
            for (int index = 0; index < total; index++)
            {
                futures.add(executor.submit(() ->
                {
                    startGate.await();
                    return context.client().query("{ __typename }", null, null);
                }));
            }
            startGate.countDown();
            try
            {
                for (Future<GraphQLResponse> future : futures)
                {
                    GraphQLResponse response = future.get();
                    statusCodes.merge(response.statusCode, 1, Integer::sum);
                    if (response.statusCode == 429)
                    {
                        rateLimited++;
                    }
                    else if (response.statusCode == 0)
                    {
                        errors++;
                    }
                }
            }
            catch (Exception exception)
            {
                errors++;
            }
            finally
            {
                executor.shutdownNow();
            }

            if (rateLimited > 0)
            {
                Finding finding = finding(
                    "Rate Limiting Detected",
                    name(),
                    FindingSeverity.INFO,
                    FindingStatus.CONFIRMED,
                    "The endpoint returned HTTP 429 during a burst test, indicating rate limiting is present.",
                    "Rate limiting helps protect against abuse and burst-driven DoS attacks.",
                    "No action needed. Ensure thresholds match operational expectations."
                );
                finding.evidence.put("rate_limited_requests", rateLimited);
                finding.evidence.put("total_requests", total);
                finding.evidence.put("concurrency", concurrency);
                finding.evidence.put("status_codes", statusCodes);
                findings.add(finding);
            }
            else if (errors > total / 2)
            {
                Finding finding = finding(
                    "Possible Rate Limiting or DoS Protection",
                    name(),
                    FindingSeverity.INFO,
                    FindingStatus.POTENTIAL,
                    "The endpoint produced a high error rate during a burst test, which may indicate throttling or protective controls.",
                    "High error rates under burst traffic can be a sign of rate limiting or defensive degradation behavior.",
                    "Review server-side throttling configuration and validate intended burst behavior manually."
                );
                finding.evidence.put("error_count", errors);
                finding.evidence.put("total_requests", total);
                finding.evidence.put("concurrency", concurrency);
                findings.add(finding);
            }
            else
            {
                Finding finding = finding(
                    "No Rate Limiting Detected",
                    name(),
                    FindingSeverity.MEDIUM,
                    FindingStatus.POTENTIAL,
                    "A burst test completed without HTTP 429 responses or clear throttling signals.",
                    "Without rate limiting, attackers may be able to flood the GraphQL endpoint or automate password guessing and resource abuse.",
                    "Implement per-IP, per-user, and/or per-operation throttling as appropriate."
                );
                finding.evidence.put("total_requests", total);
                finding.evidence.put("concurrency", concurrency);
                finding.evidence.put("status_codes", statusCodes);
                findings.add(finding);
            }
            return findings;
        }

        private List<Finding> testRateLimitHeaders(ScanContext context)
        {
            List<Finding> findings = new ArrayList<>();
            GraphQLResponse response = context.client().query("{ __typename }", null, null);
            Map<String, List<String>> matching = new LinkedHashMap<>();
            response.headers.forEach((key, value) ->
            {
                if (key != null)
                {
                    String lowered = key.toLowerCase(Locale.ROOT);
                    if (lowered.startsWith("x-ratelimit") || lowered.equals("ratelimit-limit") || lowered.equals("ratelimit-remaining") || lowered.equals("retry-after"))
                    {
                        matching.put(key, value);
                    }
                }
            });
            if (!matching.isEmpty())
            {
                Finding finding = finding(
                    "Rate Limit Headers Present",
                    name(),
                    FindingSeverity.INFO,
                    FindingStatus.CONFIRMED,
                    "The endpoint exposes explicit rate-limit metadata in HTTP headers.",
                    "Visible rate-limit headers help clients back off and confirm throttling controls are in place.",
                    "No action needed. Ensure the exposed metadata matches the true enforcement policy."
                );
                finding.evidence.put("rate_limit_headers", matching);
                findings.add(finding);
            }
            return findings;
        }

        private List<Finding> testMutationRateLimits(ScanContext context)
        {
            List<Finding> findings = new ArrayList<>();
            Map<String, Object> schema = context.client().introspect();
            if (schema == null || schema.isEmpty())
            {
                return findings;
            }
            List<Map<String, Object>> mutations = GraphQLHunterCore.getRootFields(schema, "mutationType");
            if (mutations.isEmpty())
            {
                return findings;
            }
            Operation built = GraphQLHunterCore.buildOperation(schema, mutations.getFirst(), "mutation", Map.of());
            if (!built.testable)
            {
                return findings;
            }
            int burst = Math.max(1, Math.min(50, context.configuration().rateLimitRequests / 2));
            boolean rateLimited = false;
            for (int index = 0; index < burst; index++)
            {
                GraphQLResponse response = context.client().query(built.query, built.variables, built.operationName);
                if (response.statusCode == 429)
                {
                    rateLimited = true;
                    break;
                }
            }
            if (rateLimited)
            {
                Finding finding = finding(
                    "Mutation Rate Limiting Detected",
                    name(),
                    FindingSeverity.INFO,
                    FindingStatus.CONFIRMED,
                    "A mutation burst triggered HTTP 429, suggesting operation-specific throttling is in place.",
                    "Mutation-specific throttling helps reduce abuse against state-changing operations.",
                    "No action needed. Ensure thresholds fit real usage."
                );
                finding.evidence.put("burst_requests", burst);
                findings.add(finding);
            }
            else
            {
                Finding finding = finding(
                    "Mutation Rate Limiting Not Detected",
                    name(),
                    FindingSeverity.LOW,
                    FindingStatus.MANUAL_REVIEW,
                    "A mutation burst did not trigger explicit throttling in the current test.",
                    "Mutations often deserve stricter rate limiting than read-only queries because they change server-side state.",
                    "Review whether state-changing operations have dedicated rate limits."
                );
                finding.evidence.put("burst_requests", burst);
                finding.proof = built.query;
                finding.requestSnippet = built.query;
                findings.add(finding);
            }
            return findings;
        }
    }

    public static final class CsrfScanner implements ScannerCheck
    {
        @Override
        public String name()
        {
            return "csrf";
        }

        @Override
        public List<Finding> scan(ScanContext context)
        {
            List<Finding> findings = new ArrayList<>();
            boolean hasCookieAuth = context.request().headers.keySet().stream().anyMatch(key -> "Cookie".equalsIgnoreCase(key))
                || (context.client().flowClient().getCookie("sessionid") != null);
            if (!hasCookieAuth)
            {
                return findings;
            }
            Map<String, Object> schema = context.client().introspect();
            if (schema == null || schema.isEmpty())
            {
                return findings;
            }
            List<Map<String, Object>> mutations = GraphQLHunterCore.getRootFields(schema, "mutationType");
            if (mutations.isEmpty())
            {
                return findings;
            }
            Operation built = GraphQLHunterCore.buildOperation(schema, mutations.getFirst(), "mutation", Map.of());
            if (!built.testable)
            {
                return findings;
            }

            GraphQLResponse missingOrigin = context.client().query(
                built.query,
                built.variables,
                built.operationName,
                Map.of(),
                false,
                Set.of("Origin", "Referer")
            );
            if (missingOrigin.hasData() && !containsCsrfFailure(missingOrigin.errorsText()))
            {
                Finding finding = finding(
                    "CSRF Vulnerability: Missing Origin Header Validation",
                    name(),
                    FindingSeverity.HIGH,
                    FindingStatus.POTENTIAL,
                    "A state-changing mutation succeeded without explicit Origin/Referer validation signals.",
                    "If cookie-authenticated mutations do not validate request origin, cross-site request forgery may be possible.",
                    "Validate Origin/Referer and require CSRF tokens or equivalent anti-CSRF mechanisms for mutations."
                );
                finding.proof = built.query;
                finding.requestSnippet = built.query;
                findings.add(finding);
            }

            GraphQLResponse forgedOrigin = context.client().query(
                built.query,
                built.variables,
                built.operationName,
                Map.of(
                    "Origin", "https://evil.example",
                    "Referer", "https://evil.example/attack"
                ),
                false
            );
            if (forgedOrigin.hasData() && !containsCsrfFailure(forgedOrigin.errorsText()))
            {
                Finding finding = finding(
                    "CSRF Vulnerability: Origin Header Not Validated",
                    name(),
                    FindingSeverity.HIGH,
                    FindingStatus.POTENTIAL,
                    "A state-changing mutation succeeded even when cross-site Origin and Referer headers were supplied.",
                    "If cookie-authenticated mutations do not validate Origin or Referer, attackers may be able to trigger unwanted actions from another site.",
                    "Reject cross-site Origin/Referer values for state-changing requests and require CSRF tokens or equivalent anti-CSRF controls."
                );
                finding.proof = built.query;
                finding.requestSnippet = built.query;
                finding.evidence.put("origin", "https://evil.example");
                findings.add(finding);
            }

            String csrfHeader = detectCsrfTokenSource(context);
            if (csrfHeader.isBlank())
            {
                Finding finding = finding(
                    "CSRF Token Not Detected",
                    name(),
                    FindingSeverity.MEDIUM,
                    FindingStatus.MANUAL_REVIEW,
                    "No likely CSRF token header was observed alongside cookie-based auth context.",
                    "Without CSRF tokens or equivalent protections, cookie-authenticated mutations may be at higher risk of CSRF.",
                    "Review whether CSRF tokens, SameSite cookies, and Origin/Referer validation are implemented consistently."
                );
                findings.add(finding);
            }
            else
            {
                Finding finding = finding(
                    "CSRF Token Detected",
                    name(),
                    FindingSeverity.INFO,
                    FindingStatus.CONFIRMED,
                    "A likely CSRF-related header was present in the current auth context.",
                    "Presence of a CSRF token often indicates a mitigation is in place, though validation still needs review.",
                    "Confirm server-side CSRF token validation for all mutations."
                );
                finding.evidence.put("header", csrfHeader);
                findings.add(finding);
            }
            return findings;
        }
    }

    private static String detectCsrfTokenSource(ScanContext context)
    {
        String csrfHeader = context.request().headers.keySet().stream()
            .filter(key -> key.toLowerCase(Locale.ROOT).contains("csrf") || key.toLowerCase(Locale.ROOT).contains("xsrf"))
            .findFirst()
            .orElse("");
        if (!csrfHeader.isBlank())
        {
            return csrfHeader;
        }

        String cookieHeader = context.request().headers.entrySet().stream()
            .filter(entry -> "cookie".equalsIgnoreCase(entry.getKey()))
            .map(Map.Entry::getValue)
            .findFirst()
            .orElse("");
        for (String cookie : cookieHeader.split(";"))
        {
            String name = cookie.split("=", 2)[0].trim();
            String lowered = name.toLowerCase(Locale.ROOT);
            if (lowered.contains("csrf") || lowered.contains("xsrf"))
            {
                return "cookie:" + name;
            }
        }

        for (String cookieName : List.of("csrftoken", "csrf", "xsrf", "xsrf-token", "csrf-token"))
        {
            if (context.client().flowClient().getCookie(cookieName) != null)
            {
                return "cookie:" + cookieName;
            }
        }
        return "";
    }

    private static boolean containsAuthFailure(String text)
    {
        return AuthProvider.looksLikeAuthFailure(0, text);
    }

    private static boolean containsCsrfFailure(String text)
    {
        String lowered = text == null ? "" : text.toLowerCase(Locale.ROOT);
        return lowered.contains("csrf") || lowered.contains("origin") || lowered.contains("referer") || lowered.contains("xsrf");
    }

    private static void findingsAddContext(Finding finding, GraphQLResponse response)
    {
        finding.evidence.put("status_code", response.statusCode);
        if (!response.errorsText().isBlank())
        {
            finding.evidence.put("errors", abbreviate(response.errorsText()));
        }
    }

    public static final class FileUploadScanner implements ScannerCheck
    {
        private static final List<String> PATH_TRAVERSAL_PAYLOADS = List.of(
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd"
        );
        private static final List<String> DANGEROUS_EXTENSIONS = List.of(
            "payload.php",
            "payload.jsp",
            "payload.aspx"
        );
        private static final List<String> SUSPICIOUS_FILENAMES = List.of(
            "file.txt%00.jpg",
            "file.txt\u0000.jpg",
            "file.txt\n\r"
        );

        @Override
        public String name()
        {
            return "file_upload";
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
            List<Map<String, Object>> mutations = GraphQLHunterCore.getRootFields(schema, "mutationType");
            for (Map<String, Object> mutation : mutations)
            {
                String mutationName = String.valueOf(mutation.getOrDefault("name", ""));
                List<Map<String, Object>> args = GraphQLHunterCore.asList(mutation.get("args"));
                Map<String, Map<String, Object>> argByName = new LinkedHashMap<>();
                args.forEach(arg -> argByName.put(String.valueOf(arg.get("name")).toLowerCase(Locale.ROOT), arg));

                boolean uploadScalar = args.stream().anyMatch(arg -> "Upload".equals(GraphQLHunterCore.extractTypeName(GraphQLHunterCore.asMap(arg.get("type")))));
                boolean stringUploadSurface = (argByName.containsKey("filename") || argByName.containsKey("file") || argByName.containsKey("path"))
                    && (argByName.containsKey("content") || argByName.containsKey("text") || argByName.containsKey("data") || argByName.containsKey("body"))
                    && mutationName.toLowerCase(Locale.ROOT).matches(".*(upload|import|file|paste).*");

                if (stringUploadSurface)
                {
                    Finding liveFinding = probeStringUploadSurface(context, schema, mutation, argByName);
                    if (liveFinding != null)
                    {
                        findings.add(liveFinding);
                        continue;
                    }
                }

                if (uploadScalar || stringUploadSurface)
                {
                    Finding finding = finding(
                        "File Upload Mutation Detected",
                        name(),
                        FindingSeverity.INFO,
                        FindingStatus.MANUAL_REVIEW,
                        "The schema exposes a mutation that appears to accept uploaded file data or upload-like string fields.",
                        "File upload surfaces can be vulnerable to path traversal, dangerous extensions, oversize uploads, and filename injection.",
                        "Review filename validation, file type checks, storage location, and size limits. Exercise multipart upload handling where applicable."
                    );
                    finding.evidence.put("mutation", mutationName);
                    finding.evidence.put("upload_scalar", uploadScalar);
                    finding.evidence.put("string_upload_surface", stringUploadSurface);
                    findings.add(finding);
                }
            }
            return findings;
        }

        private Finding probeStringUploadSurface(
            ScanContext context,
            Map<String, Object> schema,
            Map<String, Object> mutation,
            Map<String, Map<String, Object>> argByName
        )
        {
            String filenameArg = pickArgName(argByName, "filename", "file", "path");
            String contentArg = pickArgName(argByName, "content", "text", "data", "body");
            if (filenameArg == null || contentArg == null)
            {
                return null;
            }
            String mutationName = String.valueOf(mutation.getOrDefault("name", ""));

            Finding traversal = probeUploadPayload(
                context, schema, mutation, mutationName, filenameArg, contentArg,
                PATH_TRAVERSAL_PAYLOADS,
                "Potential Path Traversal in File Upload",
                FindingSeverity.HIGH,
                "Upload-like mutation accepted a dangerous traversal-style filename payload.",
                "If upload paths are not normalized and constrained, attackers may write files outside the intended directory tree.",
                "Normalize and validate filenames, reject traversal sequences and separators, and generate server-side filenames."
            );
            if (traversal != null)
            {
                return traversal;
            }

            Finding extension = probeUploadPayload(
                context, schema, mutation, mutationName, filenameArg, contentArg,
                DANGEROUS_EXTENSIONS,
                "Potential Dangerous File Type Upload",
                FindingSeverity.MEDIUM,
                "Upload-like mutation accepted a potentially dangerous file extension.",
                "If uploaded files are later served or executed, dangerous file types can enable server-side compromise or stored client-side attacks.",
                "Use an allowlist of permitted file types, validate MIME/magic bytes, and store uploads outside executable or public directories."
            );
            if (extension != null)
            {
                return extension;
            }

            return probeUploadPayload(
                context, schema, mutation, mutationName, filenameArg, contentArg,
                SUSPICIOUS_FILENAMES,
                "Potential Filename Injection Vulnerability",
                FindingSeverity.LOW,
                "Upload-like mutation accepted a suspicious filename payload without rejecting it.",
                "Unsanitized filenames can enable downstream parser confusion, path traversal, or command injection depending on how filenames are processed.",
                "Whitelist safe filename characters, strip control characters, and never pass user-provided filenames directly to shell commands or unsafe sinks."
            );
        }

        private Finding probeUploadPayload(
            ScanContext context,
            Map<String, Object> schema,
            Map<String, Object> mutation,
            String mutationName,
            String filenameArg,
            String contentArg,
            List<String> payloads,
            String title,
            FindingSeverity severity,
            String description,
            String impact,
            String remediation
        )
        {
            for (String payload : payloads)
            {
                Operation probe = GraphQLHunterCore.buildOperation(
                    schema,
                    mutation,
                    "mutation",
                    Map.of(
                        filenameArg, payload,
                        contentArg, "upload-test"
                    )
                );
                if (!probe.testable)
                {
                    continue;
                }
                GraphQLResponse response = context.client().query(probe.query, probe.variables, probe.operationName);
                if (response.hasData() && response.errorsText().isBlank())
                {
                    Finding finding = finding(
                        title,
                        name(),
                        severity,
                        FindingStatus.POTENTIAL,
                        description,
                        impact,
                        remediation
                    );
                    finding.proof = probe.query;
                    finding.requestSnippet = probe.query;
                    finding.evidence.put("mutation", mutationName);
                    finding.evidence.put("filename_argument", filenameArg);
                    finding.evidence.put("payload", payload);
                    findingsAddContext(finding, response);
                    return finding;
                }
            }
            return null;
        }

        private String pickArgName(Map<String, Map<String, Object>> argByName, String... candidates)
        {
            for (String candidate : candidates)
            {
                if (argByName.containsKey(candidate))
                {
                    return String.valueOf(argByName.get(candidate).get("name"));
                }
            }
            return null;
        }
    }

    public static final class MutationFuzzerScanner implements ScannerCheck
    {
        private static final List<String> DANGEROUS_KEYWORDS = List.of(
            "delete", "remove", "drop", "destroy", "admin", "privilege", "permission", "role", "grant", "revoke", "ban", "disable"
        );
        private static final List<String> SENSITIVE_FIELDS = List.of(
            "role", "admin", "isAdmin", "is_admin", "permissions", "privileges", "accessLevel",
            "userId", "user_id", "ownerId", "owner_id", "createdAt", "created_at", "updatedAt", "updated_at",
            "deletedAt", "deleted_at", "version", "id"
        );

        @Override
        public String name()
        {
            return "mutation_fuzzer";
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
            List<Map<String, Object>> mutations = GraphQLHunterCore.getRootFields(schema, "mutationType");
            if (mutations.isEmpty())
            {
                return findings;
            }
            findings.addAll(identifyDangerousMutations(context, mutations));
            findings.addAll(findIdorCandidates(context, mutations));
            findings.addAll(findMassAssignmentCandidates(context, schema, mutations));
            findings.addAll(findPrivilegeEscalationCandidates(context, mutations));
            return findings;
        }

        private List<Finding> identifyDangerousMutations(ScanContext context, List<Map<String, Object>> mutations)
        {
            List<Map<String, Object>> dangerous = new ArrayList<>();
            for (Map<String, Object> mutation : mutations)
            {
                String mutationName = String.valueOf(mutation.getOrDefault("name", "")).toLowerCase(Locale.ROOT);
                for (String keyword : DANGEROUS_KEYWORDS)
                {
                    if (mutationName.contains(keyword))
                    {
                        dangerous.add(Map.of(
                            "name", mutation.get("name"),
                            "keyword", keyword,
                            "args", mutation.get("args")
                        ));
                        break;
                    }
                }
            }
            if (dangerous.isEmpty())
            {
                return List.of();
            }
            Finding finding = finding(
                "Potentially Dangerous Mutations Found",
                name(),
                FindingSeverity.INFO,
                FindingStatus.MANUAL_REVIEW,
                "The schema includes mutations whose names suggest destructive or privileged actions.",
                "Sensitive mutations deserve close authorization review because they can modify high-value data or permissions.",
                "Review authorization controls, audit logging, and rate limits for these mutations."
            );
            finding.evidence.put("dangerous_mutations", dangerous.subList(0, Math.min(10, dangerous.size())));
            return List.of(finding);
        }

        private List<Finding> findIdorCandidates(ScanContext context, List<Map<String, Object>> mutations)
        {
            List<Map<String, Object>> candidates = new ArrayList<>();
            for (Map<String, Object> mutation : mutations)
            {
                List<Map<String, Object>> args = GraphQLHunterCore.asList(mutation.get("args"));
                List<Map<String, Object>> idArgs = new ArrayList<>();
                for (Map<String, Object> arg : args)
                {
                    String argName = String.valueOf(arg.getOrDefault("name", "")).toLowerCase(Locale.ROOT);
                    String argType = GraphQLHunterCore.extractTypeName(GraphQLHunterCore.asMap(arg.get("type")));
                    if (argName.contains("id") || "ID".equals(argType) || ("Int".equals(argType) && argName.contains("id")))
                    {
                        idArgs.add(Map.of("name", arg.get("name"), "type", argType));
                    }
                }
                if (!idArgs.isEmpty())
                {
                    candidates.add(Map.of(
                        "mutation", mutation.get("name"),
                        "id_arguments", idArgs
                    ));
                }
            }
            if (candidates.isEmpty())
            {
                return List.of();
            }
            Finding finding = finding(
                "Potential IDOR/BOLA Vulnerabilities in Mutations",
                name(),
                FindingSeverity.INFO,
                FindingStatus.MANUAL_REVIEW,
                "Several mutations accept object identifiers and may require object-level authorization review.",
                "If ownership or authorization checks are weak, attackers may be able to modify other users' resources by changing ID values.",
                "Test these mutations with identifiers belonging to other users and verify server-side ownership checks."
            );
            finding.evidence.put("idor_candidates", candidates.subList(0, Math.min(10, candidates.size())));
            return List.of(finding);
        }

        private List<Finding> findMassAssignmentCandidates(ScanContext context, Map<String, Object> schema, List<Map<String, Object>> mutations)
        {
            List<Map<String, Object>> candidates = new ArrayList<>();
            for (Map<String, Object> mutation : mutations)
            {
                for (Map<String, Object> arg : GraphQLHunterCore.asList(mutation.get("args")))
                {
                    String typeName = GraphQLHunterCore.extractTypeName(GraphQLHunterCore.asMap(arg.get("type")));
                    if (!typeName.contains("Input"))
                    {
                        continue;
                    }
                    Map<String, Object> resolved = findType(schema, typeName);
                    if (resolved.isEmpty())
                    {
                        continue;
                    }
                    List<String> fieldNames = GraphQLHunterCore.asList(resolved.get("inputFields")).stream()
                        .map(field -> String.valueOf(field.get("name")))
                        .toList();
                    List<String> sensitive = fieldNames.stream()
                        .filter(field -> SENSITIVE_FIELDS.stream().anyMatch(sensitiveField -> sensitiveField.equalsIgnoreCase(field)))
                        .toList();
                    if (!sensitive.isEmpty())
                    {
                        candidates.add(Map.of(
                            "mutation", mutation.get("name"),
                            "input_type", typeName,
                            "sensitive_fields", sensitive
                        ));
                    }
                }
            }
            if (candidates.isEmpty())
            {
                return List.of();
            }
            Finding finding = finding(
                "Potential Mass Assignment Vulnerability",
                name(),
                FindingSeverity.INFO,
                FindingStatus.MANUAL_REVIEW,
                "Some mutation input objects contain fields that look sensitive or privileged.",
                "If the backend binds these input fields directly without filtering, clients may set fields they should not control.",
                "Use allowlists for mutable fields and reject unexpected or sensitive attributes in mutation inputs."
            );
            finding.evidence.put("mass_assignment_candidates", candidates.subList(0, Math.min(10, candidates.size())));
            return List.of(finding);
        }

        private List<Finding> findPrivilegeEscalationCandidates(ScanContext context, List<Map<String, Object>> mutations)
        {
            for (Map<String, Object> mutation : mutations)
            {
                String mutationName = String.valueOf(mutation.getOrDefault("name", "")).toLowerCase(Locale.ROOT);
                if (mutationName.contains("user") || mutationName.contains("create") || mutationName.contains("update") || mutationName.contains("register") || mutationName.contains("signup"))
                {
                    Finding finding = finding(
                        "Privilege Escalation Testing Recommended",
                        name(),
                        FindingSeverity.INFO,
                        FindingStatus.MANUAL_REVIEW,
                        "A user-related mutation may warrant privilege-escalation testing via unexpected input fields.",
                        "If sensitive fields like role or admin flags are accepted, users may be able to escalate privileges during account or profile changes.",
                        "Test whether unexpected privileged fields are ignored or rejected by the server."
                    );
                    finding.evidence.put("mutation", mutation.get("name"));
                    return List.of(finding);
                }
            }
            return List.of();
        }

        private Map<String, Object> findType(Map<String, Object> schema, String typeName)
        {
            for (Map<String, Object> type : GraphQLHunterCore.asList(schema.get("types")))
            {
                if (typeName.equals(String.valueOf(type.get("name"))))
                {
                    return type;
                }
            }
            return Map.of();
        }
    }
}
