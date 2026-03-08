package graphqlhunter.burp;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import graphqlhunter.GraphQLHunterModels;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

public final class GraphQLHunterPassiveScanCheck implements PassiveScanCheck
{
    private static final Pattern STACK_TRACE = Pattern.compile(
        "(traceback \\(most recent call last\\)|exception in thread|\\bat\\s+[\\w.$]+\\(|file \".*\", line \\d+|\\.java:\\d+\\))",
        Pattern.CASE_INSENSITIVE | Pattern.MULTILINE
    );
    private final BurpIssuePublisher issuePublisher;

    public GraphQLHunterPassiveScanCheck(BurpIssuePublisher issuePublisher)
    {
        this.issuePublisher = issuePublisher;
    }

    @Override
    public String checkName()
    {
        return "GraphQL Hunter Passive";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse requestResponse)
    {
        return AuditResult.auditResult(issuesFor(requestResponse));
    }

    List<AuditIssue> issuesFor(HttpRequestResponse requestResponse)
    {
        Optional<GraphQLHttpMessageCodec.DecodedRequest> decoded = GraphQLHttpMessageCodec.decodeRequest(requestResponse.request());
        if (decoded.isEmpty() || !requestResponse.hasResponse())
        {
            return List.of();
        }
        GraphQLHunterModels.ScanRequest request = decoded.get().request();
        List<GraphQLHunterModels.Finding> findings = new ArrayList<>();
        String responseBody = requestResponse.response().bodyToString();
        String lowerBody = responseBody.toLowerCase(Locale.ROOT);
        if (STACK_TRACE.matcher(responseBody).find())
        {
            findings.add(finding(
                "Stack Trace Disclosure",
                "info_disclosure",
                GraphQLHunterModels.FindingSeverity.MEDIUM,
                GraphQLHunterModels.FindingStatus.CONFIRMED,
                "Observed GraphQL response included stack-trace-like diagnostics.",
                "Stack traces reveal internal implementation details that help attackers refine follow-up attacks.",
                "Suppress stack traces in production responses."
            ));
        }
        if (lowerBody.contains("did you mean") || lowerBody.contains("suggest"))
        {
            findings.add(finding(
                "Field Suggestion Hints Enabled",
                "info_disclosure",
                GraphQLHunterModels.FindingSeverity.LOW,
                GraphQLHunterModels.FindingStatus.CONFIRMED,
                "Observed GraphQL errors included field suggestion hints.",
                "Field suggestions help attackers enumerate schemas through typo-guided discovery.",
                "Disable schema suggestion hints in production when possible."
            ));
        }
        if (request.query != null && (request.query.contains("__schema") || request.query.contains("__type")) && responseBody.contains("__schema"))
        {
            findings.add(finding(
                "Observed GraphQL Introspection Response",
                "introspection",
                GraphQLHunterModels.FindingSeverity.MEDIUM,
                GraphQLHunterModels.FindingStatus.CONFIRMED,
                "Observed traffic already returned GraphQL introspection data.",
                "Schema disclosure accelerates reconnaissance and exploit development.",
                "Disable or restrict introspection in production."
            ));
        }
        if (hasTracingMetadata(requestResponse.response().headers(), responseBody))
        {
            findings.add(finding(
                "Debug or Tracing Metadata Exposed",
                "info_disclosure",
                GraphQLHunterModels.FindingSeverity.LOW,
                GraphQLHunterModels.FindingStatus.CONFIRMED,
                "Observed response exposed tracing or debug metadata.",
                "Tracing metadata can reveal execution details and backend internals.",
                "Disable debug and tracing metadata in production."
            ));
        }
        findings.addAll(jwtFindings(request));
        List<AuditIssue> issues = findings.stream()
            .map(finding -> issuePublisher.toAuditIssue(request, finding, List.of(requestResponse)))
            .toList();
        return issues;
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue)
    {
        return existingIssue.name().equals(newIssue.name()) ? ConsolidationAction.KEEP_EXISTING : ConsolidationAction.KEEP_BOTH;
    }

    private List<GraphQLHunterModels.Finding> jwtFindings(GraphQLHunterModels.ScanRequest request)
    {
        String token = null;
        for (Map.Entry<String, String> entry : request.headers.entrySet())
        {
            if ("Authorization".equalsIgnoreCase(entry.getKey()) && entry.getValue().startsWith("Bearer "))
            {
                token = entry.getValue().substring("Bearer ".length()).trim();
                break;
            }
            if ("Token".equalsIgnoreCase(entry.getKey()))
            {
                token = entry.getValue().trim();
                break;
            }
        }
        if (token == null || token.chars().filter(character -> character == '.').count() != 2)
        {
            return List.of();
        }
        try
        {
            String[] parts = token.split("\\.");
            String payloadJson = new String(Base64.getUrlDecoder().decode(pad(parts[1])), StandardCharsets.UTF_8);
            @SuppressWarnings("unchecked")
            Map<String, Object> payload = graphqlhunter.GraphQLHunterJson.readMap(payloadJson);
            Object exp = payload.get("exp");
            Object iat = payload.get("iat");
            List<GraphQLHunterModels.Finding> findings = new ArrayList<>();
            if (exp != null)
            {
                long current = Instant.now().getEpochSecond();
                long expires = Long.parseLong(String.valueOf(exp));
                if (expires < current)
                {
                    findings.add(finding(
                        "Expired JWT Token Detected",
                        "jwt",
                        GraphQLHunterModels.FindingSeverity.MEDIUM,
                        GraphQLHunterModels.FindingStatus.CONFIRMED,
                        "Observed JWT appears expired based on its exp claim.",
                        "If the server still honors expired tokens, stale credentials can be replayed indefinitely.",
                        "Validate the exp claim on every request and reject expired tokens."
                    ));
                }
                else if (iat != null)
                {
                    long lifetime = expires - Long.parseLong(String.valueOf(iat));
                    if (lifetime > 24 * 3600)
                    {
                        findings.add(finding(
                            "Long-Lived JWT Token",
                            "jwt",
                            GraphQLHunterModels.FindingSeverity.LOW,
                            GraphQLHunterModels.FindingStatus.POTENTIAL,
                            "Observed JWT appears to have a long access-token lifetime.",
                            "Long-lived tokens increase the blast radius of token compromise.",
                            "Prefer shorter-lived access tokens with refresh-token rotation."
                        ));
                    }
                }
            }
            return findings;
        }
        catch (Exception ignored)
        {
            return List.of();
        }
    }

    private String pad(String value)
    {
        int padding = (4 - value.length() % 4) % 4;
        return value + "=".repeat(padding);
    }

    private boolean hasTracingMetadata(List<HttpHeader> headers, String body)
    {
        for (HttpHeader header : headers)
        {
            String key = header.name().toLowerCase(Locale.ROOT);
            if (key.startsWith("x-debug") || key.equals("x-apollo-tracing") || key.equals("x-graphql-tracing"))
            {
                return true;
            }
        }
        return body.toLowerCase(Locale.ROOT).contains("\"extensions\"");
    }

    private GraphQLHunterModels.Finding finding(
        String title,
        String scanner,
        GraphQLHunterModels.FindingSeverity severity,
        GraphQLHunterModels.FindingStatus status,
        String description,
        String impact,
        String remediation
    )
    {
        GraphQLHunterModels.Finding finding = new GraphQLHunterModels.Finding();
        finding.title = title;
        finding.scanner = scanner;
        finding.severity = severity;
        finding.status = status;
        finding.description = description;
        finding.impact = impact;
        finding.remediation = remediation;
        return finding;
    }
}
