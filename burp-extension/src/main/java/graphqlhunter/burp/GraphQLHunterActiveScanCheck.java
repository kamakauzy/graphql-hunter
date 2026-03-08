package graphqlhunter.burp;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import graphqlhunter.GraphQLHunterModels;
import graphqlhunter.GraphQLHunterScanners;

import java.util.List;
import java.util.Optional;

public final class GraphQLHunterActiveScanCheck implements ActiveScanCheck
{
    private final BurpIssuePublisher issuePublisher;
    private final java.util.function.Function<Http, graphqlhunter.GraphQLHunterCore.GraphQLTransport> transportFactory;

    public GraphQLHunterActiveScanCheck(BurpIssuePublisher issuePublisher)
    {
        this(issuePublisher, BurpMontoyaTransport::new);
    }

    GraphQLHunterActiveScanCheck(
        BurpIssuePublisher issuePublisher,
        java.util.function.Function<Http, graphqlhunter.GraphQLHunterCore.GraphQLTransport> transportFactory
    )
    {
        this.issuePublisher = issuePublisher;
        this.transportFactory = transportFactory;
    }

    @Override
    public String checkName()
    {
        return "GraphQL Hunter Active";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse requestResponse, AuditInsertionPoint insertionPoint, Http http)
    {
        return AuditResult.auditResult(issuesFor(requestResponse, http));
    }

    List<AuditIssue> issuesFor(HttpRequestResponse requestResponse, Http http)
    {
        Optional<GraphQLHttpMessageCodec.DecodedRequest> decoded = GraphQLHttpMessageCodec.decodeRequest(requestResponse.request());
        if (decoded.isEmpty())
        {
            return List.of();
        }
        GraphQLHunterModels.ScanRequest request = decoded.get().request();
        GraphQLHunterModels.ScanSettings settings = buildSafeBurpSettings();
        GraphQLHunterModels.ScanExecutionResult result = GraphQLHunterScanners.runWithTransport(
            request,
            graphqlhunter.config.ConfigurationLoader.scanConfiguration(settings),
            transportFactory.apply(http),
            null,
            null
        );
        List<AuditIssue> issues = result.findings.stream()
            .filter(this::isReportableFinding)
            .map(finding -> issuePublisher.toAuditIssue(request, finding, List.of(requestResponse)))
            .toList();
        return issues;
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue)
    {
        return existingIssue.name().equals(newIssue.name()) ? ConsolidationAction.KEEP_EXISTING : ConsolidationAction.KEEP_BOTH;
    }

    private GraphQLHunterModels.ScanSettings buildSafeBurpSettings()
    {
        GraphQLHunterModels.ScanSettings settings = new GraphQLHunterModels.ScanSettings();
        settings.profileName = graphqlhunter.GraphQLHunterModels.ScanProfile.QUICK.name();
        settings.safeMode = true;
        settings.scannerEnabled.put("introspection", true);
        settings.scannerEnabled.put("info_disclosure", true);
        settings.scannerEnabled.put("auth", true);
        settings.scannerEnabled.put("batching", true);
        settings.scannerEnabled.put("jwt", true);
        settings.scannerEnabled.put("injection", false);
        settings.scannerEnabled.put("dos", false);
        settings.scannerEnabled.put("aliasing", false);
        settings.scannerEnabled.put("circular", false);
        settings.scannerEnabled.put("xss", false);
        settings.scannerEnabled.put("rate_limit", false);
        settings.scannerEnabled.put("csrf", false);
        settings.scannerEnabled.put("file_upload", false);
        settings.scannerEnabled.put("mutation_fuzzing", false);
        return settings;
    }

    private boolean isReportableFinding(GraphQLHunterModels.Finding finding)
    {
        return finding != null && switch (finding.title)
        {
            case "GraphQL Schema Summary Available",
                "JWT Token Authentication Detected",
                "Batch Size Limit Enforced",
                "Rate Limiting Detected",
                "Rate Limit Headers Present",
                "Mutation Rate Limiting Detected",
                "CSRF Token Detected",
                "File Upload Mutation Detected" -> false;
            default -> true;
        };
    }
}
