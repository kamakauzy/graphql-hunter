package graphqlhunter.reporting;

import graphqlhunter.GraphQLHunterModels;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReportingServiceTest
{
    @Test
    void summaryIncludesStatusesAndConfirmedCounts()
    {
        GraphQLHunterModels.Finding high = finding(GraphQLHunterModels.FindingSeverity.HIGH, GraphQLHunterModels.FindingStatus.CONFIRMED);
        GraphQLHunterModels.Finding medium = finding(GraphQLHunterModels.FindingSeverity.MEDIUM, GraphQLHunterModels.FindingStatus.POTENTIAL);
        GraphQLHunterModels.Finding info = finding(GraphQLHunterModels.FindingSeverity.INFO, GraphQLHunterModels.FindingStatus.MANUAL_REVIEW);

        ReportSummary summary = new ReportingService().summarize(List.of(high, medium, info));

        assertEquals(1, summary.byStatus.get("confirmed"));
        assertEquals(1, summary.byStatus.get("potential"));
        assertEquals(1, summary.byStatus.get("manual_review"));
        assertEquals(1, summary.confirmedBySeverity.get("HIGH"));
        assertEquals("HIGH", summary.riskLevel);
    }

    @Test
    void htmlReportIncludesBasicMetadata()
    {
        GraphQLHunterModels.Finding finding = finding(GraphQLHunterModels.FindingSeverity.MEDIUM, GraphQLHunterModels.FindingStatus.CONFIRMED);
        finding.title = "GraphQL Introspection Enabled";
        finding.description = "desc";
        finding.impact = "impact";
        finding.remediation = "fix it";
        finding.proof = "{ __typename }";
        finding.evidence.put("header", "Authorization");

        String html = new ReportingService().toHtmlReport(request(), settings(), List.of(finding));

        assertTrue(html.contains("GraphQL Hunter Report"));
        assertTrue(html.contains("https://api.example.com/graphql"));
        assertTrue(html.contains("GraphQL Introspection Enabled"));
        assertTrue(html.contains("severityFilter"));
        assertTrue(html.contains("applyFilters()"));
        assertTrue(html.contains("Proof of Concept"));
        assertTrue(html.contains("Scanner:"));
    }

    @Test
    void jsonReportIncludesSummaryAndFindings()
    {
        GraphQLHunterModels.Finding finding = finding(GraphQLHunterModels.FindingSeverity.HIGH, GraphQLHunterModels.FindingStatus.CONFIRMED);
        finding.title = "Possible SQL Injection Behavior";

        String json = new ReportingService().toJsonReport(request(), settings(), List.of(finding));

        assertTrue(json.contains("\"target\""));
        assertTrue(json.contains("\"Possible SQL Injection Behavior\""));
        assertTrue(json.contains("\"risk_level\""));
        assertTrue(json.contains("\"safe_mode\""));
        assertTrue(json.contains("\"executed_scanners\""));
    }

    @Test
    void jsonReportDeepRedactsNestedEvidenceAndReplayArtifacts()
    {
        GraphQLHunterModels.Finding finding = finding(GraphQLHunterModels.FindingSeverity.HIGH, GraphQLHunterModels.FindingStatus.CONFIRMED);
        finding.title = "Nested Secrets";
        finding.proof = "Authorization: Bearer secret-token-value";
        finding.evidence.put("headers", Map.of("Authorization", "Bearer secret-token-value"));
        finding.evidence.put("nested", List.of(Map.of("password", "super-secret")));

        String json = new ReportingService().toJsonReport(request(), settings(), List.of(finding));

        assertTrue(json.contains("***REDACTED***"));
        assertTrue(json.contains("\"headers\""));
        assertTrue(json.contains("\"curl_command\""));
        assertTrue(json.contains("\"burp_request\""));
    }

    private GraphQLHunterModels.ScanRequest request()
    {
        GraphQLHunterModels.ScanRequest request = new GraphQLHunterModels.ScanRequest();
        request.url = "https://api.example.com/graphql";
        request.method = "POST";
        request.query = "{ viewer { id } }";
        request.headers = new LinkedHashMap<>(Map.of("Authorization", "Bearer secret-token-value"));
        request.variables = Map.of("password", "super-secret");
        return request;
    }

    private GraphQLHunterModels.ScanSettings settings()
    {
        GraphQLHunterModels.ScanSettings settings = new GraphQLHunterModels.ScanSettings();
        settings.profileName = "deep";
        settings.safeMode = true;
        return settings;
    }

    private GraphQLHunterModels.Finding finding(GraphQLHunterModels.FindingSeverity severity, GraphQLHunterModels.FindingStatus status)
    {
        GraphQLHunterModels.Finding finding = new GraphQLHunterModels.Finding();
        finding.severity = severity;
        finding.status = status;
        return finding;
    }
}
