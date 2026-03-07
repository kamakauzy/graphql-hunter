package graphqlhunter.reporting;

import graphqlhunter.GraphQLHunterModels;
import org.junit.jupiter.api.Test;

import java.util.List;

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

        String html = new ReportingService().toHtmlReport("https://api.example.com/graphql", "quick", List.of(finding));

        assertTrue(html.contains("GraphQL Hunter Report"));
        assertTrue(html.contains("https://api.example.com/graphql"));
        assertTrue(html.contains("GraphQL Introspection Enabled"));
    }

    private GraphQLHunterModels.Finding finding(GraphQLHunterModels.FindingSeverity severity, GraphQLHunterModels.FindingStatus status)
    {
        GraphQLHunterModels.Finding finding = new GraphQLHunterModels.Finding();
        finding.severity = severity;
        finding.status = status;
        return finding;
    }
}
