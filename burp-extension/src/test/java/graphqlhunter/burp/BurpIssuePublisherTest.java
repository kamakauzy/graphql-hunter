package graphqlhunter.burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.sitemap.SiteMap;
import burp.api.montoya.sitemap.SiteMapFilter;
import graphqlhunter.GraphQLHunterModels;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BurpIssuePublisherTest
{
    @Test
    void mapsFindingSeverityAndStatusToBurpIssueMetadata()
    {
        BurpIssuePublisher publisher = publisher(new FakeSiteMap());

        AuditIssue confirmed = publisher.toAuditIssue(request(), finding(
            GraphQLHunterModels.FindingSeverity.HIGH,
            GraphQLHunterModels.FindingStatus.CONFIRMED,
            "Confirmed issue"
        ));
        AuditIssue review = publisher.toAuditIssue(request(), finding(
            GraphQLHunterModels.FindingSeverity.INFO,
            GraphQLHunterModels.FindingStatus.MANUAL_REVIEW,
            "Review issue"
        ));

        assertEquals(AuditIssueSeverity.HIGH, confirmed.severity());
        assertEquals(AuditIssueConfidence.CERTAIN, confirmed.confidence());
        assertEquals(AuditIssueSeverity.INFORMATION, review.severity());
        assertEquals(AuditIssueConfidence.TENTATIVE, review.confidence());
    }

    @Test
    void includesRedactedEvidenceAndReplayContentInIssueDetail()
    {
        BurpIssuePublisher publisher = publisher(new FakeSiteMap());
        GraphQLHunterModels.Finding finding = finding(
            GraphQLHunterModels.FindingSeverity.HIGH,
            GraphQLHunterModels.FindingStatus.CONFIRMED,
            "Nested secret issue"
        );
        finding.evidence.put("headers", Map.of("Authorization", "Bearer secret-token-value"));
        finding.evidence.put("nested", List.of(Map.of("password", "super-secret")));
        finding.proof = "Authorization: Bearer secret-token-value";

        AuditIssue issue = publisher.toAuditIssue(request(), finding);

        assertTrue(issue.detail().contains("***REDACTED***"));
        assertTrue(issue.detail().contains("Replay Request"));
        assertTrue(issue.detail().contains("Authorization"));
        assertTrue(issue.baseUrl().contains("https://api.example.com/graphql"));
    }

    @Test
    void publishesOneAuditIssuePerFindingToSiteMap()
    {
        FakeSiteMap siteMap = new FakeSiteMap();
        BurpIssuePublisher publisher = publisher(siteMap);

        int published = publisher.publish(request(), List.of(
            finding(GraphQLHunterModels.FindingSeverity.MEDIUM, GraphQLHunterModels.FindingStatus.CONFIRMED, "One"),
            finding(GraphQLHunterModels.FindingSeverity.LOW, GraphQLHunterModels.FindingStatus.POTENTIAL, "Two")
        ));

        assertEquals(2, published);
        assertEquals(2, siteMap.issues.size());
        assertEquals("One", siteMap.issues.getFirst().name());
    }

    private BurpIssuePublisher publisher(FakeSiteMap siteMap)
    {
        return new BurpIssuePublisher(
            siteMap,
            null,
            FakeAuditIssue::new,
            (request, finding) -> List.of()
        );
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

    private GraphQLHunterModels.Finding finding(GraphQLHunterModels.FindingSeverity severity, GraphQLHunterModels.FindingStatus status, String title)
    {
        GraphQLHunterModels.Finding finding = new GraphQLHunterModels.Finding();
        finding.title = title;
        finding.scanner = "jwt";
        finding.severity = severity;
        finding.status = status;
        finding.description = "desc";
        finding.impact = "impact";
        finding.remediation = "fix";
        return finding;
    }

    private static final class FakeSiteMap implements SiteMap
    {
        private final List<AuditIssue> issues = new ArrayList<>();

        @Override
        public List<HttpRequestResponse> requestResponses(SiteMapFilter filter)
        {
            return List.of();
        }

        @Override
        public List<HttpRequestResponse> requestResponses()
        {
            return List.of();
        }

        @Override
        public List<AuditIssue> issues(SiteMapFilter filter)
        {
            return new ArrayList<>(issues);
        }

        @Override
        public List<AuditIssue> issues()
        {
            return new ArrayList<>(issues);
        }

        @Override
        public void add(HttpRequestResponse requestResponse)
        {
        }

        @Override
        public void add(AuditIssue auditIssue)
        {
            issues.add(auditIssue);
        }
    }

    private static final class FakeAuditIssue implements AuditIssue
    {
        private final String name;
        private final String detail;
        private final String remediation;
        private final String baseUrl;
        private final AuditIssueSeverity severity;
        private final AuditIssueConfidence confidence;

        private FakeAuditIssue(
            String name,
            String detail,
            String remediation,
            String baseUrl,
            AuditIssueSeverity severity,
            AuditIssueConfidence confidence,
            String background,
            String remediationBackground,
            List<HttpRequestResponse> requestResponses
        )
        {
            this.name = name;
            this.detail = detail;
            this.remediation = remediation;
            this.baseUrl = baseUrl;
            this.severity = severity;
            this.confidence = confidence;
        }

        @Override
        public String name()
        {
            return name;
        }

        @Override
        public String detail()
        {
            return detail;
        }

        @Override
        public String remediation()
        {
            return remediation;
        }

        @Override
        public burp.api.montoya.http.HttpService httpService()
        {
            return null;
        }

        @Override
        public String baseUrl()
        {
            return baseUrl;
        }

        @Override
        public AuditIssueSeverity severity()
        {
            return severity;
        }

        @Override
        public AuditIssueConfidence confidence()
        {
            return confidence;
        }

        @Override
        public List<HttpRequestResponse> requestResponses()
        {
            return List.of();
        }

        @Override
        public List<burp.api.montoya.collaborator.Interaction> collaboratorInteractions()
        {
            return List.of();
        }

        @Override
        public AuditIssueDefinition definition()
        {
            return null;
        }
    }
}
