package graphqlhunter.reporting;

import graphqlhunter.GraphQLHunterJson;
import graphqlhunter.GraphQLHunterModels;
import graphqlhunter.auth.AuthRedactor;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class ReportingService
{
    private final AuthRedactor redactor = new AuthRedactor();

    public ReportSummary summarize(List<GraphQLHunterModels.Finding> findings)
    {
        ReportSummary summary = new ReportSummary();
        summary.bySeverity.put("CRITICAL", 0);
        summary.bySeverity.put("HIGH", 0);
        summary.bySeverity.put("MEDIUM", 0);
        summary.bySeverity.put("LOW", 0);
        summary.bySeverity.put("INFO", 0);
        summary.byStatus.put("confirmed", 0);
        summary.byStatus.put("potential", 0);
        summary.byStatus.put("manual_review", 0);
        summary.confirmedBySeverity.put("CRITICAL", 0);
        summary.confirmedBySeverity.put("HIGH", 0);
        summary.confirmedBySeverity.put("MEDIUM", 0);
        summary.confirmedBySeverity.put("LOW", 0);
        summary.confirmedBySeverity.put("INFO", 0);

        for (GraphQLHunterModels.Finding finding : findings)
        {
            String severity = finding.severity.name();
            String status = finding.status.name().toLowerCase();
            summary.bySeverity.computeIfPresent(severity, (key, value) -> value + 1);
            summary.byStatus.computeIfPresent(status, (key, value) -> value + 1);
            if (finding.status == GraphQLHunterModels.FindingStatus.CONFIRMED)
            {
                summary.confirmedBySeverity.computeIfPresent(severity, (key, value) -> value + 1);
            }
        }

        summary.total = findings.size();
        if (summary.confirmedBySeverity.get("CRITICAL") > 0)
        {
            summary.riskLevel = "CRITICAL";
        }
        else if (summary.confirmedBySeverity.get("HIGH") > 0)
        {
            summary.riskLevel = "HIGH";
        }
        else if (summary.confirmedBySeverity.get("MEDIUM") > 0)
        {
            summary.riskLevel = "MEDIUM";
        }
        else if (summary.confirmedBySeverity.get("LOW") > 0)
        {
            summary.riskLevel = "LOW";
        }
        else if (summary.byStatus.get("manual_review") > 0 || summary.byStatus.get("potential") > 0)
        {
            summary.riskLevel = "REVIEW_REQUIRED";
        }
        return summary;
    }

    public String toJsonReport(String target, String profile, List<GraphQLHunterModels.Finding> findings)
    {
        ReportSummary summary = summarize(findings);
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("metadata", Map.of(
            "target", target,
            "profile", profile,
            "timestamp", Instant.now().toString()
        ));
        report.put("summary", summary);
        report.put("findings", findings.stream().map(finding -> redactor.sanitizeFinding(finding, java.util.Set.of())).toList());
        return GraphQLHunterJson.write(report);
    }

    public String toHtmlReport(String target, String profile, List<GraphQLHunterModels.Finding> findings)
    {
        ReportSummary summary = summarize(findings);
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>GraphQL Hunter Report</title></head><body>");
        html.append("<h1>GraphQL Hunter Report</h1>");
        html.append("<p>Target: ").append(escape(target)).append("</p>");
        html.append("<p>Profile: ").append(escape(profile)).append("</p>");
        html.append("<p>Risk Level: ").append(escape(summary.riskLevel)).append("</p>");
        html.append("<p>Total Findings: ").append(summary.total).append("</p>");
        html.append("<ul>");
        findings.forEach(finding ->
        {
            GraphQLHunterModels.Finding safe = redactor.sanitizeFinding(finding, java.util.Set.of());
            html.append("<li><strong>")
                .append(escape(safe.title))
                .append("</strong> [")
                .append(escape(safe.severity.name()))
                .append(" / ")
                .append(escape(safe.status.name()))
                .append("] - ")
                .append(escape(safe.description))
                .append("</li>");
        });
        html.append("</ul></body></html>");
        return html.toString();
    }

    private String escape(String text)
    {
        if (text == null)
        {
            return "";
        }
        return text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#x27;");
    }
}
