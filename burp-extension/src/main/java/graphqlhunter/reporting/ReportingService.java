package graphqlhunter.reporting;

import graphqlhunter.GraphQLHunterJson;
import graphqlhunter.GraphQLHunterModels;
import graphqlhunter.GraphQLHunterModels.ScanExecutionResult;
import graphqlhunter.auth.AuthRedactor;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

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
        GraphQLHunterModels.ScanRequest request = new GraphQLHunterModels.ScanRequest();
        request.url = target;
        GraphQLHunterModels.ScanSettings settings = new GraphQLHunterModels.ScanSettings();
        settings.profileName = profile;
        return toJsonReport(request, settings, findings);
    }

    public String toJsonReport(GraphQLHunterModels.ScanRequest request, GraphQLHunterModels.ScanSettings settings, List<GraphQLHunterModels.Finding> findings)
    {
        ScanExecutionResult result = syntheticResult(request, settings, findings);
        return toJsonReport(result);
    }

    public String toJsonReport(ScanExecutionResult result)
    {
        ScanExecutionResult normalized = normalizeResult(result);
        ReportSummary summary = summarize(normalized.findings);
        List<Map<String, Object>> exportedFindings = exportFindings(normalized.request, normalized.findings);
        Map<String, Object> report = new LinkedHashMap<>();
        LinkedHashMap<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("target", normalized.request.url == null ? "" : normalized.request.url);
        metadata.put("profile", normalized.settings.profileName == null ? "" : normalized.settings.profileName);
        metadata.put("safe_mode", normalized.settings.safeMode);
        metadata.put("status", normalized.status);
        metadata.put("timestamp", normalized.timestamp);
        metadata.put("executed_scanners", normalized.executedScanners);
        metadata.put("skipped_scanners", exportSkippedScanners(normalized));
        metadata.put("failed_scanners", exportFailedScanners(normalized));
        report.put("metadata", metadata);
        report.put("summary", summaryMap(summary));
        report.put("scan", scanMetadata(normalized));
        report.put("errors", exportFailedScanners(normalized));
        report.put("findings", exportedFindings);
        return GraphQLHunterJson.write(report);
    }

    public String toHtmlReport(String target, String profile, List<GraphQLHunterModels.Finding> findings)
    {
        GraphQLHunterModels.ScanRequest request = new GraphQLHunterModels.ScanRequest();
        request.url = target;
        GraphQLHunterModels.ScanSettings settings = new GraphQLHunterModels.ScanSettings();
        settings.profileName = profile;
        return toHtmlReport(request, settings, findings);
    }

    public String toHtmlReport(GraphQLHunterModels.ScanRequest request, GraphQLHunterModels.ScanSettings settings, List<GraphQLHunterModels.Finding> findings)
    {
        return toHtmlReport(syntheticResult(request, settings, findings));
    }

    public String toHtmlReport(ScanExecutionResult result)
    {
        ScanExecutionResult normalized = normalizeResult(result);
        ReportSummary summary = summarize(normalized.findings);
        List<Map<String, Object>> exportedFindings = exportFindings(normalized.request, normalized.findings);
        StringBuilder html = new StringBuilder();
        String scanners = exportedFindings.stream()
            .map(finding -> String.valueOf(finding.getOrDefault("scanner", "")))
            .filter(scanner -> !scanner.isBlank())
            .distinct()
            .sorted()
            .map(scanner -> "<option value=\"" + escape(scanner) + "\">" + escape(scanner) + "</option>")
            .collect(Collectors.joining());

        html.append("""
            <!DOCTYPE html>
            <html>
            <head>
              <meta charset="UTF-8">
              <title>GraphQL Hunter Report</title>
              <style>
                body { font-family: Arial, sans-serif; margin: 20px; color: #222; }
                .summary { display: grid; grid-template-columns: repeat(4, minmax(140px, 1fr)); gap: 12px; margin-bottom: 20px; }
                .card { border: 1px solid #ddd; border-radius: 8px; padding: 12px; background: #fafafa; }
                .filters { display: flex; gap: 12px; flex-wrap: wrap; margin: 16px 0; }
                .finding { border: 1px solid #ddd; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
                .badge { display: inline-block; margin-right: 8px; padding: 2px 8px; border-radius: 999px; background: #eee; font-size: 12px; }
                pre { white-space: pre-wrap; word-break: break-word; background: #f6f8fa; padding: 10px; border-radius: 6px; }
                h1, h2, h3 { margin-bottom: 8px; }
                .meta { color: #555; margin-bottom: 12px; }
              </style>
              <script>
                function applyFilters() {
                  const severity = document.getElementById('severityFilter').value;
                  const status = document.getElementById('statusFilter').value;
                  const scanner = document.getElementById('scannerFilter').value;
                  const search = document.getElementById('searchFilter').value.toLowerCase();
                  document.querySelectorAll('.finding').forEach(node => {
                    const matchesSeverity = !severity || node.dataset.severity === severity;
                    const matchesStatus = !status || node.dataset.status === status;
                    const matchesScanner = !scanner || node.dataset.scanner === scanner;
                    const matchesSearch = !search || node.innerText.toLowerCase().includes(search);
                    node.style.display = matchesSeverity && matchesStatus && matchesScanner && matchesSearch ? '' : 'none';
                  });
                }
              </script>
            </head>
            <body>
            """);
        html.append("<h1>GraphQL Hunter Report</h1>");
        html.append("<div class=\"meta\">Target: ").append(escape(normalized.request.url == null ? "" : normalized.request.url)).append("<br>");
        html.append("Profile: ").append(escape(normalized.settings.profileName == null ? "" : normalized.settings.profileName)).append("<br>");
        html.append("Safe mode: ").append(normalized.settings.safeMode).append("<br>");
        html.append("Scan status: ").append(escape(normalized.status)).append("<br>");
        html.append("Timestamp: ").append(escape(normalized.timestamp)).append("<br>");
        html.append("Risk Level: ").append(escape(summary.riskLevel)).append("</div>");
        html.append("<div class=\"summary\">");
        html.append(card("Total Findings", String.valueOf(summary.total)));
        html.append(card("Confirmed", String.valueOf(summary.byStatus.getOrDefault("confirmed", 0))));
        html.append(card("Potential", String.valueOf(summary.byStatus.getOrDefault("potential", 0))));
        html.append(card("Manual Review", String.valueOf(summary.byStatus.getOrDefault("manual_review", 0))));
        html.append("</div>");
        html.append("<div class=\"meta\">Executed scanners: ")
            .append(escape(String.valueOf(normalized.executedScanners.size())))
            .append(" | Skipped scanners: ")
            .append(escape(String.valueOf(normalized.skippedScanners.size())))
            .append(" | Failed scanners: ")
            .append(escape(String.valueOf(normalized.failedScanners.size())))
            .append("</div>");
        appendSection(html, "Executed Scanners", String.join("\n", normalized.executedScanners));
        appendSection(html, "Skipped Scanners", GraphQLHunterJson.write(exportSkippedScanners(normalized)));
        appendSection(html, "Failed Scanners", GraphQLHunterJson.write(exportFailedScanners(normalized)));
        html.append("""
            <div class="filters">
              <label>Severity
                <select id="severityFilter" onchange="applyFilters()">
                  <option value="">All</option>
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                  <option value="INFO">INFO</option>
                </select>
              </label>
              <label>Status
                <select id="statusFilter" onchange="applyFilters()">
                  <option value="">All</option>
                  <option value="confirmed">confirmed</option>
                  <option value="potential">potential</option>
                  <option value="manual_review">manual_review</option>
                </select>
              </label>
              <label>Scanner
                <select id="scannerFilter" onchange="applyFilters()">
                  <option value="">All</option>
            """);
        html.append(scanners);
        html.append("""
                </select>
              </label>
              <label>Search
                <input id="searchFilter" type="text" oninput="applyFilters()">
              </label>
            </div>
            <h2>Findings</h2>
            """);

        exportedFindings.forEach(finding ->
        {
            html.append("<div class=\"finding\" data-severity=\"")
                .append(escape(String.valueOf(finding.get("severity"))))
                .append("\" data-status=\"")
                .append(escape(String.valueOf(finding.get("status"))))
                .append("\" data-scanner=\"")
                .append(escape(String.valueOf(finding.get("scanner"))))
                .append("\">");
            html.append("<h3>").append(escape(String.valueOf(finding.get("title")))).append("</h3>");
            html.append("<div class=\"meta\">")
                .append("<span class=\"badge\">Severity: ").append(escape(String.valueOf(finding.get("severity")))).append("</span>")
                .append("<span class=\"badge\">Status: ").append(escape(String.valueOf(finding.get("status")))).append("</span>")
                .append("<span class=\"badge\">Scanner: ").append(escape(String.valueOf(finding.get("scanner")))).append("</span>")
                .append("</div>");
            appendSection(html, "Description", finding.get("description"));
            appendSection(html, "Impact", finding.get("impact"));
            appendSection(html, "Remediation", finding.get("remediation"));
            appendSection(html, "Evidence", GraphQLHunterJson.write(finding.getOrDefault("evidence", Map.of())));
            appendSection(html, "Proof of Concept", finding.get("poc"));
            appendSection(html, "Request", GraphQLHunterJson.write(finding.get("request")));
            appendSection(html, "cURL Command", finding.get("curl_command"));
            appendSection(html, "Burp Suite Request", finding.get("burp_request"));
            html.append("</div>");
        });
        html.append("</body></html>");
        return html.toString();
    }

    private List<Map<String, Object>> exportFindings(GraphQLHunterModels.ScanRequest request, List<GraphQLHunterModels.Finding> findings)
    {
        List<GraphQLHunterModels.Finding> ordered = new ArrayList<>(findings);
        ordered.sort(Comparator.comparingInt(this::severityRank));
        return ordered.stream().map(finding -> exportFinding(request, finding)).toList();
    }

    private Map<String, Object> exportFinding(GraphQLHunterModels.ScanRequest request, GraphQLHunterModels.Finding finding)
    {
        GraphQLHunterModels.Finding safe = redactor.sanitizeFinding(finding, java.util.Set.of());
        LinkedHashMap<String, Object> exported = new LinkedHashMap<>();
        exported.put("title", safe.title);
        exported.put("scanner", safe.scanner);
        exported.put("severity", safe.severity.name());
        exported.put("status", safe.status.name().toLowerCase(Locale.ROOT));
        exported.put("description", safe.description);
        exported.put("impact", safe.impact);
        exported.put("remediation", safe.remediation);
        exported.put("proof", safe.proof);
        exported.put("poc", safe.proof);
        exported.put("request_snippet", safe.requestSnippet);
        exported.put("evidence", safe.evidence);

        if (request != null && request.url != null && !request.url.isBlank())
        {
            Map<String, Object> replayRequest = buildReplayRequest(request, safe);
            exported.put("request", replayRequest);
            exported.put("curl_command", generateCurlCommand(request.url, replayRequest));
            exported.put("burp_request", generateBurpRequest(request.url, replayRequest));
        }

        return exported;
    }

    private Map<String, Object> summaryMap(ReportSummary summary)
    {
        LinkedHashMap<String, Object> map = new LinkedHashMap<>();
        map.put("total", summary.total);
        map.put("by_severity", summary.bySeverity);
        map.put("by_status", summary.byStatus);
        map.put("confirmed_by_severity", summary.confirmedBySeverity);
        map.put("risk_level", summary.riskLevel);
        map.put("manual_verification_required", summary.byStatus.getOrDefault("manual_review", 0));
        map.put("bySeverity", summary.bySeverity);
        map.put("byStatus", summary.byStatus);
        map.put("confirmedBySeverity", summary.confirmedBySeverity);
        map.put("riskLevel", summary.riskLevel);
        return map;
    }

    private Map<String, Object> scanMetadata(ScanExecutionResult result)
    {
        return Map.of(
            "status", result.status,
            "executed_scanners", result.executedScanners,
            "skipped_scanners", exportSkippedScanners(result),
            "failed_scanners", exportFailedScanners(result)
        );
    }

    private List<Map<String, String>> exportSkippedScanners(ScanExecutionResult result)
    {
        return result.skippedScanners.stream()
            .map(skip -> Map.of(
                "scanner", skip.scanner == null ? "" : skip.scanner,
                "reason", skip.reason == null ? "" : skip.reason
            ))
            .toList();
    }

    private List<Map<String, String>> exportFailedScanners(ScanExecutionResult result)
    {
        return result.failedScanners.stream()
            .map(failure -> Map.of(
                "scanner", failure.scanner == null ? "" : failure.scanner,
                "error", failure.error == null ? "" : failure.error
            ))
            .toList();
    }

    private ScanExecutionResult syntheticResult(
        GraphQLHunterModels.ScanRequest request,
        GraphQLHunterModels.ScanSettings settings,
        List<GraphQLHunterModels.Finding> findings
    )
    {
        ScanExecutionResult result = new ScanExecutionResult();
        result.request = request == null ? new GraphQLHunterModels.ScanRequest() : request.copy();
        result.settings = settings == null ? new GraphQLHunterModels.ScanSettings() : settings.copy();
        result.findings = findings == null ? List.of() : new ArrayList<>(findings);
        result.status = "completed";
        result.timestamp = Instant.now().toString();
        result.executedScanners = result.findings.stream()
            .map(finding -> finding.scanner)
            .filter(scanner -> scanner != null && !scanner.isBlank())
            .distinct()
            .toList();
        return result;
    }

    private ScanExecutionResult normalizeResult(ScanExecutionResult result)
    {
        if (result == null)
        {
            return syntheticResult(new GraphQLHunterModels.ScanRequest(), new GraphQLHunterModels.ScanSettings(), List.of());
        }
        if (result.request == null)
        {
            result.request = new GraphQLHunterModels.ScanRequest();
        }
        if (result.settings == null)
        {
            result.settings = new GraphQLHunterModels.ScanSettings();
        }
        if (result.findings == null)
        {
            result.findings = new ArrayList<>();
        }
        if (result.executedScanners == null)
        {
            result.executedScanners = new ArrayList<>();
        }
        if (result.skippedScanners == null)
        {
            result.skippedScanners = new ArrayList<>();
        }
        if (result.failedScanners == null)
        {
            result.failedScanners = new ArrayList<>();
        }
        if (result.status == null || result.status.isBlank())
        {
            result.status = result.failedScanners.isEmpty() ? "completed" : "partial";
        }
        if (result.timestamp == null || result.timestamp.isBlank())
        {
            result.timestamp = Instant.now().toString();
        }
        return result;
    }

    private Map<String, Object> buildReplayRequest(GraphQLHunterModels.ScanRequest request, GraphQLHunterModels.Finding finding)
    {
        LinkedHashMap<String, Object> replay = new LinkedHashMap<>();
        replay.put("method", request.method == null || request.method.isBlank() ? "POST" : request.method.toUpperCase(Locale.ROOT));
        replay.put("headers", redactor.redactHeaders(request.headers, java.util.Set.of()));
        Object body = replayBody(request, finding);
        replay.put("body", body);
        if (body instanceof Map<?, ?> bodyMap)
        {
            if (bodyMap.containsKey("query"))
            {
                replay.put("query", bodyMap.get("query"));
            }
            if (bodyMap.containsKey("variables"))
            {
                replay.put("variables", bodyMap.get("variables"));
            }
            if (bodyMap.containsKey("operationName"))
            {
                replay.put("operationName", bodyMap.get("operationName"));
            }
        }
        return replay;
    }

    private Object replayBody(GraphQLHunterModels.ScanRequest request, GraphQLHunterModels.Finding finding)
    {
        String candidate = firstNonBlank(finding.requestSnippet, finding.proof, request.query);
        Object parsed = tryParseJson(candidate);
        if (parsed instanceof List<?>)
        {
            return redactor.redactObject(parsed, null);
        }
        if (parsed instanceof Map<?, ?> map && (map.containsKey("query") || map.containsKey("variables") || map.containsKey("operationName")))
        {
            return redactor.redactObject(parsed, null);
        }

        LinkedHashMap<String, Object> payload = new LinkedHashMap<>();
        payload.put("query", candidate == null ? "" : candidate);
        payload.put("variables", redactor.redactObject(request.variables, null));
        if (request.operationName != null && !request.operationName.isBlank())
        {
            payload.put("operationName", request.operationName);
        }
        return payload;
    }

    private Object tryParseJson(String candidate)
    {
        if (candidate == null || candidate.isBlank())
        {
            return null;
        }
        String trimmed = candidate.trim();
        if (!(trimmed.startsWith("{") || trimmed.startsWith("[")))
        {
            return null;
        }
        try
        {
            return GraphQLHunterJson.mapper().readValue(trimmed, Object.class);
        }
        catch (Exception ignored)
        {
            return null;
        }
    }

    private String firstNonBlank(String... values)
    {
        for (String value : values)
        {
            if (value != null && !value.isBlank())
            {
                return value;
            }
        }
        return "";
    }

    private int severityRank(GraphQLHunterModels.Finding finding)
    {
        return switch (finding.severity)
        {
            case CRITICAL -> 0;
            case HIGH -> 1;
            case MEDIUM -> 2;
            case LOW -> 3;
            case INFO -> 4;
        };
    }

    private String card(String label, String value)
    {
        return "<div class=\"card\"><strong>" + escape(label) + "</strong><div>" + escape(value) + "</div></div>";
    }

    private void appendSection(StringBuilder html, String title, Object value)
    {
        if (value == null)
        {
            return;
        }
        String text = String.valueOf(value);
        if (text.isBlank() || "null".equals(text))
        {
            return;
        }
        html.append("<h4>").append(escape(title)).append("</h4><pre>").append(escape(text)).append("</pre>");
    }

    private String generateCurlCommand(String url, Map<String, Object> request)
    {
        @SuppressWarnings("unchecked")
        Map<String, String> headers = (Map<String, String>) request.getOrDefault("headers", Map.of());
        String body = GraphQLHunterJson.write(request.get("body"));
        StringBuilder builder = new StringBuilder();
        builder.append("curl -X ").append(escapeShell(String.valueOf(request.getOrDefault("method", "POST")))).append(' ')
            .append(escapeShell(url));
        headers.forEach((key, value) -> builder.append(" \\\n  -H ").append(escapeShell(key + ": " + value)));
        builder.append(" \\\n  -d ").append(escapeShell(body));
        return builder.toString();
    }

    private String generateBurpRequest(String url, Map<String, Object> request)
    {
        java.net.URI uri = java.net.URI.create(url);
        String path = uri.getRawPath() == null || uri.getRawPath().isBlank() ? "/graphql" : uri.getRawPath();
        if (uri.getRawQuery() != null && !uri.getRawQuery().isBlank())
        {
            path += "?" + uri.getRawQuery();
        }
        @SuppressWarnings("unchecked")
        Map<String, String> headers = new LinkedHashMap<>((Map<String, String>) request.getOrDefault("headers", Map.of()));
        headers.putIfAbsent("Host", uri.getAuthority());
        headers.putIfAbsent("Content-Type", "application/json");
        String body = GraphQLHunterJson.write(request.get("body"));
        headers.put("Content-Length", String.valueOf(body.getBytes(java.nio.charset.StandardCharsets.UTF_8).length));
        StringBuilder builder = new StringBuilder();
        builder.append(request.getOrDefault("method", "POST")).append(' ').append(path).append(" HTTP/1.1\n");
        headers.forEach((key, value) -> builder.append(key).append(": ").append(value).append('\n'));
        builder.append('\n').append(body);
        return builder.toString();
    }

    private String escapeShell(String text)
    {
        return "'" + (text == null ? "" : text.replace("'", "'\"'\"'")) + "'";
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
