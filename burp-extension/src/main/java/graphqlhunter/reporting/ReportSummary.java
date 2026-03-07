package graphqlhunter.reporting;

import java.util.LinkedHashMap;
import java.util.Map;

public final class ReportSummary
{
    public int total;
    public Map<String, Integer> bySeverity = new LinkedHashMap<>();
    public Map<String, Integer> byStatus = new LinkedHashMap<>();
    public Map<String, Integer> confirmedBySeverity = new LinkedHashMap<>();
    public String riskLevel = "MINIMAL";
}
