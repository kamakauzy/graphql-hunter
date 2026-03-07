package graphqlhunter;

import java.util.LinkedHashMap;
import java.util.Map;

public final class GraphQLHunterModels
{
    private GraphQLHunterModels()
    {
    }

    public enum FindingSeverity
    {
        CRITICAL,
        HIGH,
        MEDIUM,
        LOW,
        INFO
    }

    public enum FindingStatus
    {
        CONFIRMED,
        POTENTIAL,
        MANUAL_REVIEW
    }

    public enum ScanProfile
    {
        QUICK,
        STANDARD,
        DEEP,
        STEALTH
    }

    public static final class ScanRequest
    {
        public String source = "manual";
        public String url = "";
        public String method = "POST";
        public String query = "";
        public Object variables = new LinkedHashMap<String, Object>();
        public String operationName = "";
        public String rawBody = "";
        public boolean batch;
        public Map<String, String> headers = new LinkedHashMap<>();

        public ScanRequest copy()
        {
            ScanRequest copy = new ScanRequest();
            copy.source = source;
            copy.url = url;
            copy.method = method;
            copy.query = query;
            copy.variables = variables;
            copy.operationName = operationName;
            copy.rawBody = rawBody;
            copy.batch = batch;
            copy.headers = new LinkedHashMap<>(headers);
            return copy;
        }
    }

    public static final class Finding
    {
        public String title = "";
        public String scanner = "";
        public FindingSeverity severity = FindingSeverity.INFO;
        public FindingStatus status = FindingStatus.POTENTIAL;
        public String description = "";
        public String impact = "";
        public String remediation = "";
        public String proof = "";
        public String requestSnippet = "";
        public Map<String, Object> evidence = new LinkedHashMap<>();

        public String details()
        {
            StringBuilder builder = new StringBuilder();
            builder.append("Title: ").append(title).append(System.lineSeparator());
            builder.append("Scanner: ").append(scanner).append(System.lineSeparator());
            builder.append("Severity: ").append(severity).append(System.lineSeparator());
            builder.append("Status: ").append(status).append(System.lineSeparator()).append(System.lineSeparator());

            if (description != null && !description.isBlank())
            {
                builder.append("Description").append(System.lineSeparator());
                builder.append(description).append(System.lineSeparator()).append(System.lineSeparator());
            }
            if (impact != null && !impact.isBlank())
            {
                builder.append("Impact").append(System.lineSeparator());
                builder.append(impact).append(System.lineSeparator()).append(System.lineSeparator());
            }
            if (remediation != null && !remediation.isBlank())
            {
                builder.append("Remediation").append(System.lineSeparator());
                builder.append(remediation).append(System.lineSeparator()).append(System.lineSeparator());
            }
            if (proof != null && !proof.isBlank())
            {
                builder.append("Proof").append(System.lineSeparator());
                builder.append(proof).append(System.lineSeparator()).append(System.lineSeparator());
            }
            if (requestSnippet != null && !requestSnippet.isBlank())
            {
                builder.append("Request Snippet").append(System.lineSeparator());
                builder.append(requestSnippet).append(System.lineSeparator()).append(System.lineSeparator());
            }
            if (!evidence.isEmpty())
            {
                builder.append("Evidence").append(System.lineSeparator());
                evidence.forEach((key, value) -> builder.append("- ").append(key).append(": ").append(String.valueOf(value)).append(System.lineSeparator()));
            }

            return builder.toString();
        }
    }

    public static final class ExtensionState
    {
        public ScanRequest lastRequest = new ScanRequest();
        public String scanProfile = ScanProfile.STANDARD.name();
        public ScanSettings scanSettings = new ScanSettings();
        public AuthSettings authSettings = new AuthSettings();
    }

    public static final class ScanSettings
    {
        public String profileName = ScanProfile.STANDARD.name();
        public boolean safeMode;
        public Double delaySeconds;
        public Integer bruteForceAttempts;
        public Integer rateLimitConcurrency;
        public Integer rateLimitRequests;
        public Map<String, Boolean> scannerEnabled = new LinkedHashMap<>();

        public ScanSettings copy()
        {
            ScanSettings copy = new ScanSettings();
            copy.profileName = profileName;
            copy.safeMode = safeMode;
            copy.delaySeconds = delaySeconds;
            copy.bruteForceAttempts = bruteForceAttempts;
            copy.rateLimitConcurrency = rateLimitConcurrency;
            copy.rateLimitRequests = rateLimitRequests;
            copy.scannerEnabled = new LinkedHashMap<>(scannerEnabled);
            return copy;
        }
    }

    public static final class AuthSettings
    {
        public String mode = "none";
        public String profileName = "";
        public boolean detectFailures = true;
        public Map<String, String> authVars = new LinkedHashMap<>();
        public Map<String, String> staticHeaders = new LinkedHashMap<>();
        public Map<String, String> importedAuthHeaders = new LinkedHashMap<>();
        public Map<String, String> runtimeOnlySecrets = new LinkedHashMap<>();

        public AuthSettings copy()
        {
            AuthSettings copy = new AuthSettings();
            copy.mode = mode;
            copy.profileName = profileName;
            copy.detectFailures = detectFailures;
            copy.authVars = new LinkedHashMap<>(authVars);
            copy.staticHeaders = new LinkedHashMap<>(staticHeaders);
            copy.importedAuthHeaders = new LinkedHashMap<>(importedAuthHeaders);
            copy.runtimeOnlySecrets = new LinkedHashMap<>(runtimeOnlySecrets);
            return copy;
        }
    }
}
