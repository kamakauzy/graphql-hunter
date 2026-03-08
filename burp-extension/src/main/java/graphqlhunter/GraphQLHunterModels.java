package graphqlhunter;

import java.util.LinkedHashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Comparator;

public final class GraphQLHunterModels
{
    public static final int MAX_RECENT_REQUESTS = 25;

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
        public String contentType = "application/json";
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
            copy.variables = deepCopyObject(variables);
            copy.operationName = operationName;
            copy.contentType = contentType;
            copy.rawBody = rawBody;
            copy.batch = batch;
            copy.headers = new LinkedHashMap<>(headers);
            return copy;
        }
    }

    public static final class RecentRequestEntry
    {
        public String fingerprint = "";
        public String source = "manual";
        public String url = "";
        public String method = "POST";
        public String operationName = "";
        public String query = "";
        public Object variables = new LinkedHashMap<String, Object>();
        public Map<String, String> headers = new LinkedHashMap<>();
        public boolean batch;
        public String firstSeenAt = "";
        public String lastSeenAt = "";
        public int seenCount = 1;

        public RecentRequestEntry copy()
        {
            RecentRequestEntry copy = new RecentRequestEntry();
            copy.fingerprint = fingerprint;
            copy.source = source;
            copy.url = url;
            copy.method = method;
            copy.operationName = operationName;
            copy.query = query;
            copy.variables = deepCopyObject(variables);
            copy.headers = new LinkedHashMap<>(headers);
            copy.batch = batch;
            copy.firstSeenAt = firstSeenAt;
            copy.lastSeenAt = lastSeenAt;
            copy.seenCount = seenCount;
            return copy;
        }

        public ScanRequest toScanRequest()
        {
            ScanRequest request = new ScanRequest();
            request.source = source;
            request.url = url;
            request.method = method;
            request.query = query;
            request.variables = deepCopyObject(variables);
            request.operationName = operationName;
            request.batch = batch;
            request.headers = new LinkedHashMap<>(headers);
            return request;
        }

        public static RecentRequestEntry fromScanRequest(ScanRequest request, String timestamp)
        {
            RecentRequestEntry entry = new RecentRequestEntry();
            entry.fingerprint = fingerprintFor(request);
            entry.source = request.source;
            entry.url = request.url;
            entry.method = request.method;
            entry.operationName = request.operationName;
            entry.query = request.query;
            entry.variables = deepCopyObject(request.variables);
            entry.headers = new LinkedHashMap<>(request.headers);
            entry.batch = request.batch;
            entry.firstSeenAt = timestamp;
            entry.lastSeenAt = timestamp;
            return entry;
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
        public List<RecentRequestEntry> recentRequests = new ArrayList<>();
        public String scanProfile = ScanProfile.STANDARD.name();
        public ScanSettings scanSettings = new ScanSettings();
        public AuthSettings authSettings = new AuthSettings();

        public ExtensionState copy()
        {
            ExtensionState copy = new ExtensionState();
            copy.lastRequest = lastRequest == null ? new ScanRequest() : lastRequest.copy();
            recentRequests.forEach(entry -> copy.recentRequests.add(entry.copy()));
            copy.scanProfile = scanProfile;
            copy.scanSettings = scanSettings == null ? new ScanSettings() : scanSettings.copy();
            copy.authSettings = authSettings == null ? new AuthSettings() : authSettings.copy();
            return copy;
        }
    }

    public static final class ScannerSkip
    {
        public String scanner = "";
        public String reason = "";

        public ScannerSkip()
        {
        }

        public ScannerSkip(String scanner, String reason)
        {
            this.scanner = scanner;
            this.reason = reason;
        }
    }

    public static final class ScannerFailure
    {
        public String scanner = "";
        public String error = "";

        public ScannerFailure()
        {
        }

        public ScannerFailure(String scanner, String error)
        {
            this.scanner = scanner;
            this.error = error;
        }
    }

    public static final class ScanExecutionResult
    {
        public ScanRequest request = new ScanRequest();
        public ScanSettings settings = new ScanSettings();
        public List<Finding> findings = new ArrayList<>();
        public List<String> executedScanners = new ArrayList<>();
        public List<ScannerSkip> skippedScanners = new ArrayList<>();
        public List<ScannerFailure> failedScanners = new ArrayList<>();
        public String status = "completed";
        public String timestamp = "";
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
        public String authConfigPath = "";
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
            copy.authConfigPath = authConfigPath;
            copy.detectFailures = detectFailures;
            copy.authVars = new LinkedHashMap<>(authVars);
            copy.staticHeaders = new LinkedHashMap<>(staticHeaders);
            copy.importedAuthHeaders = new LinkedHashMap<>(importedAuthHeaders);
            copy.runtimeOnlySecrets = new LinkedHashMap<>(runtimeOnlySecrets);
            return copy;
        }
    }

    @SuppressWarnings("unchecked")
    private static Object deepCopyObject(Object value)
    {
        if (value == null)
        {
            return null;
        }
        return GraphQLHunterJson.mapper().convertValue(
            GraphQLHunterJson.mapper().valueToTree(value),
            Object.class
        );
    }

    public static String fingerprintFor(ScanRequest request)
    {
        String input = normalizeMethod(request.method) + "\n"
            + normalizeUrl(request.url) + "\n"
            + (request.batch ? "1" : "0") + "\n"
            + normalizeText(request.operationName) + "\n"
            + normalizeQuery(request.query) + "\n"
            + canonicalVariables(request.variables);
        try
        {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder();
            for (byte value : hash)
            {
                builder.append(String.format("%02x", value));
            }
            return builder.toString();
        }
        catch (Exception exception)
        {
            return Integer.toHexString(input.hashCode());
        }
    }

    private static String normalizeMethod(String method)
    {
        return method == null ? "POST" : method.trim().toUpperCase();
    }

    private static String normalizeUrl(String value)
    {
        if (value == null || value.isBlank())
        {
            return "";
        }
        try
        {
            URI uri = new URI(value);
            String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase();
            String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase();
            int port = uri.getPort();
            boolean defaultPort = (port == 80 && "http".equals(scheme)) || (port == 443 && "https".equals(scheme));
            String authority = port == -1 || defaultPort ? host : host + ":" + port;
            List<String> params = new ArrayList<>();
            if (uri.getQuery() != null && !uri.getQuery().isBlank())
            {
                for (String pair : uri.getQuery().split("&"))
                {
                    params.add(pair);
                }
                params.sort(Comparator.naturalOrder());
            }
            return scheme + "://" + authority + (uri.getPath() == null ? "" : uri.getPath())
                + (params.isEmpty() ? "" : "?" + String.join("&", params));
        }
        catch (URISyntaxException exception)
        {
            return value.trim();
        }
    }

    private static String normalizeQuery(String query)
    {
        if (query == null)
        {
            return "";
        }
        return query.replace("\r\n", "\n")
            .replace('\r', '\n')
            .strip();
    }

    private static String normalizeText(String value)
    {
        return value == null ? "" : value.trim();
    }

    private static String canonicalVariables(Object variables)
    {
        if (variables == null)
        {
            return "";
        }
        try
        {
            return GraphQLHunterJson.mapper().writeValueAsString(
                GraphQLHunterJson.mapper().readTree(GraphQLHunterJson.mapper().writeValueAsString(variables))
            );
        }
        catch (Exception exception)
        {
            return String.valueOf(variables);
        }
    }
}
