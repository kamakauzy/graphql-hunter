package graphqlhunter.config;

import graphqlhunter.GraphQLHunterModels;

import java.util.LinkedHashMap;
import java.util.Map;

public final class ScanConfiguration
{
    public String profileName = GraphQLHunterModels.ScanProfile.STANDARD.name();
    public boolean safeMode;
    public double delaySeconds;
    public int timeoutSeconds = 30;
    public int depthLimit = 5;
    public int fieldLimit = 20;
    public boolean enableDos = true;
    public boolean enableDeepInjection = true;
    public boolean enableRateLimitTesting = true;
    public boolean enableCsrfTesting = true;
    public boolean enableFileUploadTesting = true;
    public int batchSize = 10;
    public int bruteForceAttempts = 20;
    public int rateLimitConcurrency = 50;
    public int rateLimitRequests = 100;
    public int maxXssTests = 20;
    public int maxUploadTestSize = 1024;
    public final Map<String, Boolean> scannerEnabled = new LinkedHashMap<>();

    public boolean isScannerEnabled(String scannerName)
    {
        return scannerEnabled.getOrDefault(scannerName, Boolean.TRUE);
    }
}
