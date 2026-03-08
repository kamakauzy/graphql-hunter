package graphqlhunter.config;

public final class ProfileSettings
{
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
    public int timeout = 30;
    public double delay = 0.0;
    public String description = "";
}
