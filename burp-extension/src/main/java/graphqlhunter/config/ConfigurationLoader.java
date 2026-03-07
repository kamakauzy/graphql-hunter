package graphqlhunter.config;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import graphqlhunter.GraphQLHunterModels;

import java.io.InputStream;
import java.util.Locale;
import java.util.Map;

public final class ConfigurationLoader
{
    private static final String PAYLOADS_RESOURCE = "/graphqlhunter/config/payloads.yaml";
    private static final ObjectMapper YAML_MAPPER = new ObjectMapper(new YAMLFactory())
        .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
        .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);

    private static PayloadConfiguration payloadConfiguration;

    private ConfigurationLoader()
    {
    }

    public static synchronized PayloadConfiguration payloads()
    {
        if (payloadConfiguration == null)
        {
            payloadConfiguration = loadYaml(PAYLOADS_RESOURCE, PayloadConfiguration.class);
        }
        return payloadConfiguration;
    }

    public static ScanConfiguration scanConfiguration(GraphQLHunterModels.ScanSettings settings)
    {
        ScanConfiguration configuration = new ScanConfiguration();
        String profileName = settings == null || settings.profileName == null || settings.profileName.isBlank()
            ? GraphQLHunterModels.ScanProfile.STANDARD.name()
            : settings.profileName;
        configuration.profileName = profileName;

        ProfileSettings profile = payloads().profiles.getOrDefault(profileName.toLowerCase(Locale.ROOT), new ProfileSettings());
        configuration.depthLimit = profile.depthLimit;
        configuration.fieldLimit = profile.fieldLimit;
        configuration.enableDos = profile.enableDos;
        configuration.enableDeepInjection = profile.enableDeepInjection;
        configuration.enableRateLimitTesting = profile.enableRateLimitTesting;
        configuration.enableCsrfTesting = profile.enableCsrfTesting;
        configuration.enableFileUploadTesting = profile.enableFileUploadTesting;
        configuration.batchSize = profile.batchSize;
        configuration.bruteForceAttempts = profile.bruteForceAttempts;
        configuration.rateLimitConcurrency = profile.rateLimitConcurrency;
        configuration.rateLimitRequests = profile.rateLimitRequests;
        configuration.maxXssTests = profile.maxXssTests;
        configuration.timeoutSeconds = profile.timeout;
        configuration.delaySeconds = profile.delay;

        if (settings != null)
        {
            configuration.safeMode = settings.safeMode;
            if (settings.delaySeconds != null)
            {
                configuration.delaySeconds = settings.delaySeconds;
            }
            if (settings.bruteForceAttempts != null)
            {
                configuration.bruteForceAttempts = settings.bruteForceAttempts;
            }
            if (settings.rateLimitConcurrency != null)
            {
                configuration.rateLimitConcurrency = settings.rateLimitConcurrency;
            }
            if (settings.rateLimitRequests != null)
            {
                configuration.rateLimitRequests = settings.rateLimitRequests;
            }
            configuration.scannerEnabled.putAll(settings.scannerEnabled);
        }

        if (configuration.safeMode)
        {
            configuration.enableDos = false;
            configuration.enableRateLimitTesting = false;
            configuration.bruteForceAttempts = Math.min(configuration.bruteForceAttempts, 5);
        }

        return configuration;
    }

    private static <T> T loadYaml(String resourcePath, Class<T> type)
    {
        try (InputStream stream = ConfigurationLoader.class.getResourceAsStream(resourcePath))
        {
            if (stream == null)
            {
                throw new IllegalStateException("Missing resource: " + resourcePath);
            }
            return YAML_MAPPER.readValue(stream, type);
        }
        catch (Exception exception)
        {
            throw new IllegalStateException("Unable to load YAML resource: " + resourcePath, exception);
        }
    }
}
