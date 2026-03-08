package graphqlhunter.config;

import graphqlhunter.GraphQLHunterModels;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfigurationLoaderTest
{
    @Test
    void loadsYamlBackedProfileSettings()
    {
        PayloadConfiguration configuration = ConfigurationLoader.payloads();

        assertTrue(configuration.profiles.containsKey("standard"));
        assertEquals(5, configuration.profiles.get("standard").depthLimit);
        assertEquals(1024, configuration.profiles.get("standard").maxUploadTestSize);
        assertTrue(configuration.sqlInjection.basic.contains("' OR '1'='1"));
    }

    @Test
    void appliesSafeModeOverrides()
    {
        GraphQLHunterModels.ScanSettings settings = new GraphQLHunterModels.ScanSettings();
        settings.profileName = GraphQLHunterModels.ScanProfile.DEEP.name();
        settings.safeMode = true;

        ScanConfiguration configuration = ConfigurationLoader.scanConfiguration(settings);

        assertFalse(configuration.enableDos);
        assertFalse(configuration.enableRateLimitTesting);
        assertEquals(5, configuration.bruteForceAttempts);
    }
}
