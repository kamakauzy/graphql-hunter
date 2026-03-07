package graphqlhunter.auth.config;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import java.io.InputStream;

public final class AuthConfigurationLoader
{
    private static final String AUTH_RESOURCE = "/graphqlhunter/config/auth.yaml";
    private static final ObjectMapper YAML_MAPPER = new ObjectMapper(new YAMLFactory())
        .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
        .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);

    private static AuthConfiguration authConfiguration;

    private AuthConfigurationLoader()
    {
    }

    public static synchronized AuthConfiguration configuration()
    {
        if (authConfiguration == null)
        {
            authConfiguration = loadYaml(AUTH_RESOURCE, AuthConfiguration.class);
        }
        return authConfiguration;
    }

    private static <T> T loadYaml(String resourcePath, Class<T> type)
    {
        try (InputStream stream = AuthConfigurationLoader.class.getResourceAsStream(resourcePath))
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
