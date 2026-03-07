package graphqlhunter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.util.LinkedHashMap;
import java.util.Map;

public final class GraphQLHunterJson
{
    private static final ObjectMapper MAPPER = new ObjectMapper()
        .registerModule(new JavaTimeModule())
        .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
        .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

    private GraphQLHunterJson()
    {
    }

    public static ObjectMapper mapper()
    {
        return MAPPER;
    }

    public static String write(Object value)
    {
        try
        {
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(value);
        }
        catch (JsonProcessingException exception)
        {
            throw new IllegalStateException("Unable to serialize JSON value", exception);
        }
    }

    public static <T> T read(String json, Class<T> type)
    {
        try
        {
            return MAPPER.readValue(json, type);
        }
        catch (JsonProcessingException exception)
        {
            throw new IllegalStateException("Unable to parse JSON value", exception);
        }
    }

    public static Map<String, Object> readMap(String json)
    {
        try
        {
            return MAPPER.readValue(json, new TypeReference<LinkedHashMap<String, Object>>()
            {
            });
        }
        catch (JsonProcessingException exception)
        {
            throw new IllegalStateException("Unable to parse JSON object", exception);
        }
    }
}
