package graphqlhunter.config;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class PayloadConfiguration
{
    public SqlInjectionPayloads sqlInjection = new SqlInjectionPayloads();
    public List<String> nosqlInjection = new ArrayList<>();
    public List<String> commandInjection = new ArrayList<>();
    public List<String> xssPayloads = new ArrayList<>();
    public Map<String, ProfileSettings> profiles = new LinkedHashMap<>();
    public Map<String, Object> defaults = new LinkedHashMap<>();

    public static final class SqlInjectionPayloads
    {
        public List<String> basic = new ArrayList<>();
        public List<String> unionBased = new ArrayList<>();
        public List<String> timeBased = new ArrayList<>();
        public List<String> errorBased = new ArrayList<>();
    }
}
