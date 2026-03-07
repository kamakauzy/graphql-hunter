package graphqlhunter.discovery;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class DiscoveryResult
{
    public String url;
    public String authMethod;
    public Map<String, String> credentials = new LinkedHashMap<>();
    public Map<String, String> headers = new LinkedHashMap<>();
    public Map<String, String> tokens = new LinkedHashMap<>();
    public List<Map<String, Object>> queries = new ArrayList<>();
    public List<Map<String, Object>> mutations = new ArrayList<>();
    public Map<String, Object> recommendations = new LinkedHashMap<>();
}
