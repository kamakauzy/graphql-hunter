package graphqlhunter.auth.config;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class AuthProfileDefinition
{
    public String type = "";
    public String headerName = "";
    public String var = "";
    public String prefix = "";
    public String tokenUrl = "";
    public String authMethod = "";
    public String clientIdVar = "";
    public String clientSecretVar = "";
    public String refreshTokenVar = "";
    public String scopeVar = "";
    public String audienceVar = "";
    public String authorizeUrl = "";
    public String redirectUri = "";
    public String codeVar = "";
    public String deviceAuthorizationUrl = "";
    public Map<String, String> injectHeaders = new LinkedHashMap<>();
    public List<String> sensitiveHeaders = new ArrayList<>();
    public List<Map<String, Object>> acquireSteps = new ArrayList<>();
    public List<Map<String, Object>> loginSteps = new ArrayList<>();
    public Map<String, Object> csrf = new LinkedHashMap<>();
}
