package graphqlhunter.importer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import graphqlhunter.GraphQLHunterJson;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class RequestImporter
{
    private static final ObjectMapper YAML_MAPPER = new ObjectMapper(new YAMLFactory());
    private static final Pattern HTTP_REQUEST_LINE = Pattern.compile("^([A-Z]+)\\s+(\\S+)\\s+HTTP/\\d\\.\\d$");
    private static final Pattern OPERATION_NAME_PATTERN = Pattern.compile("(?:query|mutation|subscription)\\s+(\\w+)");

    private RequestImporter()
    {
    }

    public static ImportedRequest fromCurlCommand(String curlCommand)
    {
        List<String> tokens = shellSplit(curlCommand);
        if (!tokens.isEmpty() && "curl".equals(tokens.getFirst()))
        {
            tokens = tokens.subList(1, tokens.size());
        }

        ImportedRequest request = new ImportedRequest();
        String bodyText = "";

        for (int index = 0; index < tokens.size(); index++)
        {
            String token = tokens.get(index);
            if (("-X".equals(token) || "--request".equals(token)) && index + 1 < tokens.size())
            {
                request.method = tokens.get(++index).toUpperCase(Locale.ROOT);
                continue;
            }
            if (("-H".equals(token) || "--header".equals(token)) && index + 1 < tokens.size())
            {
                String header = tokens.get(++index);
                int separator = header.indexOf(':');
                if (separator > 0)
                {
                    request.headers.put(header.substring(0, separator).trim(), header.substring(separator + 1).trim());
                }
                continue;
            }
            if (token.startsWith("http://") || token.startsWith("https://"))
            {
                request.url = token;
                continue;
            }
            if ((token.startsWith("-d") || token.startsWith("--data")) && index + 1 < tokens.size())
            {
                bodyText += tokens.get(++index);
            }
        }

        request.name = "Imported from cURL";
        if (request.method == null || request.method.isBlank())
        {
            request.method = bodyText.isBlank() ? "GET" : "POST";
        }
        applyGraphQlBody(request, bodyText);
        return request;
    }

    public static ImportedRequest fromRawHttp(String rawRequest)
    {
        String normalized = rawRequest.replace("\r\n", "\n").replace('\r', '\n').trim();
        String[] lines = normalized.split("\n");
        if (lines.length == 0)
        {
            throw new IllegalArgumentException("Raw HTTP request is empty");
        }

        Matcher matcher = HTTP_REQUEST_LINE.matcher(lines[0]);
        ImportedRequest request = new ImportedRequest();
        request.name = "Imported from raw HTTP";
        boolean matched = matcher.find();
        request.method = matched ? matcher.group(1) : "POST";
        String path = matched ? matcher.group(2) : "/";

        int bodyStart = lines.length;
        String host = "";
        for (int index = 1; index < lines.length; index++)
        {
            String line = lines[index];
            if (line.isBlank())
            {
                bodyStart = index + 1;
                break;
            }
            int separator = line.indexOf(':');
            if (separator > 0)
            {
                String key = line.substring(0, separator).trim();
                String value = line.substring(separator + 1).trim();
                request.headers.put(key, value);
                if ("host".equalsIgnoreCase(key))
                {
                    host = value;
                }
            }
        }

        request.url = buildUrl(host, path);
        String body = bodyStart >= lines.length ? "" : String.join("\n", java.util.Arrays.copyOfRange(lines, bodyStart, lines.length));
        applyGraphQlBody(request, body);
        return request;
    }

    public static ImportedRequest fromJsonContent(String json)
    {
        try
        {
            JsonNode node = GraphQLHunterJson.mapper().readTree(json);
            ImportedRequest request = new ImportedRequest();
            request.name = text(node, "name", "Imported from JSON");
            request.url = text(node, "url", "");
            request.method = text(node, "method", "POST");
            request.query = text(node, "query", "");
            request.operationName = text(node, "operation_name", text(node, "operationName", extractOperationName(request.query)));
            request.variables = node.has("variables") && !node.get("variables").isNull()
                ? GraphQLHunterJson.mapper().convertValue(node.get("variables"), Object.class)
                : new LinkedHashMap<String, Object>();
            if (node.has("headers") && node.get("headers").isObject())
            {
                node.get("headers").fields().forEachRemaining(entry -> request.headers.put(entry.getKey(), entry.getValue().asText("")));
            }
            return request;
        }
        catch (Exception exception)
        {
            throw new IllegalArgumentException("Unable to parse JSON request content", exception);
        }
    }

    public static ImportedRequest fromYamlContent(String yaml)
    {
        try
        {
            Object parsed = YAML_MAPPER.readValue(yaml, Object.class);
            return fromJsonContent(GraphQLHunterJson.write(parsed));
        }
        catch (Exception exception)
        {
            throw new IllegalArgumentException("Unable to parse YAML request content", exception);
        }
    }

    public static List<ImportedRequest> fromPostmanCollectionContent(String json)
    {
        try
        {
            JsonNode root = GraphQLHunterJson.mapper().readTree(json);
            List<ImportedRequest> requests = new ArrayList<>();
            JsonNode items = root.path("item");
            if (items.isArray())
            {
                for (JsonNode item : items)
                {
                    extractPostmanRequests(item, "", requests);
                }
            }
            return requests;
        }
        catch (Exception exception)
        {
            throw new IllegalArgumentException("Unable to parse Postman collection", exception);
        }
    }

    public static List<ImportedRequest> autoDetect(String fileName, String content)
    {
        String lowerName = fileName == null ? "" : fileName.toLowerCase(Locale.ROOT);
        String trimmed = content == null ? "" : content.trim();
        if (trimmed.startsWith("{") || trimmed.startsWith("["))
        {
            try
            {
                JsonNode node = GraphQLHunterJson.mapper().readTree(content);
                if ((node.has("info") && node.path("info").has("schema")) || node.has("item"))
                {
                    return fromPostmanCollectionContent(content);
                }
                return List.of(fromJsonContent(content));
            }
            catch (Exception ignored)
            {
            }
        }
        if (looksLikeYamlRequest(content))
        {
            try
            {
                return List.of(fromYamlContent(content));
            }
            catch (Exception ignored)
            {
            }
        }
        if (lowerName.endsWith(".json"))
        {
            try
            {
                JsonNode node = GraphQLHunterJson.mapper().readTree(content);
                if (node.has("info") && node.path("info").has("schema"))
                {
                    return fromPostmanCollectionContent(content);
                }
            }
            catch (Exception ignored)
            {
            }
            return List.of(fromJsonContent(content));
        }
        if (lowerName.endsWith(".yaml") || lowerName.endsWith(".yml"))
        {
            return List.of(fromYamlContent(content));
        }
        if (content.trim().startsWith("curl "))
        {
            return List.of(fromCurlCommand(content.trim()));
        }
        if (HTTP_REQUEST_LINE.matcher(content.split("\\R", 2)[0]).matches())
        {
            return List.of(fromRawHttp(content));
        }
        throw new IllegalArgumentException("Unsupported request format");
    }

    public static String extractOperationNameFromQuery(String query)
    {
        return extractOperationName(query);
    }

    private static void extractPostmanRequests(JsonNode item, String folderPath, List<ImportedRequest> requests)
    {
        if (item.has("request"))
        {
            JsonNode requestNode = item.get("request");
            ImportedRequest request = new ImportedRequest();
            request.name = text(item, "name", "Unnamed Request");
            request.folder = folderPath;
            request.method = text(requestNode, "method", "POST");
            request.url = buildPostmanUrl(requestNode.path("url"));
            JsonNode headers = requestNode.path("header");
            if (headers.isArray())
            {
                for (JsonNode header : headers)
                {
                    if (!header.path("disabled").asBoolean(false))
                    {
                        request.headers.put(text(header, "key", ""), text(header, "value", ""));
                    }
                }
            }

            JsonNode body = requestNode.path("body");
            if ("raw".equals(body.path("mode").asText("")))
            {
                applyGraphQlBody(request, body.path("raw").asText(""));
            }
            else if ("graphql".equals(body.path("mode").asText("")))
            {
                request.query = body.path("graphql").path("query").asText("");
                if (body.path("graphql").has("variables"))
                {
                    request.variables = normalizeVariables(body.path("graphql").get("variables"));
                }
                request.operationName = extractOperationName(request.query);
            }

            requests.add(request);
        }

        JsonNode nestedItems = item.path("item");
        if (nestedItems.isArray())
        {
            String nextFolder = folderPath;
            if (item.has("name"))
            {
                nextFolder = folderPath.isBlank() ? item.get("name").asText("") : folderPath + "/" + item.get("name").asText("");
            }
            for (JsonNode nested : nestedItems)
            {
                extractPostmanRequests(nested, nextFolder, requests);
            }
        }
    }

    private static void applyGraphQlBody(ImportedRequest request, String body)
    {
        if (body == null || body.isBlank())
        {
            return;
        }
        try
        {
            JsonNode bodyJson = GraphQLHunterJson.mapper().readTree(body);
            if (bodyJson.isObject())
            {
                request.query = bodyJson.path("query").asText(body);
                if (bodyJson.has("variables"))
                {
                    request.variables = normalizeVariables(bodyJson.get("variables"));
                }
                request.operationName = bodyJson.has("operationName")
                    ? bodyJson.get("operationName").asText("")
                    : extractOperationName(request.query);
                return;
            }
        }
        catch (Exception ignored)
        {
        }
        request.query = body;
        request.operationName = extractOperationName(body);
    }

    private static Object normalizeVariables(JsonNode variables)
    {
        if (variables == null || variables.isNull())
        {
            return new LinkedHashMap<String, Object>();
        }
        if (variables.isTextual())
        {
            String raw = variables.asText("");
            if (raw.isBlank())
            {
                return new LinkedHashMap<String, Object>();
            }
            try
            {
                return GraphQLHunterJson.mapper().readValue(raw, Object.class);
            }
            catch (Exception exception)
            {
                return raw;
            }
        }
        return GraphQLHunterJson.mapper().convertValue(variables, Object.class);
    }

    private static String extractOperationName(String query)
    {
        if (query == null || query.isBlank())
        {
            return "";
        }
        Matcher matcher = OPERATION_NAME_PATTERN.matcher(query);
        return matcher.find() ? matcher.group(1) : "";
    }

    private static boolean looksLikeYamlRequest(String content)
    {
        String lowered = content == null ? "" : content.toLowerCase(Locale.ROOT);
        return lowered.contains("query:")
            || lowered.contains("url:")
            || lowered.contains("method:")
            || lowered.contains("variables:")
            || lowered.contains("headers:");
    }

    private static String text(JsonNode node, String field, String defaultValue)
    {
        return node.has(field) ? node.get(field).asText(defaultValue) : defaultValue;
    }

    private static String buildPostmanUrl(JsonNode urlNode)
    {
        if (urlNode.isTextual())
        {
            return urlNode.asText("");
        }
        String protocol = text(urlNode, "protocol", "https");
        String host = joinArray(urlNode.path("host"), ".");
        String path = joinArray(urlNode.path("path"), "/");
        return (protocol + "://" + host + "/" + path).replace("//", "/").replace(":/", "://");
    }

    private static String joinArray(JsonNode node, String separator)
    {
        if (!node.isArray())
        {
            return node.asText("");
        }
        List<String> parts = new ArrayList<>();
        node.forEach(value -> parts.add(value.asText("")));
        return String.join(separator, parts);
    }

    private static String buildUrl(String host, String path)
    {
        if (host == null || host.isBlank())
        {
            return path;
        }
        String protocol = host.contains(":443") ? "https" : "http";
        if (!host.contains(":"))
        {
            return protocol + "://" + host + path;
        }
        try
        {
            URI uri = new URI(protocol + "://" + host);
            return uri.toString() + path;
        }
        catch (URISyntaxException exception)
        {
            return protocol + "://" + host + path;
        }
    }

    private static List<String> shellSplit(String command)
    {
        ArrayList<String> tokens = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean single = false;
        boolean dbl = false;
        for (int index = 0; index < command.length(); index++)
        {
            char character = command.charAt(index);
            if (character == '\'' && !dbl)
            {
                single = !single;
                continue;
            }
            if (character == '"' && !single)
            {
                dbl = !dbl;
                continue;
            }
            if (Character.isWhitespace(character) && !single && !dbl)
            {
                if (!current.isEmpty())
                {
                    tokens.add(current.toString());
                    current.setLength(0);
                }
                continue;
            }
            current.append(character);
        }
        if (!current.isEmpty())
        {
            tokens.add(current.toString());
        }
        return tokens;
    }
}
