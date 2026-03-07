package graphqlhunter.auth.flow;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class FlowRunner
{
    public interface FlowClient
    {
        FlowStepResult executeHttp(String method, String url, Map<String, String> headers, Object jsonBody, Map<String, String> formBody, String dataBody);

        FlowStepResult executeGraphQl(String query, Object variables, String operationName, Map<String, String> headers, boolean bypassAuth);

        String getCookie(String name);
    }

    public Map<String, String> run(FlowClient client, List<Map<String, Object>> steps, Map<String, String> variables)
    {
        if (steps == null)
        {
            return variables;
        }
        for (Map<String, Object> step : steps)
        {
            Object rendered = TemplateRenderer.render(step, variables);
            if (!(rendered instanceof Map<?, ?> renderedStep))
            {
                throw new FlowException("Rendered flow step must be an object");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> typedStep = (Map<String, Object>) renderedStep;
            String type = String.valueOf(typedStep.getOrDefault("type", "http")).toLowerCase(Locale.ROOT);
            FlowStepResult result = switch (type)
            {
                case "http" -> runHttpStep(client, typedStep);
                case "graphql" -> runGraphQlStep(client, typedStep);
                default -> throw new FlowException("Unknown flow step type: " + type);
            };
            applyExtractors(client, result, typedStep, variables);
        }
        return variables;
    }

    private FlowStepResult runHttpStep(FlowClient client, Map<String, Object> step)
    {
        String method = String.valueOf(step.getOrDefault("method", "POST"));
        String url = String.valueOf(step.getOrDefault("url", ""));
        if (url.isBlank())
        {
            throw new FlowException("HTTP flow step missing url");
        }
        return client.executeHttp(
            method,
            url,
            stringMap(step.get("headers")),
            step.get("json"),
            stringMap(step.get("form")),
            step.containsKey("data") ? String.valueOf(step.get("data")) : null
        );
    }

    private FlowStepResult runGraphQlStep(FlowClient client, Map<String, Object> step)
    {
        String query = String.valueOf(step.getOrDefault("query", ""));
        if (query.isBlank())
        {
            throw new FlowException("GraphQL flow step missing query");
        }
        return client.executeGraphQl(
            query,
            step.get("variables"),
            step.containsKey("operationName") ? String.valueOf(step.get("operationName")) : null,
            stringMap(step.get("headers")),
            true
        );
    }

    private void applyExtractors(FlowClient client, FlowStepResult result, Map<String, Object> step, Map<String, String> variables)
    {
        Object extractorsValue = step.get("extract");
        if (!(extractorsValue instanceof List<?> extractors))
        {
            return;
        }

        for (Object extractorValue : extractors)
        {
            if (!(extractorValue instanceof Map<?, ?> extractor))
            {
                continue;
            }
            String variableName = stringValue(extractor, "var", "");
            if (variableName.isBlank())
            {
                continue;
            }
            String source = stringValue(extractor, "from", "json").toLowerCase(Locale.ROOT);
            Object extracted = switch (source)
            {
                case "json" -> JsonPathExtractor.extract(result.json(), stringValue(extractor, "path", ""));
                case "header" -> extractHeader(result, extractor);
                case "text" -> extractText(result, extractor);
                case "cookie" -> client.getCookie(stringValue(extractor, "name", ""));
                default -> throw new FlowException("Unknown extractor source: " + source);
            };

            if (extracted != null)
            {
                variables.put(variableName, String.valueOf(extracted));
            }
        }
    }

    private Object extractHeader(FlowStepResult result, Map<?, ?> extractor)
    {
        String headerName = stringValue(extractor, "name", "");
        if (headerName.isBlank())
        {
            return null;
        }
        for (Map.Entry<String, String> entry : result.headers().entrySet())
        {
            if (entry.getKey().equalsIgnoreCase(headerName))
            {
                return applyRegex(entry.getValue(), extractor);
            }
        }
        return null;
    }

    private Object extractText(FlowStepResult result, Map<?, ?> extractor)
    {
        Object regex = extractor.get("regex");
        return regex == null ? null : applyRegex(result.text(), extractor);
    }

    private Object applyRegex(String text, Map<?, ?> extractor)
    {
        Object regex = extractor.get("regex");
        if (regex == null)
        {
            return text;
        }
        Matcher matcher = Pattern.compile(String.valueOf(regex), Pattern.DOTALL).matcher(text == null ? "" : text);
        if (!matcher.find())
        {
            return null;
        }
        return matcher.groupCount() >= 1 ? matcher.group(1) : matcher.group();
    }

    @SuppressWarnings("unchecked")
    private Map<String, String> stringMap(Object value)
    {
        if (!(value instanceof Map<?, ?> map))
        {
            return Map.of();
        }
        java.util.LinkedHashMap<String, String> converted = new java.util.LinkedHashMap<>();
        map.forEach((key, entryValue) -> converted.put(String.valueOf(key), entryValue == null ? "" : String.valueOf(entryValue)));
        return converted;
    }

    private String stringValue(Map<?, ?> values, String key, String defaultValue)
    {
        Object value = values.get(key);
        return value == null ? defaultValue : String.valueOf(value);
    }
}
