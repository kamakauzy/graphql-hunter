package graphqlhunter.auth.flow;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class TemplateRenderer
{
    private static final Pattern TEMPLATE_PATTERN = Pattern.compile("\\{\\{\\s*([^}]+?)\\s*}}");

    private TemplateRenderer()
    {
    }

    public static Object render(Object value, Map<String, String> variables)
    {
        if (value == null)
        {
            return null;
        }
        if (value instanceof String stringValue)
        {
            Matcher matcher = TEMPLATE_PATTERN.matcher(stringValue);
            StringBuffer rendered = new StringBuffer();
            while (matcher.find())
            {
                String key = matcher.group(1).trim();
                matcher.appendReplacement(rendered, Matcher.quoteReplacement(variables.getOrDefault(key, "")));
            }
            matcher.appendTail(rendered);
            return rendered.toString();
        }
        if (value instanceof Map<?, ?> mapValue)
        {
            LinkedHashMap<String, Object> renderedMap = new LinkedHashMap<>();
            mapValue.forEach((key, nestedValue) -> renderedMap.put(String.valueOf(key), render(nestedValue, variables)));
            return renderedMap;
        }
        if (value instanceof List<?> listValue)
        {
            List<Object> renderedList = new ArrayList<>();
            listValue.forEach(item -> renderedList.add(render(item, variables)));
            return renderedList;
        }
        return value;
    }
}
