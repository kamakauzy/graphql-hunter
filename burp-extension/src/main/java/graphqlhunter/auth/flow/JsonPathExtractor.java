package graphqlhunter.auth.flow;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class JsonPathExtractor
{
    private JsonPathExtractor()
    {
    }

    public static Object extract(Object obj, String path)
    {
        Object current = obj;
        for (String token : tokenize(path))
        {
            if (token.startsWith("[") && token.endsWith("]"))
            {
                if (!(current instanceof List<?> list))
                {
                    return null;
                }
                int index;
                try
                {
                    index = Integer.parseInt(token.substring(1, token.length() - 1).trim());
                }
                catch (NumberFormatException exception)
                {
                    throw new FlowException("Invalid list index in path " + path + ": " + token, exception);
                }
                if (index < 0 || index >= list.size())
                {
                    return null;
                }
                current = list.get(index);
            }
            else
            {
                if (!(current instanceof Map<?, ?> map))
                {
                    return null;
                }
                current = map.get(token);
            }
        }
        return current;
    }

    static List<String> tokenize(String path)
    {
        if (path == null || path.isBlank())
        {
            return List.of();
        }
        List<String> tokens = new ArrayList<>();
        StringBuilder buffer = new StringBuilder();
        int index = 0;
        while (index < path.length())
        {
            char current = path.charAt(index);
            if (current == '.')
            {
                if (!buffer.isEmpty())
                {
                    tokens.add(buffer.toString());
                    buffer.setLength(0);
                }
                index++;
                continue;
            }
            if (current == '[')
            {
                if (!buffer.isEmpty())
                {
                    tokens.add(buffer.toString());
                    buffer.setLength(0);
                }
                int end = path.indexOf(']', index);
                if (end < 0)
                {
                    throw new FlowException("Invalid JSON path (missing ']'): " + path);
                }
                tokens.add(path.substring(index, end + 1));
                index = end + 1;
                continue;
            }
            buffer.append(current);
            index++;
        }
        if (!buffer.isEmpty())
        {
            tokens.add(buffer.toString());
        }
        return tokens;
    }
}
