package graphqlhunter.auth;

import graphqlhunter.GraphQLHunterCore;

import java.util.Map;
import java.util.Set;

public interface AuthProvider
{
    default void prepare(AuthExecutionContext context)
    {
    }

    Map<String, String> headersForRequest();

    default boolean isAuthFailure(GraphQLHunterCore.GraphQLResponse response)
    {
        int statusCode = response.statusCode;
        if (statusCode == 401 || statusCode == 403)
        {
            return true;
        }
        String errors = response.errorsText().toLowerCase();
        return errors.contains("unauthorized")
            || errors.contains("forbidden")
            || errors.contains("unauthenticated")
            || errors.contains("invalid token")
            || errors.contains("csrf");
    }

    default boolean canRefresh()
    {
        return false;
    }

    default boolean refresh(AuthExecutionContext context)
    {
        return false;
    }

    default Set<String> sensitiveHeaderNames()
    {
        return Set.of();
    }
}
