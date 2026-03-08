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
        return looksLikeAuthFailure(response.statusCode, response.errorsText());
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

    static boolean looksLikeAuthFailure(int statusCode, String text)
    {
        if (statusCode == 401 || statusCode == 403)
        {
            return true;
        }
        String lowered = text == null ? "" : text.toLowerCase();
        return lowered.contains("unauthorized")
            || lowered.contains("forbidden")
            || lowered.contains("unauthenticated")
            || lowered.contains("not authenticated")
            || lowered.contains("authentication")
            || lowered.contains("invalid token")
            || lowered.contains("missing token")
            || lowered.contains("token expired")
            || lowered.contains("access denied")
            || lowered.contains("jwt")
            || lowered.contains("csrf");
    }

    static boolean looksLikePermissionFailure(String text)
    {
        String lowered = text == null ? "" : text.toLowerCase();
        return lowered.contains("permission") || lowered.contains("authorization");
    }
}
