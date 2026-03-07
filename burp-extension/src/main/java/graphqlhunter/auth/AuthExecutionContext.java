package graphqlhunter.auth;

import graphqlhunter.GraphQLHunterCore;
import graphqlhunter.GraphQLHunterLogger;

public record AuthExecutionContext(GraphQLHunterCore.GraphQLClient client, GraphQLHunterLogger logger)
{
}
