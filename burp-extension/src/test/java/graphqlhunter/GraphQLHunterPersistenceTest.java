package graphqlhunter;

import burp.api.montoya.persistence.PersistedObject;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GraphQLHunterPersistenceTest
{
    @Test
    void saveDoesNotMutateRuntimeOnlySecretsInMemory()
    {
        PersistedObject store = fakeStore();
        GraphQLHunterPersistence persistence = new GraphQLHunterPersistence(store, null);
        GraphQLHunterModels.ExtensionState state = new GraphQLHunterModels.ExtensionState();
        state.authSettings.runtimeOnlySecrets.put("access_token", "runtime-secret");

        persistence.save(state);

        assertEquals("runtime-secret", state.authSettings.runtimeOnlySecrets.get("access_token"));
    }

    @Test
    void saveOmitsRuntimeOnlySecretsFromPersistedState()
    {
        PersistedObject store = fakeStore();
        GraphQLHunterPersistence persistence = new GraphQLHunterPersistence(store, null);
        GraphQLHunterModels.ExtensionState state = new GraphQLHunterModels.ExtensionState();
        state.authSettings.runtimeOnlySecrets.put("access_token", "runtime-secret");

        persistence.save(state);

        String persisted = store.getString("graphqlhunter.burp.state");
        assertFalse(persisted.contains("runtime-secret"));
    }

    @Test
    void savePersistsAuthConfigPath()
    {
        PersistedObject store = fakeStore();
        GraphQLHunterPersistence persistence = new GraphQLHunterPersistence(store, null);
        GraphQLHunterModels.ExtensionState state = new GraphQLHunterModels.ExtensionState();
        state.authSettings.authConfigPath = "/tmp/auth.yaml";

        persistence.save(state);

        String persisted = store.getString("graphqlhunter.burp.state");
        assertTrue(persisted.contains("/tmp/auth.yaml"));
    }

    @Test
    void saveAndLoadPreservesRecentRequestHistory()
    {
        PersistedObject store = fakeStore();
        GraphQLHunterPersistence persistence = new GraphQLHunterPersistence(store, null);
        GraphQLHunterModels.ExtensionState state = new GraphQLHunterModels.ExtensionState();
        GraphQLHunterModels.RecentRequestEntry entry = new GraphQLHunterModels.RecentRequestEntry();
        entry.fingerprint = "abc";
        entry.url = "https://api.example.com/graphql";
        entry.query = "{ __typename }";
        entry.lastSeenAt = "2026-03-08T00:00:00Z";
        state.recentRequests.add(entry);

        persistence.save(state);
        GraphQLHunterModels.ExtensionState loaded = persistence.load();

        assertEquals(1, loaded.recentRequests.size());
        assertEquals("abc", loaded.recentRequests.getFirst().fingerprint);
    }

    private PersistedObject fakeStore()
    {
        Map<String, String> strings = new LinkedHashMap<>();
        return (PersistedObject) Proxy.newProxyInstance(
            PersistedObject.class.getClassLoader(),
            new Class<?>[]{PersistedObject.class},
            (proxy, method, args) ->
            {
                return switch (method.getName())
                {
                    case "getString" -> strings.get(args[0]);
                    case "setString" ->
                    {
                        strings.put(String.valueOf(args[0]), String.valueOf(args[1]));
                        yield null;
                    }
                    case "stringKeys" -> strings.keySet();
                    default -> null;
                };
            }
        );
    }
}
