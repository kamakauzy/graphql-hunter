package graphqlhunter;

import burp.api.montoya.persistence.PersistedObject;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

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
