package graphqlhunter;

import burp.api.montoya.persistence.PersistedObject;

public final class GraphQLHunterPersistence
{
    private static final String STATE_KEY = "graphqlhunter.burp.state";

    private final PersistedObject store;
    private final GraphQLHunterLogger logger;

    public GraphQLHunterPersistence(PersistedObject store, GraphQLHunterLogger logger)
    {
        this.store = store;
        this.logger = logger;
    }

    public GraphQLHunterModels.ExtensionState load()
    {
        String json = store.getString(STATE_KEY);
        if (json == null || json.isBlank())
        {
            return new GraphQLHunterModels.ExtensionState();
        }

        try
        {
            GraphQLHunterModels.ExtensionState state = GraphQLHunterJson.read(json, GraphQLHunterModels.ExtensionState.class);
            if (state.lastRequest == null)
            {
                state.lastRequest = new GraphQLHunterModels.ScanRequest();
            }
            if (state.scanSettings == null)
            {
                state.scanSettings = new GraphQLHunterModels.ScanSettings();
            }
            if (state.authSettings == null)
            {
                state.authSettings = new GraphQLHunterModels.AuthSettings();
            }
            if (state.scanSettings.profileName == null || state.scanSettings.profileName.isBlank())
            {
                state.scanSettings.profileName = state.scanProfile == null || state.scanProfile.isBlank()
                    ? GraphQLHunterModels.ScanProfile.STANDARD.name()
                    : state.scanProfile;
            }
            if (state.scanProfile == null || state.scanProfile.isBlank())
            {
                state.scanProfile = state.scanSettings.profileName;
            }
            return state;
        }
        catch (RuntimeException exception)
        {
            logger.error("Unable to load persisted GraphQL Hunter Burp state; starting fresh.", exception);
            return new GraphQLHunterModels.ExtensionState();
        }
    }

    public void save(GraphQLHunterModels.ExtensionState state)
    {
        if (state.scanSettings == null)
        {
            state.scanSettings = new GraphQLHunterModels.ScanSettings();
        }
        if (state.authSettings == null)
        {
            state.authSettings = new GraphQLHunterModels.AuthSettings();
        }
        state.scanProfile = state.scanSettings.profileName;
        state.authSettings.runtimeOnlySecrets.clear();
        store.setString(STATE_KEY, GraphQLHunterJson.write(state));
    }
}
