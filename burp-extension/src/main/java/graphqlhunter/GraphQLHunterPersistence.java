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
            if (state.recentRequests == null)
            {
                state.recentRequests = new java.util.ArrayList<>();
            }
            if (state.recentRequests.isEmpty()
                && state.lastRequest != null
                && state.lastRequest.url != null && !state.lastRequest.url.isBlank()
                && state.lastRequest.query != null && !state.lastRequest.query.isBlank())
            {
                state.recentRequests.add(GraphQLHunterModels.RecentRequestEntry.fromScanRequest(state.lastRequest.copy(), java.time.Instant.now().toString()));
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
        GraphQLHunterModels.ExtensionState persisted = new GraphQLHunterModels.ExtensionState();
        persisted.lastRequest = state.lastRequest == null ? new GraphQLHunterModels.ScanRequest() : state.lastRequest.copy();
        if (state.recentRequests != null)
        {
            state.recentRequests.stream()
                .limit(GraphQLHunterModels.MAX_RECENT_REQUESTS)
                .forEach(entry -> persisted.recentRequests.add(entry.copy()));
        }
        persisted.scanProfile = state.scanProfile;
        persisted.scanSettings = state.scanSettings.copy();
        persisted.authSettings = state.authSettings.copy();
        persisted.authSettings.runtimeOnlySecrets.clear();
        store.setString(STATE_KEY, GraphQLHunterJson.write(persisted));
    }
}
