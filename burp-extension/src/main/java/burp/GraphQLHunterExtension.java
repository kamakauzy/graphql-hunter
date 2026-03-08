package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import graphqlhunter.GraphQLHunterLogger;
import graphqlhunter.GraphQLHunterModels.ExtensionState;
import graphqlhunter.GraphQLHunterModels.Finding;
import graphqlhunter.GraphQLHunterModels.AuthSettings;
import graphqlhunter.GraphQLHunterModels.ScanRequest;
import graphqlhunter.GraphQLHunterModels.ScanExecutionResult;
import graphqlhunter.GraphQLHunterModels.ScanSettings;
import graphqlhunter.GraphQLHunterCore;
import graphqlhunter.auth.AuthManager;
import graphqlhunter.GraphQLHunterPersistence;
import graphqlhunter.GraphQLHunterScanners;
import graphqlhunter.burp.BurpIssuePublisher;
import graphqlhunter.burp.GraphQLRequestCaptureHandler;
import graphqlhunter.burp.RecentRequestHistory;
import graphqlhunter.config.ConfigurationLoader;
import graphqlhunter.burp.GraphQLHunterContextMenuItemsProvider;
import graphqlhunter.ui.GraphQLHunterTab;

import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

public final class GraphQLHunterExtension implements BurpExtension
{
    private final List<Registration> registrations = new ArrayList<>();
    private MontoyaApi api;
    private GraphQLHunterLogger logger;
    private GraphQLHunterPersistence persistence;
    private ExtensionState state;
    private GraphQLHunterTab tab;
    private BurpIssuePublisher issuePublisher;
    private ExecutorService executorService;

    @Override
    public void initialize(MontoyaApi api)
    {
        this.api = api;
        this.logger = new GraphQLHunterLogger(api.logging());
        this.persistence = new GraphQLHunterPersistence(api.persistence().extensionData(), logger);
        this.state = persistence.load();
        this.issuePublisher = new BurpIssuePublisher(api.siteMap(), logger);
        this.executorService = Executors.newVirtualThreadPerTaskExecutor();

        api.extension().setName("GraphQL Hunter");
        registrations.add(api.extension().registerUnloadingHandler(this::shutdown));

        this.tab = new GraphQLHunterTab(new Actions(), logger);
        api.userInterface().applyThemeToComponent(tab);
        registrations.add(api.userInterface().registerSuiteTab("GraphQL Hunter", tab));
        registrations.add(api.http().registerHttpHandler(new GraphQLRequestCaptureHandler(this::captureRequest)));
        registrations.add(api.userInterface().registerContextMenuItemsProvider(
            new GraphQLHunterContextMenuItemsProvider(logger, this::importRequest)
        ));

        logger.info("GraphQL Hunter Burp extension initialized.");
    }

    private synchronized void importRequest(ScanRequest request)
    {
        state.recentRequests = RecentRequestHistory.upsert(state.recentRequests, request);
        state.lastRequest = request.copy();
        if (state.scanSettings == null)
        {
            state.scanSettings = new ScanSettings();
        }
        if (state.authSettings == null)
        {
            state.authSettings = new AuthSettings();
        }
        state.authSettings.importedAuthHeaders = extractImportedAuthHeaders(request.headers);
        if (!state.authSettings.importedAuthHeaders.isEmpty() && (state.authSettings.mode == null || "none".equalsIgnoreCase(state.authSettings.mode)))
        {
            state.authSettings.mode = "imported_headers";
        }
        persistState();
        if (tab != null)
        {
            List<graphqlhunter.GraphQLHunterModels.RecentRequestEntry> history = state.recentRequests.stream()
                .map(graphqlhunter.GraphQLHunterModels.RecentRequestEntry::copy)
                .toList();
            tab.updateRecentRequests(history, "");
            tab.importRequest(request);
        }
        logger.info("Imported GraphQL request into the GraphQL Hunter tab.");
    }

    private synchronized void captureRequest(ScanRequest request)
    {
        state.recentRequests = RecentRequestHistory.upsert(state.recentRequests, request);
        persistState();
        if (tab != null)
        {
            List<graphqlhunter.GraphQLHunterModels.RecentRequestEntry> history = state.recentRequests.stream()
                .map(graphqlhunter.GraphQLHunterModels.RecentRequestEntry::copy)
                .toList();
            SwingUtilities.invokeLater(() -> tab.updateRecentRequests(history, "Captured GraphQL request into Recent Requests."));
        }
    }

    private Map<String, String> extractImportedAuthHeaders(Map<String, String> headers)
    {
        LinkedHashMap<String, String> authHeaders = new LinkedHashMap<>();
        if (headers == null)
        {
            return authHeaders;
        }
        headers.forEach((key, value) ->
        {
            if (key == null)
            {
                return;
            }
            String lowered = key.toLowerCase(Locale.ROOT);
            if (lowered.equals("authorization")
                || lowered.equals("cookie")
                || lowered.equals("token")
                || lowered.equals("x-api-key")
                || lowered.equals("x-auth-token"))
            {
                authHeaders.put(key, value);
            }
        });
        return authHeaders;
    }

    private synchronized void persistState()
    {
        persistence.save(state);
    }

    private synchronized void shutdown()
    {
        if (executorService != null)
        {
            executorService.shutdownNow();
        }
        persistState();
        registrations.forEach(Registration::deregister);
        registrations.clear();
    }

    private synchronized ExtensionState snapshot()
    {
        return state == null ? new ExtensionState() : state.copy();
    }

    private final class Actions implements GraphQLHunterTab.GraphQLHunterActions
    {
        @Override
        public ExtensionState currentState()
        {
            return snapshot();
        }

        @Override
        public void saveState(ExtensionState newState)
        {
            synchronized (GraphQLHunterExtension.this)
            {
                if (newState.recentRequests == null || newState.recentRequests.isEmpty())
                {
                    newState.recentRequests = state.recentRequests;
                }
                state = newState;
                persistState();
            }
        }

        @Override
        public void runScan(ScanRequest request, ScanSettings settings, Consumer<ScanExecutionResult> onSuccess, Consumer<Throwable> onError)
        {
            executorService.submit(() ->
            {
                try
                {
                    ScanExecutionResult result = GraphQLHunterScanners.runWithMetadata(
                        request,
                        ConfigurationLoader.scanConfiguration(settings),
                        state.authSettings,
                        logger
                    );
                    result.settings = settings.copy();
                    result.timestamp = java.time.Instant.now().toString();
                    synchronized (GraphQLHunterExtension.this)
                    {
                        state.recentRequests = RecentRequestHistory.upsert(state.recentRequests, request);
                        state.lastRequest = request.copy();
                        state.scanSettings = settings.copy();
                        state.scanProfile = settings.profileName;
                        persistState();
                    }
                    SwingUtilities.invokeLater(() -> onSuccess.accept(result));
                }
                catch (Throwable throwable)
                {
                    logger.error("GraphQL scan execution failed.", throwable);
                    SwingUtilities.invokeLater(() -> onError.accept(throwable));
                }
            });
        }

        @Override
        public void validateAuth(ScanRequest request, AuthSettings settings, Consumer<String> onSuccess, Consumer<Throwable> onError)
        {
            executorService.submit(() ->
            {
                try
                {
                    AuthManager authManager = AuthManager.fromState(settings, logger);
                    GraphQLHunterCore.GraphQLClient client = new GraphQLHunterCore.GraphQLClient(
                        request.url,
                        request.headers,
                        new GraphQLHunterCore.JavaHttpTransport(30, 0.0),
                        logger,
                        authManager
                    );
                    GraphQLHunterCore.AuthValidationResult validation = client.validateAuth(request.query, request.variables);
                    String message = "WITH auth: " + validation.statusWithAuth + System.lineSeparator()
                        + "WITHOUT auth: " + validation.statusWithoutAuth + System.lineSeparator()
                        + "Auth required: " + validation.authRequired + System.lineSeparator()
                        + "Auth working: " + validation.authWorking + System.lineSeparator()
                        + System.lineSeparator()
                        + validation.analysis;
                    SwingUtilities.invokeLater(() -> onSuccess.accept(message));
                }
                catch (Throwable throwable)
                {
                    logger.error("Auth validation failed.", throwable);
                    SwingUtilities.invokeLater(() -> onError.accept(throwable));
                }
            });
        }

        @Override
        public void publishIssues(ScanRequest request, List<Finding> findings, Consumer<Integer> onSuccess, Consumer<Throwable> onError)
        {
            executorService.submit(() ->
            {
                try
                {
                    int published = issuePublisher.publish(request, findings);
                    SwingUtilities.invokeLater(() -> onSuccess.accept(published));
                }
                catch (Throwable throwable)
                {
                    logger.error("Burp issue publication failed.", throwable);
                    SwingUtilities.invokeLater(() -> onError.accept(throwable));
                }
            });
        }
    }
}
