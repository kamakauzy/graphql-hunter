package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import graphqlhunter.GraphQLHunterLogger;
import graphqlhunter.GraphQLHunterModels.ExtensionState;
import graphqlhunter.GraphQLHunterModels.Finding;
import graphqlhunter.GraphQLHunterModels.ScanProfile;
import graphqlhunter.GraphQLHunterModels.ScanRequest;
import graphqlhunter.GraphQLHunterPersistence;
import graphqlhunter.GraphQLHunterScanners;
import graphqlhunter.burp.GraphQLHunterContextMenuItemsProvider;
import graphqlhunter.ui.GraphQLHunterTab;

import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.List;
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
    private ExecutorService executorService;

    @Override
    public void initialize(MontoyaApi api)
    {
        this.api = api;
        this.logger = new GraphQLHunterLogger(api.logging());
        this.persistence = new GraphQLHunterPersistence(api.persistence().extensionData(), logger);
        this.state = persistence.load();
        this.executorService = Executors.newVirtualThreadPerTaskExecutor();

        api.extension().setName("GraphQL Hunter");
        registrations.add(api.extension().registerUnloadingHandler(this::shutdown));

        this.tab = new GraphQLHunterTab(new Actions(), logger);
        api.userInterface().applyThemeToComponent(tab);
        registrations.add(api.userInterface().registerSuiteTab("GraphQL Hunter", tab));
        registrations.add(api.userInterface().registerContextMenuItemsProvider(
            new GraphQLHunterContextMenuItemsProvider(logger, this::importRequest)
        ));

        logger.info("GraphQL Hunter Burp extension initialized.");
    }

    private synchronized void importRequest(ScanRequest request)
    {
        state.lastRequest = request.copy();
        persistState();
        if (tab != null)
        {
            tab.importRequest(request);
        }
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
        ExtensionState snapshot = new ExtensionState();
        snapshot.lastRequest = state.lastRequest == null ? new ScanRequest() : state.lastRequest.copy();
        snapshot.scanProfile = state.scanProfile;
        return snapshot;
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
                state = newState;
                persistState();
            }
        }

        @Override
        public void runScan(ScanRequest request, ScanProfile profile, Consumer<List<Finding>> onSuccess, Consumer<Throwable> onError)
        {
            executorService.submit(() ->
            {
                try
                {
                    List<Finding> findings = GraphQLHunterScanners.run(request, profile, logger);
                    synchronized (GraphQLHunterExtension.this)
                    {
                        state.lastRequest = request.copy();
                        state.scanProfile = profile.name();
                        persistState();
                    }
                    SwingUtilities.invokeLater(() -> onSuccess.accept(findings));
                }
                catch (Throwable throwable)
                {
                    logger.error("GraphQL scan execution failed.", throwable);
                    SwingUtilities.invokeLater(() -> onError.accept(throwable));
                }
            });
        }
    }
}
