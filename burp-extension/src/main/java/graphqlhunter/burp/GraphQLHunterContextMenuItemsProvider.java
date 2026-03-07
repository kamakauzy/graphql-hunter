package graphqlhunter.burp;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import graphqlhunter.GraphQLHunterCore;
import graphqlhunter.GraphQLHunterLogger;
import graphqlhunter.GraphQLHunterModels.ScanRequest;

import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

public final class GraphQLHunterContextMenuItemsProvider implements ContextMenuItemsProvider
{
    private final GraphQLHunterLogger logger;
    private final Consumer<ScanRequest> importer;

    public GraphQLHunterContextMenuItemsProvider(GraphQLHunterLogger logger, Consumer<ScanRequest> importer)
    {
        this.logger = logger;
        this.importer = importer;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event)
    {
        JMenuItem item = new JMenuItem("Send GraphQL request to GraphQL Hunter");
        item.addActionListener(actionEvent -> importFromEvent(event));
        return List.of(item);
    }

    private void importFromEvent(ContextMenuEvent event)
    {
        try
        {
            Optional<?> maybeEditor = event.messageEditorRequestResponse();
            if (maybeEditor.isEmpty())
            {
                logger.warn("GraphQL Hunter import was invoked without an HTTP message editor context.");
                return;
            }

            Object editorContext = maybeEditor.get();
            HttpRequest request = (HttpRequest) editorContext.getClass().getMethod("requestResponse").invoke(editorContext).getClass().getMethod("request").invoke(
                editorContext.getClass().getMethod("requestResponse").invoke(editorContext)
            );
            Map<String, String> headers = new LinkedHashMap<>();
            request.headers().forEach(header -> headers.put(header.name(), header.value()));

            Optional<ScanRequest> imported = GraphQLHunterCore.parseRequest(
                "burp-selection",
                request.url(),
                request.method(),
                headers,
                request.bodyToString()
            );

            if (imported.isEmpty())
            {
                logger.warn("Selected request does not look like a GraphQL request body.");
                return;
            }

            SwingUtilities.invokeLater(() -> importer.accept(imported.get()));
            logger.info("Imported GraphQL request from Burp context menu.");
        }
        catch (Exception exception)
        {
            logger.error("Unable to import GraphQL request from Burp.", exception);
        }
    }
}
