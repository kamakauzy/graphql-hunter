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
        Optional<ScanRequest> imported = parseFromEvent(event);
        if (imported.isEmpty())
        {
            return List.of();
        }

        JMenuItem item = new JMenuItem("Send GraphQL request to GraphQL Hunter");
        item.addActionListener(actionEvent -> SwingUtilities.invokeLater(() -> importer.accept(imported.get())));
        return List.of(item);
    }

    private Optional<ScanRequest> parseFromEvent(ContextMenuEvent event)
    {
        try
        {
            Optional<?> maybeEditor = event.messageEditorRequestResponse();
            if (maybeEditor.isEmpty())
            {
                return Optional.empty();
            }

            Object editorContext = maybeEditor.get();
            Object requestResponse = editorContext.getClass().getMethod("requestResponse").invoke(editorContext);
            HttpRequest request = (HttpRequest) requestResponse.getClass().getMethod("request").invoke(requestResponse);
            Map<String, String> headers = new LinkedHashMap<>();
            request.headers().forEach(header -> headers.put(header.name(), header.value()));

            return GraphQLHunterCore.parseRequest(
                "burp-selection",
                request.url(),
                request.method(),
                headers,
                request.bodyToString()
            );
        }
        catch (Exception exception)
        {
            logger.error("Unable to inspect Burp context menu request.", exception);
            return Optional.empty();
        }
    }
}
