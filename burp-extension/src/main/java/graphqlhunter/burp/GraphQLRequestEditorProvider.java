package graphqlhunter.burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextField;
import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.util.Optional;

public final class GraphQLRequestEditorProvider implements HttpRequestEditorProvider
{
    private final UserInterface userInterface;

    public GraphQLRequestEditorProvider(UserInterface userInterface)
    {
        this.userInterface = userInterface;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext context)
    {
        return new Editor(userInterface, context.editorMode() == EditorMode.READ_ONLY);
    }

    private static final class Editor implements ExtensionProvidedHttpRequestEditor
    {
        private final RawEditor queryEditor;
        private final RawEditor variablesEditor;
        private final JPanel panel = new JPanel(new BorderLayout(6, 6));
        private final JTextField operationNameField = new JTextField();
        private final JLabel transportLabel = new JLabel("Transport: unknown");
        private final boolean forceReadOnly;
        private GraphQLHttpMessageCodec.DecodedRequest decoded;
        private String baselineOperationName = "";

        private Editor(UserInterface userInterface, boolean forceReadOnly)
        {
            this.forceReadOnly = forceReadOnly;
            this.queryEditor = userInterface.createRawEditor(EditorOptions.WRAP_LINES);
            this.variablesEditor = userInterface.createRawEditor(EditorOptions.WRAP_LINES);

            JPanel meta = new JPanel(new GridLayout(2, 1, 4, 4));
            meta.add(transportLabel);
            JPanel opPanel = new JPanel(new BorderLayout(4, 4));
            opPanel.add(new JLabel("Operation Name"), BorderLayout.WEST);
            opPanel.add(operationNameField, BorderLayout.CENTER);
            meta.add(opPanel);

            JSplitPane split = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                new JScrollPane(queryEditor.uiComponent()),
                new JScrollPane(variablesEditor.uiComponent())
            );
            split.setResizeWeight(0.6);
            panel.add(meta, BorderLayout.NORTH);
            panel.add(split, BorderLayout.CENTER);
        }

        @Override
        public HttpRequest getRequest()
        {
            if (decoded == null || !decoded.editable() || forceReadOnly || !isModified())
            {
                return decoded == null ? null : decoded.originalRequest();
            }
            return GraphQLHttpMessageCodec.encodeEditedRequest(
                decoded,
                queryEditor.getContents().toString(),
                variablesEditor.getContents().toString(),
                operationNameField.getText()
            );
        }

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse)
        {
            Optional<GraphQLHttpMessageCodec.DecodedRequest> parsed = requestResponse == null
                ? Optional.empty()
                : GraphQLHttpMessageCodec.decodeRequest(requestResponse.request());
            if (parsed.isEmpty())
            {
                decoded = null;
                queryEditor.setContents(ByteArray.byteArray(""));
                variablesEditor.setContents(ByteArray.byteArray(""));
                operationNameField.setText("");
                operationNameField.setEditable(false);
                queryEditor.setEditable(false);
                variablesEditor.setEditable(false);
                transportLabel.setText("Transport: unsupported");
                return;
            }

            decoded = parsed.get();
            baselineOperationName = decoded.request().operationName == null ? "" : decoded.request().operationName;
            queryEditor.setContents(ByteArray.byteArray(decoded.request().query == null ? "" : decoded.request().query));
            variablesEditor.setContents(ByteArray.byteArray(graphqlhunter.GraphQLHunterJson.write(decoded.request().variables == null ? new java.util.LinkedHashMap<>() : decoded.request().variables)));
            operationNameField.setText(baselineOperationName);
            boolean editable = decoded.editable() && !forceReadOnly;
            queryEditor.setEditable(editable);
            variablesEditor.setEditable(editable);
            operationNameField.setEditable(editable);
            transportLabel.setText("Transport: " + decoded.transportKind() + (editable ? " (editable)" : " (read-only)"));
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse)
        {
            return requestResponse != null && GraphQLHttpMessageCodec.decodeRequest(requestResponse.request()).isPresent();
        }

        @Override
        public String caption()
        {
            return "GraphQL";
        }

        @Override
        public java.awt.Component uiComponent()
        {
            return panel;
        }

        @Override
        public Selection selectedData()
        {
            return queryEditor.selection().orElse(null);
        }

        @Override
        public boolean isModified()
        {
            return decoded != null && decoded.editable() && !forceReadOnly && (
                queryEditor.isModified()
                    || variablesEditor.isModified()
                    || !baselineOperationName.equals(operationNameField.getText())
            );
        }
    }
}
