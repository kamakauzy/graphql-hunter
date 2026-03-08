package graphqlhunter.burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;

public final class GraphQLResponseEditorProvider implements HttpResponseEditorProvider
{
    private final UserInterface userInterface;

    public GraphQLResponseEditorProvider(UserInterface userInterface)
    {
        this.userInterface = userInterface;
    }

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext context)
    {
        return new Editor(userInterface);
    }

    private static final class Editor implements ExtensionProvidedHttpResponseEditor
    {
        private final RawEditor rawEditor;
        private HttpRequestResponse requestResponse;

        private Editor(UserInterface userInterface)
        {
            this.rawEditor = userInterface.createRawEditor(EditorOptions.READ_ONLY, EditorOptions.WRAP_LINES);
            this.rawEditor.setEditable(false);
        }

        @Override
        public HttpResponse getResponse()
        {
            return requestResponse == null ? null : requestResponse.response();
        }

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse)
        {
            this.requestResponse = requestResponse;
            java.util.Optional<GraphQLHttpMessageCodec.DecodedResponse> decoded = requestResponse == null
                ? java.util.Optional.empty()
                : GraphQLHttpMessageCodec.decodeResponse(requestResponse);
            rawEditor.setContents(ByteArray.byteArray(decoded.map(GraphQLHttpMessageCodec.DecodedResponse::prettyText).orElse("")));
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse)
        {
            return requestResponse != null && GraphQLHttpMessageCodec.decodeResponse(requestResponse).isPresent();
        }

        @Override
        public String caption()
        {
            return "GraphQL";
        }

        @Override
        public java.awt.Component uiComponent()
        {
            return rawEditor.uiComponent();
        }

        @Override
        public Selection selectedData()
        {
            return rawEditor.selection().orElse(null);
        }

        @Override
        public boolean isModified()
        {
            return false;
        }
    }
}
