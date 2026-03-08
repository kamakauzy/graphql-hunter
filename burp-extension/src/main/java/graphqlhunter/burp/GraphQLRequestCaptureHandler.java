package graphqlhunter.burp;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import graphqlhunter.GraphQLHunterCore;
import graphqlhunter.GraphQLHunterModels.ScanRequest;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Consumer;

public final class GraphQLRequestCaptureHandler implements HttpHandler
{
    private final Consumer<ScanRequest> consumer;
    private final Function<HttpRequestToBeSent, RequestToBeSentAction> requestContinuation;
    private final Function<HttpResponseReceived, ResponseReceivedAction> responseContinuation;

    public GraphQLRequestCaptureHandler(Consumer<ScanRequest> consumer)
    {
        this(
            consumer,
            RequestToBeSentAction::continueWith,
            ResponseReceivedAction::continueWith
        );
    }

    GraphQLRequestCaptureHandler(
        Consumer<ScanRequest> consumer,
        Function<HttpRequestToBeSent, RequestToBeSentAction> requestContinuation,
        Function<HttpResponseReceived, ResponseReceivedAction> responseContinuation
    )
    {
        this.consumer = consumer;
        this.requestContinuation = requestContinuation;
        this.responseContinuation = responseContinuation;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request)
    {
        if (request.toolSource().isFromTool(ToolType.PROXY, ToolType.REPEATER, ToolType.TARGET))
        {
            Map<String, String> headers = new LinkedHashMap<>();
            request.headers().forEach(header -> headers.put(header.name(), header.value()));
            Optional<ScanRequest> parsed = GraphQLHunterCore.parseRequest(
                "burp-" + request.toolSource().toolType().toolName().toLowerCase(),
                request.url(),
                request.method(),
                headers,
                request.bodyToString()
            );
            parsed.ifPresent(consumer);
        }
        return requestContinuation.apply(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response)
    {
        return responseContinuation.apply(response);
    }
}
