package graphqlhunter.burp;

import graphqlhunter.GraphQLHunterModels;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RecentRequestHistoryTest
{
    @Test
    void duplicateRequestsAreDedupedAndPromoted()
    {
        GraphQLHunterModels.ScanRequest request = new GraphQLHunterModels.ScanRequest();
        request.source = "burp-proxy";
        request.url = "https://api.example.com/graphql";
        request.method = "POST";
        request.query = "{ __typename }";

        List<GraphQLHunterModels.RecentRequestEntry> history = RecentRequestHistory.upsert(new ArrayList<>(), request);
        history = RecentRequestHistory.upsert(history, request);

        assertEquals(1, history.size());
        assertEquals(2, history.getFirst().seenCount);
    }

    @Test
    void preservesContentTypeAndRawBodyInHistory()
    {
        GraphQLHunterModels.ScanRequest request = new GraphQLHunterModels.ScanRequest();
        request.source = "burp-proxy";
        request.url = "https://api.example.com/graphql";
        request.method = "POST";
        request.query = "mutation Upload($file: Upload!) { upload(file: $file) { ok } }";
        request.operationName = "Upload";
        request.contentType = "multipart/form-data; boundary=----Boundary";
        request.rawBody = "------Boundary\r\nContent-Disposition: form-data; name=\"operations\"\r\n\r\n{}";

        List<GraphQLHunterModels.RecentRequestEntry> history = RecentRequestHistory.upsert(new ArrayList<>(), request);
        GraphQLHunterModels.ScanRequest restored = history.getFirst().toScanRequest();

        assertEquals("multipart/form-data; boundary=----Boundary", restored.contentType);
        assertEquals(request.rawBody, restored.rawBody);
    }
}
