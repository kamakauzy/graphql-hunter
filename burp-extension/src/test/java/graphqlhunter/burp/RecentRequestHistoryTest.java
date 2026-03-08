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
}
