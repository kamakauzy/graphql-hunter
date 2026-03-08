package graphqlhunter.burp;

import graphqlhunter.GraphQLHunterModels;
import graphqlhunter.GraphQLHunterModels.RecentRequestEntry;
import graphqlhunter.GraphQLHunterModels.ScanRequest;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public final class RecentRequestHistory
{
    private RecentRequestHistory()
    {
    }

    public static List<RecentRequestEntry> upsert(List<RecentRequestEntry> existing, ScanRequest request)
    {
        List<RecentRequestEntry> history = new ArrayList<>();
        if (existing != null)
        {
            existing.forEach(entry -> history.add(entry.copy()));
        }
        if (request == null || request.url == null || request.url.isBlank() || request.query == null || request.query.isBlank())
        {
            return trim(history);
        }

        String now = Instant.now().toString();
        String fingerprint = GraphQLHunterModels.fingerprintFor(request);
        for (int index = 0; index < history.size(); index++)
        {
            RecentRequestEntry entry = history.get(index);
            if (fingerprint.equals(entry.fingerprint))
            {
                entry.source = request.source;
                entry.url = request.url;
                entry.method = request.method;
                entry.operationName = request.operationName;
                entry.query = request.query;
                entry.variables = GraphQLJsonClone.deepCopy(request.variables);
                entry.headers = new java.util.LinkedHashMap<>(request.headers);
                entry.batch = request.batch;
                entry.lastSeenAt = now;
                entry.seenCount += 1;
                history.remove(index);
                history.add(0, entry);
                return trim(history);
            }
        }

        RecentRequestEntry entry = RecentRequestEntry.fromScanRequest(request.copy(), now);
        history.add(0, entry);
        return trim(history);
    }

    private static List<RecentRequestEntry> trim(List<RecentRequestEntry> history)
    {
        while (history.size() > GraphQLHunterModels.MAX_RECENT_REQUESTS)
        {
            history.remove(history.size() - 1);
        }
        return history;
    }

    private static final class GraphQLJsonClone
    {
        private static Object deepCopy(Object value)
        {
            if (value == null)
            {
                return null;
            }
            return graphqlhunter.GraphQLHunterJson.mapper().convertValue(
                graphqlhunter.GraphQLHunterJson.mapper().valueToTree(value),
                Object.class
            );
        }
    }
}
