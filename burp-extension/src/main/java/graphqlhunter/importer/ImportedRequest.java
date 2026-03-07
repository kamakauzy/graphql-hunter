package graphqlhunter.importer;

import graphqlhunter.GraphQLHunterModels;

import java.util.LinkedHashMap;
import java.util.Map;

public final class ImportedRequest
{
    public String name = "Imported Request";
    public String folder = "";
    public String url = "";
    public String method = "POST";
    public String query = "";
    public Object variables = new LinkedHashMap<String, Object>();
    public String operationName = "";
    public Map<String, String> headers = new LinkedHashMap<>();

    public GraphQLHunterModels.ScanRequest toScanRequest()
    {
        GraphQLHunterModels.ScanRequest request = new GraphQLHunterModels.ScanRequest();
        request.source = folder == null || folder.isBlank() ? name : folder + "/" + name;
        request.url = url;
        request.method = method;
        request.query = query;
        request.variables = variables;
        request.operationName = operationName;
        request.headers = new LinkedHashMap<>(headers);
        return request;
    }
}
