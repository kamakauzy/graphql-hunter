# Request Import Feature

## Overview

GraphQL Hunter now supports importing requests from various formats, making it easy to test endpoints without manually typing headers, queries, and variables.

CLI note:
- Preferred commands use the installed CLI: `gqlh ...`
- Source-checkout fallback: `python3 gqlh.py ...`

## Supported Formats

### 1. Postman Collection (JSON)
Import entire Postman collections and extract all GraphQL requests:

```bash
python graphql-hunter.py --import my-collection.json --list-imported
python graphql-hunter.py --import my-collection.json -u https://api.example.com/graphql
```

**Features:**
- Automatically detects Postman Collection v2.1 format
- Extracts all requests recursively (including folders)
- Preserves headers, queries, variables, and operation names
- Lists all available requests with `--list-imported`

### 2. JSON Request Files
Simple JSON format for individual requests:

```json
{
  "name": "My Request",
  "url": "https://api.example.com/graphql",
  "method": "POST",
  "headers": {
    "Authorization": "Bearer TOKEN",
    "Content-Type": "application/json"
  },
  "query": "mutation { ... }",
  "variables": { "key": "value" },
  "operation_name": "MyMutation"
}
```

```bash
python graphql-hunter.py --import request.json --validate-auth
```

### 3. YAML Request Files
Same format as JSON but in YAML:

```yaml
name: My Request
url: https://api.example.com/graphql
headers:
  Authorization: Bearer TOKEN
query: |
  mutation { ... }
variables:
  key: value
```

```bash
python graphql-hunter.py --import request.yaml
```

### 4. cURL Commands
Import directly from cURL command strings:

```bash
python graphql-hunter.py --import-curl "curl -X POST https://api.example.com/graphql -H 'Authorization: Bearer TOKEN' -d '{\"query\":\"{__typename}\"}'"
```

You can also point `--import` at a text file containing a cURL command:

```bash
python graphql-hunter.py --import saved-request.txt --list-imported
```

### 5. Raw HTTP Requests
Parse raw HTTP request strings:

```bash
python graphql-hunter.py --import-raw-http "POST /graphql HTTP/1.1
Host: api.example.com
Authorization: Bearer TOKEN

{\"query\":\"{__typename}\"}"
```

## Usage Examples

### Example 1: Import and List Requests
```bash
# Import Postman collection and see what's available
python graphql-hunter.py --import collection.json --list-imported
```

### Example 2: Import and Use for Testing
```bash
# Import request and use it for scanning
python graphql-hunter.py --import request.json -u https://api.example.com/graphql

# Import and validate auth
python graphql-hunter.py --import request.json --validate-auth
```

### Example 3: Import from cURL
```bash
# Copy cURL from browser DevTools and import
python graphql-hunter.py --import-curl "$(pbpaste)" --validate-auth
```

### Example 4: Combine Import with Custom Headers
```bash
# Import request but override/add headers
python graphql-hunter.py --import request.json \
  -H "X-Custom-Header: value" \
  -H "Authorization: Bearer NEW_TOKEN"
```

## How It Works

1. **Auto-detection**: The tool automatically detects file format based on extension
2. **Postman Collections**: Recursively extracts all requests from folders and subfolders
3. **Header Merging**: Imported headers are merged with CLI headers, and explicit CLI headers take precedence
4. **Query Extraction**: Automatically extracts GraphQL queries and variables
5. **Operation Names**: Detects operation names from queries

## Integration with Auth Validation

When you import a request and use `--validate-auth`, the tool will:
- Use the imported query/mutation for validation
- Use imported variables if provided
- Compare responses with/without imported headers

Example:
```bash
python graphql-hunter.py --import request.json --validate-auth
```

## Benefits

1. **No Manual Typing**: Import requests directly from Postman, browser DevTools, etc.
2. **Batch Testing**: Import Postman collections to test multiple endpoints
3. **Easy Sharing**: Share request files (JSON/YAML) with team members
4. **Version Control**: Store request definitions in git
5. **Consistency**: Use same requests across different testing tools

## File Format Examples

See `examples/` directory for:
- `example_request.json` - JSON format example
- `example_request.yaml` - YAML format example

## Limitations

- Postman Collection v2.1 format only (v2.0 may work but not tested)
- Only extracts GraphQL requests (other request types are skipped)
- Variables in Postman collections must be in JSON format
- cURL parsing focuses on common `-X`, `-H`, `-d` / `--data-raw`, and URL patterns

## Future Enhancements

Potential improvements:
- Support for Insomnia collections
- Support for HTTPie commands
- Support for OpenAPI/Swagger specs
- Batch testing of imported requests
- Export requests back to Postman format
