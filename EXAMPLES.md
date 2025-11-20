# GraphQL Hunter Examples

This directory contains example configurations and test cases.

## Example Public Endpoints

You can test GraphQL Hunter against these public GraphQL APIs:

### 1. Countries API (Recommended for testing)
```bash
python graphql-hunter.py -u https://countries.trevorblades.com/graphql
```

### 2. SpaceX API
```bash
python graphql-hunter.py -u https://api.spacex.land/graphql/
```

### 3. GitHub GraphQL API (requires authentication)
```bash
python graphql-hunter.py -u https://api.github.com/graphql -t YOUR_GITHUB_TOKEN
```

## Example Scenarios

### Scenario 1: Testing a New API

```bash
# Start with a quick scan to get an overview
python graphql-hunter.py -u https://api.example.com/graphql -p quick

# If issues are found, run a deep scan
python graphql-hunter.py -u https://api.example.com/graphql -p deep -o results.json

# Review the results
cat results.json | python -m json.tool
```

### Scenario 2: Authenticated Testing

```bash
# Test with API key
python graphql-hunter.py -u https://api.example.com/graphql \
  -H "X-API-Key: your-api-key-here" \
  -o authenticated-results.json

# Test with JWT token
python graphql-hunter.py -u https://api.example.com/graphql \
  -t eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... \
  -v
```

### Scenario 3: Stealth Testing

```bash
# Slow scan with delays to avoid detection
python graphql-hunter.py -u https://api.example.com/graphql \
  -p stealth \
  --delay 3 \
  --safe-mode \
  -o stealth-results.json
```

### Scenario 4: Focus on Specific Vulnerabilities

```bash
# Only test for injection vulnerabilities
python graphql-hunter.py -u https://api.example.com/graphql \
  --skip-info-disclosure \
  --skip-auth \
  --skip-dos \
  --skip-batching \
  --skip-aliasing \
  --skip-circular \
  --skip-mutation-fuzzing

# Only test authorization
python graphql-hunter.py -u https://api.example.com/graphql \
  --skip-introspection \
  --skip-info-disclosure \
  --skip-injection \
  --skip-dos \
  --skip-batching \
  --skip-aliasing \
  --skip-circular \
  --skip-mutation-fuzzing
```

### Scenario 5: Testing Through a Proxy (Burp Suite)

```bash
# Route through Burp Suite to see all requests
python graphql-hunter.py -u https://api.example.com/graphql \
  --proxy http://127.0.0.1:8080 \
  -v
```

## Interpreting Results

### Critical Findings Example

```json
{
  "title": "SQL Injection Vulnerability Detected",
  "severity": "CRITICAL",
  "description": "SQL error messages detected when testing query.field with injection payload",
  "impact": "SQL injection allows attackers to manipulate database queries...",
  "remediation": "Use parameterized queries or ORM methods...",
  "cwe": "CWE-89: SQL Injection",
  "evidence": {
    "query": "exampleQuery",
    "argument": "id",
    "payload": "' OR '1'='1"
  }
}
```

### What to do:
1. Verify the finding manually
2. Fix the vulnerability
3. Re-scan to confirm fix
4. Document the fix

## Testing Your Own APIs

Before testing:

1. ✅ Get written permission
2. ✅ Test in development/staging first  
3. ✅ Use --safe-mode initially
4. ✅ Start with quick profile
5. ✅ Gradually increase scan depth

## False Positives

Some findings may be false positives:

- **Introspection Enabled** - May be acceptable in development
- **Verbose Errors** - May be intentional for debugging
- **Circular References** - Common pattern, risk depends on depth limits

Always verify findings manually before reporting them as vulnerabilities.

