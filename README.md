# GraphQL Hunter

```
   ____                 _      ___  _       _   _             _            
  / ___|_ __ __ _ _ __ | |__  / _ \| |     | | | |_   _ _ __ | |_ ___ _ __ 
 | |  _| '__/ _` | '_ \| '_ \| | | | |     | |_| | | | | '_ \| __/ _ \ '__|
 | |_| | | | (_| | |_) | | | | |_| | |___  |  _  | |_| | | | | ||  __/ |   
  \____|_|  \__,_| .__/|_| |_|\__\_\_____| |_| |_|\__,_|_| |_|\__\___|_|   
                 |_|                                                        
```

A comprehensive GraphQL security testing tool that performs automated vulnerability scanning on GraphQL APIs. GraphQL Hunter tests for a wide range of security issues including injection vulnerabilities, authentication bypass, DoS vectors, and more.

## Features

### [+] Comprehensive Security Scanning

- **Introspection Analysis** - Detects if introspection is enabled and analyzes the schema for sensitive fields
- **Information Disclosure** - Tests for stack traces, debug mode, verbose errors, and field suggestions
- **Authentication/Authorization** - Checks for missing auth, unauthenticated access, and field-level authorization issues
- **Injection Testing** - SQL injection, NoSQL injection, and command injection detection
- **DoS Vectors** - Deep nesting, field duplication, circular queries, and complexity limit testing
- **Batching Attacks** - Tests query batching support and batch size limits
- **Aliasing Abuse** - Detects field aliasing vulnerabilities that can cause resource exhaustion
- **Mutation Security** - Identifies dangerous mutations, IDOR vulnerabilities, and unauthorized access

### [+] User-Friendly Interface

- Colored terminal output for easy reading
- Real-time progress reporting
- Detailed finding descriptions with CWE references
- Severity-based classification (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- JSON export for integration with other tools

### [+] Flexible Configuration

- **Scan Profiles**: Quick, Standard, Deep, and Stealth modes
- **Safe Mode**: Skips potentially destructive DoS tests
- **Custom Headers**: Support for authentication tokens and custom headers
- **Rate Limiting**: Configurable delays between requests
- **Proxy Support**: HTTP/HTTPS/SOCKS proxy configuration
- **Selective Scanning**: Skip specific scanners as needed

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Required Packages

- `requests` - HTTP client library
- `colorama` - Cross-platform colored terminal output
- `pyyaml` - YAML configuration file support

## Usage

### Basic Scan

```bash
python graphql-hunter.py -u https://api.example.com/graphql
```

### Scan with Authentication

```bash
# Using Bearer token
python graphql-hunter.py -u https://api.example.com/graphql -t YOUR_TOKEN

# Using custom headers
python graphql-hunter.py -u https://api.example.com/graphql -H "Authorization: Bearer TOKEN"
python graphql-hunter.py -u https://api.example.com/graphql -H "X-API-Key: KEY" -H "X-User-ID: 123"
```

### Scan Profiles

```bash
# Quick scan (fast, minimal tests)
python graphql-hunter.py -u https://api.example.com/graphql -p quick

# Standard scan (balanced coverage) - DEFAULT
python graphql-hunter.py -u https://api.example.com/graphql -p standard

# Deep scan (thorough, all tests)
python graphql-hunter.py -u https://api.example.com/graphql -p deep

# Stealth scan (slow, low detection risk)
python graphql-hunter.py -u https://api.example.com/graphql -p stealth --delay 2
```

### Safe Mode

Skip potentially destructive DoS tests:

```bash
python graphql-hunter.py -u https://api.example.com/graphql --safe-mode
```

### Output Options

```bash
# Save results to JSON file
python graphql-hunter.py -u https://api.example.com/graphql -o results.json

# Verbose mode (show requests/responses)
python graphql-hunter.py -u https://api.example.com/graphql -v

# Disable colors (for piping to file)
python graphql-hunter.py -u https://api.example.com/graphql --no-color > scan.txt
```

### Selective Scanning

```bash
# Skip specific scanners
python graphql-hunter.py -u https://api.example.com/graphql --skip-dos --skip-batching

# Only run introspection and injection tests
python graphql-hunter.py -u https://api.example.com/graphql \
  --skip-info-disclosure \
  --skip-auth \
  --skip-dos \
  --skip-batching \
  --skip-aliasing \
  --skip-circular \
  --skip-mutation-fuzzing
```

### Proxy Usage

```bash
# HTTP proxy
python graphql-hunter.py -u https://api.example.com/graphql --proxy http://127.0.0.1:8080

# Use with Burp Suite
python graphql-hunter.py -u https://api.example.com/graphql --proxy http://127.0.0.1:8080
```

## Command Line Options

```
Required Arguments:
  -u, --url URL                 GraphQL endpoint URL

Authentication & Headers:
  -H, --header HEADER           Custom headers (can be used multiple times)
  -t, --token TOKEN             Bearer token for authentication

Scan Configuration:
  -p, --profile PROFILE         Scan profile: quick, standard, deep, stealth (default: standard)
  --safe-mode                   Skip potentially destructive DoS tests
  --delay SECONDS               Delay between requests in seconds (default: 0)

Scanner Selection:
  --skip-introspection          Skip introspection scanner
  --skip-info-disclosure        Skip information disclosure checks
  --skip-auth                   Skip authentication/authorization tests
  --skip-injection              Skip injection tests
  --skip-dos                    Skip DoS vector tests
  --skip-batching               Skip batching attack tests
  --skip-aliasing               Skip aliasing abuse tests
  --skip-circular               Skip circular query tests
  --skip-mutation-fuzzing       Skip mutation fuzzing

Output Options:
  -o, --output FILE             Output JSON file path
  -v, --verbose                 Verbose output (show requests/responses)
  --no-color                    Disable colored output

Proxy Settings:
  --proxy URL                   Proxy URL (e.g., http://127.0.0.1:8080)
```

## Understanding Results

### Severity Levels

- **CRITICAL** - Severe vulnerabilities requiring immediate action (e.g., SQL injection)
- **HIGH** - Serious issues that should be fixed soon (e.g., unauthenticated introspection)
- **MEDIUM** - Moderate issues that should be addressed (e.g., batching enabled)
- **LOW** - Minor issues with limited impact (e.g., verbose errors)
- **INFO** - Informational findings (e.g., introspection disabled - good!)

### Exit Codes

- `0` - No critical or high severity findings
- `1` - High severity findings detected
- `2` - Critical severity findings detected
- `130` - Scan interrupted by user (Ctrl+C)

## Common Vulnerabilities Detected

### 1. Introspection Enabled

**Issue**: GraphQL introspection is enabled in production  
**Impact**: Attackers can discover the entire API structure  
**Remediation**: Disable introspection in production environments

### 2. SQL Injection

**Issue**: User input is not properly sanitized in database queries  
**Impact**: Database compromise, data theft, authentication bypass  
**Remediation**: Use parameterized queries and input validation

### 3. Authentication Bypass

**Issue**: API endpoints accessible without authentication  
**Impact**: Unauthorized access to data and operations  
**Remediation**: Implement authentication middleware

### 4. DoS via Deep Nesting

**Issue**: No query depth limits enforced  
**Impact**: Resource exhaustion through deeply nested queries  
**Remediation**: Implement query depth limiting (recommended: 5-7 levels)

### 5. Batching Attacks

**Issue**: Unlimited query batching allowed  
**Impact**: Rate limit bypass, resource exhaustion  
**Remediation**: Limit batch sizes to 5-10 queries maximum

### 6. Field Aliasing Abuse

**Issue**: No limits on field aliases  
**Impact**: Resource exhaustion through aliased field multiplication  
**Remediation**: Implement query cost analysis that counts aliases

### 7. IDOR in Mutations

**Issue**: Mutations accept ID parameters without authorization checks  
**Impact**: Users can modify other users' data  
**Remediation**: Implement object-level authorization checks

## Remediation Guide

### General GraphQL Security Best Practices

1. **Disable Introspection in Production**
   ```javascript
   // Apollo Server example
   const server = new ApolloServer({
     introspection: process.env.NODE_ENV !== 'production'
   });
   ```

2. **Implement Query Depth Limiting**
   ```javascript
   // Using graphql-depth-limit
   import depthLimit from 'graphql-depth-limit';
   
   const server = new ApolloServer({
     validationRules: [depthLimit(7)]
   });
   ```

3. **Implement Query Complexity Analysis**
   ```javascript
   // Using graphql-query-complexity
   import { createComplexityLimitRule } from 'graphql-validation-complexity';
   
   const server = new ApolloServer({
     validationRules: [createComplexityLimitRule(1000)]
   });
   ```

4. **Require Authentication**
   ```javascript
   // Apollo Server context example
   const server = new ApolloServer({
     context: ({ req }) => {
       const token = req.headers.authorization || '';
       if (!token) throw new Error('Not authenticated');
       return { user: verifyToken(token) };
     }
   });
   ```

5. **Implement Field-Level Authorization**
   ```javascript
   // Using graphql-shield
   import { shield, rule } from 'graphql-shield';
   
   const isAuthenticated = rule()(async (parent, args, ctx) => {
     return ctx.user !== null;
   });
   
   const permissions = shield({
     Query: {
       sensitiveData: isAuthenticated
     }
   });
   ```

6. **Disable Query Batching (or limit it)**
   ```javascript
   // Apollo Server
   const server = new ApolloServer({
     allowBatchedHttpRequests: false
   });
   ```

7. **Implement Rate Limiting**
   ```javascript
   // Using graphql-rate-limit
   import { createRateLimitDirective } from 'graphql-rate-limit';
   
   const rateLimitDirective = createRateLimitDirective({
     identifyContext: (ctx) => ctx.user.id
   });
   ```

## Testing on Your Own APIs

GraphQL Hunter is designed for **authorized security testing only**. Before testing:

1. Obtain written permission from the API owner
2. Test in a non-production environment when possible
3. Use `--safe-mode` to avoid DoS tests
4. Use `--delay` to avoid overwhelming the target
5. Review findings carefully - false positives are possible

**[!] WARNING**: Unauthorized testing may be illegal. Always get permission first.

## Example Output

```
===============================================================
                                                               
   GRAPHQL HUNTER - Security Scanner v1.0                     
   Comprehensive GraphQL API Security Testing                 
                                                               
===============================================================

[i] Target: https://api.example.com/graphql
[i] Profile: standard
----------------------------------------------------------------------

[*] Introspection
----------------------------------------------------------------------
[!] Introspection is ENABLED

[MEDIUM] GraphQL Introspection Enabled
  Description: The GraphQL endpoint has introspection enabled...
  Impact: Attackers can map the entire API surface area...
  Remediation: Disable introspection in production environments...

[*] SCAN SUMMARY
----------------------------------------------------------------------

Total Findings: 5
  Critical: 1
  High: 2
  Medium: 1
  Low: 1

Overall Risk: CRITICAL - Immediate action required!
```

## Troubleshooting

### Connection Errors

```
[X] Failed to initialize client: Connection failed
```
**Solution**: Check URL, network connectivity, and SSL certificates

### Timeout Errors

```
[!] Request timeout
```
**Solution**: Increase timeout with a custom configuration or use `--delay`

### No Schema Available

```
[i] Schema not available, skipping...
```
**Solution**: Introspection is disabled. Some tests will be limited.

## Contributing

This is a security tool - contributions should focus on:
- Adding new vulnerability checks
- Improving detection accuracy
- Reducing false positives
- Better reporting formats

## Contact

For questions, suggestions, or security research collaboration:

**Brad Crawford**  
Email: brad@securit360.com  
GitHub: [@kamakauzy](https://github.com/kamakauzy)

## License

This tool is provided for educational and authorized testing purposes only.

## Disclaimer

**GraphQL Hunter is a security testing tool. Use responsibly and legally.**

- Only test systems you have permission to test
- Be aware that some tests may impact system performance
- The authors are not responsible for misuse of this tool
- Always follow responsible disclosure practices

## Version

GraphQL Hunter v1.0 - November 2025

---

**[+] Happy (Ethical) Hunting!**
