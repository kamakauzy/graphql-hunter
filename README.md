# GraphQL Hunter

<p align="center">
  <img src="graphql-hunter-banner.png" alt="GraphQL Hunter" width="800"/>
</p>

> *"Because GraphQL APIs deserve a security audit that's more thorough than your code reviews."* 😎

A comprehensive GraphQL security testing tool that hunts down vulnerabilities in GraphQL APIs with the precision of a caffeinated security researcher at 3 AM. Tests for injection vulnerabilities, authentication bypass, DoS vectors, and more. Basically, it's that friend who tells you the hard truths about your API security.

## Features

### [+] Comprehensive Security Scanning

*AKA "The Bad News You Need to Hear"*

- **Introspection Analysis** - Checks if you left the schema docs wide open (spoiler: you probably did)
- **Information Disclosure** - Finds those helpful stack traces you're leaking to attackers
- **Authentication/Authorization** - Tests if your "auth" is more like a suggestion than a requirement
- **Injection Testing** - SQL injection, NoSQL injection, command injection... basically all the injections
- **DoS Vectors** - See how many nested queries it takes to make your server cry
- **Batching Attacks** - Tests if attackers can spam your API like it's 2010
- **Aliasing Abuse** - Checks if you're multiplying vulnerabilities like rabbits
- **Mutation Security** - Because `deletEverything` shouldn't be publicly accessible
- **Rate Limiting** - Tests if your API can handle a flood of requests (spoiler: probably not)
- **CSRF Protection** - Checks if mutations are vulnerable to cross-site request forgery
- **File Upload** - Tests for path traversal, oversized files, and malicious extensions
- **Mass Assignment** - Detects if mutations accept unexpected sensitive fields
- **Brute-Force Protection** - Tests login mutations for rate limiting and account lockout
- **Token Expiration** - Verifies JWT tokens properly expire and are rejected when expired

### [+] User-Friendly Interface

*"Friendly" being relative when it's roasting your security posture*

- Colored terminal output (red means panic, green means celebrate)
- **Beautiful HTML reports** (impress management with gradients!)
- JSON export (for when you need machine-readable proof)
- Real-time progress reporting (watch the findings roll in!)
- Detailed descriptions with CWE references (so you can sound smart in meetings)
- Severity-based classification (CRITICAL = update your resume)
- Print-friendly HTML layouts (for that paper trail)

### [+] Flexible Configuration

*Because one size fits none*

- **Scan Profiles**: Quick, Standard, Deep, and Stealth modes
- **Safe Mode**: For when you don't want to accidentally DoS production (again)
- **Custom Headers**: Bring your own auth tokens
- **Rate Limiting**: Be a polite hacker
- **Proxy Support**: Route through Burp Suite like a pro
- **Selective Scanning**: Skip the scanners that hurt your feelings

## Quick Start

### Installation

```bash
# Clone the repository (you know, the usual dance)
git clone https://github.com/kamakauzy/graphql-hunter.git
cd graphql-hunter

# Install dependencies (shouldn't take longer than making coffee)
pip install -r requirements.txt

# Optional: install CLI entrypoints
python -m pip install .

# Run a test scan (prepare for bad news)
gqlh -u https://countries.trevorblades.com/graphql
```

CLI note:
- Preferred commands: `gqlh ...` or `graphql-hunter ...` after `pip install .`
- Source-checkout fallback: `python3 gqlh.py ...`
- Legacy `python3 graphql-hunter.py ...` usage still works

### Basic Usage

```bash
# Basic scan (the gentle introduction)
python graphql-hunter.py -u https://api.example.com/graphql

# Authenticated scan (pretend you're a real user)
python graphql-hunter.py -u https://api.example.com/graphql -t YOUR_TOKEN

# Deep scan with output (for when you want ALL the bad news)
python graphql-hunter.py -u https://api.example.com/graphql -p deep -o results.json

# Safe mode (skip DoS tests, your ops team will thank you)
python graphql-hunter.py -u https://api.example.com/graphql --safe-mode

# Stealth mode (be sneaky, move slowly, don't wake the WAF)
python graphql-hunter.py -u https://api.example.com/graphql -p stealth --delay 2
```

### Burp Suite Professional Addon (`.jar`)

This repository now also includes a **native Burp Suite Professional addon** under `burp-extension/`.

What it does today:
- installs as a **Java `.jar`** in Burp Pro
- adds a **GraphQL Hunter** suite tab
- imports GraphQL requests from Burp via the context menu
- carries imported auth headers into the Burp auth workspace automatically
- supports runtime-only auth secrets that are not persisted with Burp extension state
- validates auth against an isolated anonymous baseline instead of reusing the authenticated Burp session
- can load auth profiles from an external YAML path instead of only the bundled example config
- includes Burp-side workspaces for:
  - request editing, including operation-name preservation
  - recent GraphQL request history captured from Burp traffic
  - auth setup and validation
  - pasted import parsing with content-based auto-detect for JSON/Postman/YAML
  - discovery analysis and application
  - JSON / HTML export with redacted replay artifacts and real scan coverage metadata
  - native Burp issue publication
- runs focused native checks against the imported endpoint:
  - introspection
  - information disclosure
  - auth exposure differentials and login brute-force protection heuristics
  - batching and large-batch review
  - injection, including query-only time-based and conservative boolean-differential probes in deep-enabled profiles
  - DoS / depth / complexity
  - aliasing
  - circular query review
  - XSS reflection review
  - JWT review, including `alg:none` and expired-token acceptance checks
  - concurrent rate limiting
  - CSRF review, including missing-origin suppression and cross-site origin validation probes
  - file upload surface review plus live probes for string-backed, multipart, nested-target, and oversize upload mutations
  - mutation review heuristics

The Burp addon is **additive**. The existing Python CLI remains the primary standalone workflow and is unchanged.

Build the Burp addon:

```bash
cd burp-extension
./gradlew clean fatJar test
```

Artifact:

```bash
burp-extension/build/libs/GraphQLHunterBurp.jar
```

Load it in Burp Suite Professional:
1. Open **Extensions**.
2. Add a new **Java** extension.
3. Select `burp-extension/build/libs/GraphQLHunterBurp.jar`.
4. Use Burp's HTTP message context menu to send a GraphQL request to the **GraphQL Hunter** tab.
5. Use the tab's **Auth** and **Import & Discovery** workspaces to validate auth, parse pasted requests, auto-apply imported auth headers, analyze notes, manage runtime-only secrets, export findings with cURL / Burp replay snippets plus executed/skipped/failed scanner coverage, and publish findings as native Burp issues.

## Usage Guide

### Scan Profiles

*Choose your fighter*

```bash
# Quick scan (fast food of security scans)
python graphql-hunter.py -u https://api.example.com/graphql -p quick

# Standard scan (the Goldilocks option) - DEFAULT
python graphql-hunter.py -u https://api.example.com/graphql -p standard

# Deep scan (hold my coffee, this'll take a minute)
python graphql-hunter.py -u https://api.example.com/graphql -p deep

# Stealth scan (ninja mode activated 🥷)
python graphql-hunter.py -u https://api.example.com/graphql -p stealth --delay 2
```

### Authentication

*"No auth header, who dis?"*

```bash
# Using Bearer token (the modern way)
python graphql-hunter.py -u https://api.example.com/graphql -t YOUR_TOKEN

# Using custom headers (because you're special)
python graphql-hunter.py -u https://api.example.com/graphql -H "Authorization: Bearer TOKEN"
python graphql-hunter.py -u https://api.example.com/graphql -H "X-API-Key: KEY" -H "X-User-ID: 123"
```

### Advanced Authentication Workflows (OAuth, cookie sessions, CSRF)

GraphQL Hunter can also run **auth workflows** (token acquisition + refresh + cookie sessions) via **auth profiles** in `config/auth.yaml`.

```bash
# OAuth2 client-credentials (service-to-service)
python graphql-hunter.py -u https://api.example.com/graphql \
  --auth-profile oauth2_client_credentials \
  --auth-var client_id=YOUR_CLIENT_ID \
  --auth-var client_secret=YOUR_CLIENT_SECRET \
  --auth-var scope="read:graphql"

# OAuth2 auth-code (semi-manual: open URL, then paste code)
python graphql-hunter.py -u https://api.example.com/graphql \
  --auth-profile oauth2_auth_code \
  --auth-var client_id=YOUR_CLIENT_ID \
  --auth-var client_secret=YOUR_CLIENT_SECRET \
  --auth-var oauth_code=PASTE_CODE_HERE

# Cookie session + CSRF (semi-manual vars; steps defined in config/auth.yaml)
python graphql-hunter.py -u https://api.example.com/graphql \
  --auth-profile cookie_session_with_csrf \
  --auth-var username=YOUR_USERNAME \
  --auth-var password=YOUR_PASSWORD
```

Notes:
- The default auth config path is `config/auth.yaml` (safe-to-commit template; **do not store secrets** in it).
- You can also provide variables via environment variables prefixed with `GQLH_` (example: `GQLH_CLIENT_ID`, `GQLH_CLIENT_SECRET`).
- Verbose output and reports **redact** common secrets (tokens, cookies, passwords).

### Auth Wizard (interactive)

If you prefer an interactive prompt that outputs a ready-to-run command (without printing secrets), run:

```bash
python graphql-hunter.py --auth-wizard
```

### Auto-Discovery

*"Just figure it out from my notes"*

The tool can automatically discover authentication and configuration from notes, JSON, YAML files, or any text:

```bash
# Auto-discover from notes file
python graphql-hunter.py --auto-discover notes.txt

# Show what was discovered (without running scan)
python graphql-hunter.py --auto-discover notes.txt --show-discovery

# Auto-discover from multiple sources
python graphql-hunter.py --auto-discover notes.txt config.json request.yaml
```

**What it discovers:**
- URLs and endpoints
- Authentication methods (tokenAuth, OAuth, etc.)
- Credentials (email, password, tokens)
- Headers and tokens
- Queries and mutations from files
- Generates ready-to-run commands

**Example:** Provide a notes file with email/password/URL, and the tool will automatically:
1. Detect the authentication method
2. Configure the auth profile
3. Set up credentials
4. Run the scan

See `AUTO_DISCOVERY.md` for detailed documentation.

### Importing Requests

*"I already have these requests, why retype them?"*

GraphQL Hunter can import requests from various formats to make testing easier:

```bash
# Import from Postman Collection (JSON)
python graphql-hunter.py --import my-collection.json -u https://api.example.com/graphql

# Import from JSON file
python graphql-hunter.py --import request.json --validate-auth

# Import from YAML file
python graphql-hunter.py --import request.yaml -H "Authorization: Bearer TOKEN"

# Import from cURL command
python graphql-hunter.py --import-curl "curl -X POST https://api.example.com/graphql -H 'Authorization: Bearer TOKEN' -d '{\"query\":\"{__typename}\"}'"

# List all requests in a Postman collection
python graphql-hunter.py --import collection.json --list-imported
```

**Supported Formats:**
- **Postman Collection v2.1** - Automatically extracts all requests from collection
- **JSON** - Simple request format with url, headers, query, variables
- **YAML** - Same as JSON but in YAML format
- **cURL commands / cURL text files** - Parse cURL command strings or text files containing a cURL request
- **Raw HTTP** - Parse raw HTTP request strings

**Example JSON format:**
```json
{
  "url": "https://api.example.com/graphql",
  "headers": {
    "Authorization": "Bearer TOKEN"
  },
  "query": "mutation { ... }",
  "variables": { "key": "value" },
  "operation_name": "MyMutation"
}
```

When importing, the tool will automatically:
- Extract URL, headers, query, and variables
- Use the imported request for auth validation if `--validate-auth` is used
- Merge imported headers with command-line headers (CLI headers take precedence)
- Normalize JSON-string `variables` values into objects when possible

### Output Options

```bash
# Save results to JSON (for posterity and blame assignment)
python graphql-hunter.py -u https://api.example.com/graphql -o results.json

# Save results to HTML (pretty reports for management)
python graphql-hunter.py -u https://api.example.com/graphql --html report.html

# Both JSON and HTML (cover all your bases)
python graphql-hunter.py -u https://api.example.com/graphql -o results.json --html report.html

# Verbose mode (ALL the details, prepare for information overload)
python graphql-hunter.py -u https://api.example.com/graphql -v

# Disable colors (for logs that'll outlive us all)
python graphql-hunter.py -u https://api.example.com/graphql --no-color > scan.txt
```

Reports now distinguish:
- **confirmed** findings - runtime evidence strongly supports the issue
- **potential** findings - signals were observed, but impact still needs review
- **manual_review** findings - attack surface or heuristics that should be validated by a human

JSON/HTML output also includes status counts and confirmed-severity rollups so automation can reason about noise vs. confirmed risk.
The JSON report includes a `scan` section describing executed, skipped, and failed scanners so you can see exactly what coverage was achieved.

### Selective Scanning

*"I don't want to know about THAT problem"*

```bash
# Skip the scary scanners
python graphql-hunter.py -u https://api.example.com/graphql --skip-dos --skip-batching

# Only run the scanners you can handle emotionally
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

*For when you want to see EVERYTHING*

```bash
# HTTP proxy (route through Burp Suite)
python graphql-hunter.py -u https://api.example.com/graphql --proxy http://127.0.0.1:8080

# Watch the requests in real-time (it's oddly satisfying)
python graphql-hunter.py -u https://api.example.com/graphql --proxy http://127.0.0.1:8080 -v
```

## Examples & Test Cases

### Public Test Endpoints

*Practice makes perfect (or at least less embarrassing)*

```bash
# Countries API (Recommended - won't get you fired)
python graphql-hunter.py -u https://countries.trevorblades.com/graphql

# SpaceX API (because space is cool)
python graphql-hunter.py -u https://api.spacex.land/graphql/

# GitHub GraphQL API (bring your token or go home)
python graphql-hunter.py -u https://api.github.com/graphql -t YOUR_GITHUB_TOKEN
```

### Vulnerable Test Application

*For when you want to feel like a hacking god without the legal consequences*

**[Damn Vulnerable GraphQL Application (DVGA)](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application)** is perfect for practice:

```bash
# Clone and run DVGA (requires Docker, because of course it does)
git clone https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application.git
cd Damn-Vulnerable-GraphQL-Application
docker build -t dvga .
docker run -t -p 5013:5013 -e WEB_HOST=0.0.0.0 dvga

# Unleash GraphQL Hunter on it (it never stood a chance)
python graphql-hunter.py -u http://localhost:5013/graphql -p deep -o dvga-scan.json
```

DVGA contains intentional vulnerabilities perfect for testing:
- SQL Injection (the classic)
- OS Command Injection (execute order 66)
- Authorization bypass (walks right through the door)
- DoS vectors (makes servers go boom)
- Information disclosure (oversharing is caring?)
- And more! (it's vulnerable all the way down)

### Example Scenarios

**Scenario 1: Testing a New API**
```bash
# Start gentle (like a first date)
python graphql-hunter.py -u https://api.example.com/graphql -p quick

# If issues are found, go deeper (relationship getting serious)
python graphql-hunter.py -u https://api.example.com/graphql -p deep -o results.json

# Review the damage
cat results.json | python -m json.tool
```

**Scenario 2: Authenticated Testing**
```bash
# Test with API key (you've got the VIP pass)
python graphql-hunter.py -u https://api.example.com/graphql \
  -H "X-API-Key: your-api-key-here" \
  -o authenticated-results.json

# Test with JWT token (fancy!)
python graphql-hunter.py -u https://api.example.com/graphql \
  -t eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... \
  -v
```

**Scenario 3: Focus on Specific Vulnerabilities**
```bash
# Only test for injection (because that's bad enough)
python graphql-hunter.py -u https://api.example.com/graphql \
  --skip-info-disclosure \
  --skip-auth \
  --skip-dos \
  --skip-batching \
  --skip-aliasing \
  --skip-circular \
  --skip-mutation-fuzzing
```

## Command Line Options

*All the knobs and switches*

```
Required Arguments:
  -u, --url URL                 GraphQL endpoint URL

Authentication & Headers:
  -H, --header HEADER           Custom headers (can be used multiple times)
  -t, --token TOKEN             Bearer token for authentication

Auth Workflow Engine:
  --auth-config FILE            Auth config YAML path (default: config/auth.yaml)
  --auth-profile NAME           Auth profile name from auth config
  --auth-var KEY=VALUE          Auth variable override (can be used multiple times)
  --auth-detect                 Enable best-effort auth/CSRF diagnostics (default)
  --no-auth-detect              Disable best-effort auth/CSRF diagnostics
  --auth-wizard                 Interactive auth wizard (prints a ready-to-run command without exposing secrets)

Scan Configuration:
  -p, --profile PROFILE         Scan profile: quick, standard, deep, stealth (default: standard)
  --safe-mode                   Skip potentially destructive DoS tests
  --delay SECONDS               Delay between requests in seconds (defaults to profile setting)

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
  --skip-xss                    Skip XSS tests
  --skip-jwt                    Skip JWT security tests
  --skip-rate-limit             Skip rate limiting tests
  --skip-csrf                   Skip CSRF tests
  --skip-file-upload            Skip file upload tests
  --brute-force-attempts N      Number of brute-force attempts (defaults to profile setting)
  --rate-limit-concurrency N    Number of concurrent workers for rate limit tests
  --rate-limit-requests N       Total requests to send during rate limit tests

Output Options:
  -o, --output FILE             Output JSON file path
  --html FILE                   Output HTML report file path
  -v, --verbose                 Verbose output (show requests/responses)
  --no-color                    Disable colored output

Proxy Settings:
  --proxy URL                   Proxy URL (e.g., http://127.0.0.1:8080)
```

## Understanding Results

### Severity Levels

*The hierarchy of "oh no"*

- **CRITICAL** - Drop everything, fix this NOW (your API is basically a screen door on a submarine)
- **HIGH** - Fix this soon, like really soon (attackers are probably already exploiting it)
- **MEDIUM** - Should address this (before it becomes a HIGH)
- **LOW** - Minor issues (but death by a thousand paper cuts is still death)
- **INFO** - Informational (or as we call it, "the good news")

### Exit Codes

*For the automation enthusiasts*

- `0` - No **confirmed** critical/high findings
- `1` - Confirmed high severity findings detected
- `2` - Confirmed critical severity findings detected
- `130` - Scan interrupted by user (Ctrl+C is your friend)

### Interpreting Findings

*How to read the tea leaves*

Each finding now includes a **status**:
- **confirmed** - behavior strongly supports the issue
- **potential** - signal observed, but not fully proven
- **manual_review** - attack surface or heuristic that should be checked manually

Example critical finding:
```json
{
  "title": "SQL Injection Vulnerability Detected",
  "severity": "CRITICAL",
  "status": "confirmed",
  "scanner": "injection",
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

**Response Steps** (aka "Damage Control"):
1. Verify the finding manually (maybe it's wrong? Probably not though)
2. Fix the vulnerability (actually fix it, don't just add a TODO)
3. Re-scan to confirm fix (trust but verify)
4. Document the fix (future you will thank present you)

## Common Vulnerabilities Detected

*The Greatest Hits Album*

### 1. Introspection Enabled

**Issue**: GraphQL introspection is enabled in production  
**Impact**: Attackers get a free API map  
**Remediation**: Disable it. Just... disable it.

### 2. SQL Injection

**Issue**: User input goes straight to database (yikes)  
**Impact**: Database goes bye-bye  
**Remediation**: Parameterized queries are your friend

### 3. Authentication Bypass

**Issue**: API is as open as a 24/7 convenience store  
**Impact**: Unauthorized access to everything  
**Remediation**: Add actual authentication (novel concept!)

### 4. DoS via Deep Nesting

**Issue**: No query depth limits (infinite loops anyone?)  
**Impact**: Server becomes a space heater  
**Remediation**: Implement depth limiting (5-7 levels is reasonable)

### 5. Batching Attacks

**Issue**: Unlimited query batching (it's a buffet!)  
**Impact**: Rate limits become decorative  
**Remediation**: Limit batch sizes to 5-10 queries

### 6. Field Aliasing Abuse

**Issue**: No limits on field aliases (multiplication is fun!)  
**Impact**: One query becomes 100 queries  
**Remediation**: Count aliases in query cost

### 7. IDOR in Mutations

**Issue**: Can modify other users' data (whoops)  
**Impact**: Privacy? Never heard of her  
**Remediation**: Check if user owns the resource before mutating

### 8. Rate Limiting Missing

**Issue**: No rate limiting on API endpoints  
**Impact**: Brute-force attacks and DoS become trivial  
**Remediation**: Implement rate limiting (100-1000 requests/minute per IP)

### 9. CSRF Vulnerabilities

**Issue**: Mutations accept requests without Origin validation  
**Impact**: Attackers can perform actions on behalf of users  
**Remediation**: Validate Origin/Referer headers, use CSRF tokens, implement SameSite cookies

### 10. File Upload Vulnerabilities

**Issue**: File uploads vulnerable to path traversal, oversized files, malicious extensions  
**Impact**: Server compromise, DoS, unauthorized file access  
**Remediation**: Validate filenames, enforce size limits, check file types (MIME, not extension), store outside web root

### 11. Mass Assignment

**Issue**: Mutations accept unexpected sensitive fields (e.g., `role: "admin"`)  
**Impact**: Privilege escalation, unauthorized data modification  
**Remediation**: Use allowlists of accepted fields, explicitly exclude sensitive fields, validate all inputs

### 12. Weak Authentication

**Issue**: No brute-force protection, expired tokens still accepted  
**Impact**: Account compromise, indefinite token usage  
**Remediation**: Implement rate limiting on login, account lockout, CAPTCHA, enforce token expiration

## Remediation Guide

*How to fix the things we found*

### General GraphQL Security Best Practices

1. **Disable Introspection in Production**
   ```javascript
   // Apollo Server example
   const server = new ApolloServer({
     introspection: process.env.NODE_ENV !== 'production'
   });
   // Is it production? Then no schema for you!
   ```

2. **Implement Query Depth Limiting**
   ```javascript
   // Using graphql-depth-limit
   import depthLimit from 'graphql-depth-limit';
   
   const server = new ApolloServer({
     validationRules: [depthLimit(7)]  // 7 levels is plenty
   });
   ```

3. **Implement Query Complexity Analysis**
   ```javascript
   // Using graphql-query-complexity
   import { createComplexityLimitRule } from 'graphql-validation-complexity';
   
   const server = new ApolloServer({
     validationRules: [createComplexityLimitRule(1000)]  // Pick a number, any number
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
   // No token, no entry. Simple!
   ```

5. **Implement Field-Level Authorization**
   ```javascript
   // Using graphql-shield
   import { shield, rule } from 'graphql-shield';
   
   const isAuthenticated = rule()(async (parent, args, ctx) => {
     return ctx.user !== null;  // Must have user, sorry bots
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
     allowBatchedHttpRequests: false  // Just say no
   });
   ```

7. **Implement Rate Limiting**
   ```javascript
   // Using express-rate-limit or similar
   const rateLimit = require('express-rate-limit');
   
   const limiter = rateLimit({
     windowMs: 15 * 60 * 1000, // 15 minutes
     max: 100 // limit each IP to 100 requests per windowMs
   });
   
   app.use('/graphql', limiter);
   ```

8. **Protect Against CSRF**
   ```javascript
   // Validate Origin header for mutations
   app.use('/graphql', (req, res, next) => {
     if (req.method === 'POST' && req.body.query.includes('mutation')) {
       const origin = req.headers.origin;
       const expectedOrigin = process.env.ALLOWED_ORIGIN;
       if (origin !== expectedOrigin) {
         return res.status(403).json({ error: 'CSRF validation failed' });
       }
     }
     next();
   });
   ```

9. **Secure File Uploads**
   ```javascript
   // Validate file uploads
   const multer = require('multer');
   const upload = multer({
     limits: { fileSize: 10 * 1024 * 1024 }, // 10MB max
     fileFilter: (req, file, cb) => {
       const allowedTypes = ['image/jpeg', 'image/png'];
       if (allowedTypes.includes(file.mimetype)) {
         cb(null, true);
       } else {
         cb(new Error('Invalid file type'));
       }
     },
     storage: multer.diskStorage({
       destination: '/uploads', // Outside web root
       filename: (req, file, cb) => {
         // Generate unique filename
         cb(null, `${Date.now()}-${Math.random().toString(36)}.${file.originalname.split('.').pop()}`);
       }
     })
   });
   ```

10. **Prevent Mass Assignment**
    ```javascript
    // Use allowlists for mutation inputs
    const allowedFields = ['name', 'email', 'bio'];
    const input = {};
    for (const field of allowedFields) {
      if (args.input[field] !== undefined) {
        input[field] = args.input[field];
      }
    }
    // Only allowed fields are copied, sensitive fields ignored
    ```

11. **Implement Brute-Force Protection**
    ```javascript
    // Rate limit login mutations
    const loginLimiter = rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 5, // 5 attempts per 15 minutes
      message: 'Too many login attempts, please try again later'
    });
    
    // Account lockout after multiple failures
    let failedAttempts = {};
    if (failedAttempts[email] >= 5) {
      throw new Error('Account temporarily locked');
    }
    ```

12. **Enforce Token Expiration**
    ```javascript
    // Validate JWT expiration
    const jwt = require('jsonwebtoken');
    const decoded = jwt.verify(token, secret);
    const now = Math.floor(Date.now() / 1000);
    if (decoded.exp < now) {
      throw new Error('Token expired');
    }
    ```

## Advanced Scanners

*The new kids on the block*

### Rate Limiting Scanner

Tests your API's ability to handle request flooding:
- Sends 100+ concurrent requests
- Detects 429 (Too Many Requests) responses
- Measures response time degradation
- Tests mutation-specific rate limits

**Usage**: Automatically enabled in standard/deep profiles. Disabled in safe mode.

### CSRF Scanner

Tests mutations for Cross-Site Request Forgery vulnerabilities:
- Detects cookie-based authentication
- Tests with missing Origin header
- Tests with mismatched Origin header
- Validates CSRF token presence

**Usage**: Automatically enabled. Only tests when cookies are present.

### File Upload Scanner

Detects and tests file upload mutations:
- Identifies Upload scalar type in schema
- Flags them for manual review when full multipart exploitation cannot be exercised automatically
- Recommends testing for path traversal
- Recommends testing for oversized files
- Recommends testing for malicious extensions

**Usage**: Automatically enabled. Findings are typically emitted as `manual_review` unless real multipart exploit evidence is captured.

### Enhanced Mutation Testing

The mutation fuzzer now includes:
- **Mass Assignment Review**: Flags suspicious input objects for manual validation
- **Enhanced IDOR Review**: Highlights object-ID mutation surfaces that warrant authorization testing
- **Privilege Escalation Review**: Suggests role/admin field injection checks where applicable

### Enhanced Authentication Testing

The auth scanner now includes:
- **Brute-Force Testing**: Tests login mutations for rate limiting and account lockout
- **Token Expiration Testing**: Verifies JWT tokens properly expire (JWT scanner)

### Enhanced Injection/XSS Testing

Both scanners now test mutations (not just queries):
- **Injection Scanner**: Uses schema-valid operations and reports backend-specific error signatures as potential findings
- **XSS Scanner**: Treats reflected payloads as review candidates unless browser-executable sink evidence is available

## Testing Guidelines

*The fine print*

### Before Testing Your Own APIs

GraphQL Hunter is designed for **authorized security testing only**. Before testing:

1. ✅ Obtain written permission (seriously, get it in writing)
2. ✅ Test in non-production first (prod is sacred)
3. ✅ Use `--safe-mode` initially (baby steps)
4. ✅ Start with quick profile (ease into it)
5. ✅ Review findings carefully (false positives happen)

**[!] WARNING**: Unauthorized testing may be illegal. Don't be that person. Always get permission first. We're not posting your bail.

### False Positives

*Sometimes the tool is wrong (gasp!)*

Some findings may be false positives or acceptable:

- **Introspection Enabled** - Might be fine in dev (emphasis on "in dev")
- **Verbose Errors** - Could be intentional for debugging (but probably shouldn't be)
- **Circular References** - Common pattern if depth limits are enforced

Always verify findings manually before freaking out.

## Example Output

*What success looks like (or doesn't)*

Check out the **real vulnerability scan** in the `examples/` directory:
- **[dvga-scan.json](examples/dvga-scan.json)** - Machine-readable JSON report (16.5 KB)
- **[dvga-report.html](examples/dvga-report.html)** - Beautiful HTML report (37.5 KB) - open in browser

These were generated from a **deep scan of DVGA** (Damn Vulnerable GraphQL Application) showing **15 real findings**:
- **confirmed** findings where runtime evidence was strong
- **potential** findings where behavior was suspicious but not fully proven
- **manual_review** findings highlighting attack surface worth validating by hand

### Terminal Output

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
  Metadata: scanner=introspection, status=confirmed, confidence=confirmed
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
  Confirmed: 2
  Potential: 1
  Manual review: 2

Overall Risk: CRITICAL - Immediate action required! (Translation: panic responsibly)
```

## Troubleshooting

*When things go sideways*

### Connection Errors

```
[X] Failed to initialize client: Connection failed
```
**Solution**: Check URL, network, SSL certs. The usual suspects.

### Timeout Errors

```
[!] Request timeout
```
**Solution**: Server is slow or dead. Increase timeout or `--delay`.

### No Schema Available

```
[i] Schema not available, skipping...
```
**Solution**: Introspection is disabled (good!) but some tests will be limited.

## Unit Tests

Run the offline unit test suite:

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

## Project Structure

*For the curious and the contributors*

```
graphql-hunter/
├── graphql-hunter.py           # The main show
├── burp-extension/             # Native Burp Suite Professional addon (.jar)
├── requirements.txt            # Dependencies (not many!)
├── README.md                   # You are here
├── quickstart.bat              # For Windows folks
├── test_tool.py                # Self-test script
├── config/
│   ├── payloads.yaml          # Attack payloads (the spicy stuff)
│   └── auth.yaml              # Auth workflow profiles (safe template)
├── lib/
│   ├── graphql_client.py      # Talks to GraphQL
│   ├── auth/                  # Auth workflow engine (OAuth, cookies, CSRF, wizard)
│   ├── reporter.py            # Makes things pretty
│   ├── utils.py               # Random useful stuff
│   └── introspection.py       # Schema parser
└── scanners/
    ├── introspection_scanner.py       # Finds exposed schemas
    ├── info_disclosure_scanner.py     # Finds leaky errors
    ├── auth_bypass_scanner.py         # Tests auth (or lack thereof)
    ├── injection_scanner.py           # Injection detection
    ├── dos_scanner.py                 # DoS tests (carefully!)
    ├── batching_scanner.py            # Batch attack tests
    ├── aliasing_scanner.py            # Aliasing abuse detection
    ├── circular_query_scanner.py      # Finds loops
    ├── mutation_fuzzer.py             # Mutation security
    ├── xss_scanner.py                 # XSS detection
    └── jwt_scanner.py                 # JWT security tests
```

## Contributing

*Want to make it better? Sweet!*

Contributions are welcome! Focus on:

- Adding new vulnerability checks (more is more!)
- Improving detection accuracy (fewer false positives please)
- Better reporting formats (make it pretty)
- Documentation improvements (help future humans)

Please maintain the tool's ethical use focus. We're the good guys here.

## Contact

*For questions, high-fives, or security collaborations*

**Brad Crawford**  
Email: brad@securit360.com  
GitHub: [@kamakauzy](https://github.com/kamakauzy)

## License

This tool is provided for educational and authorized testing purposes only. Don't use it for evil. We mean it.

## Disclaimer

**GraphQL Hunter is a security testing tool. Use responsibly and legally.**

- Only test systems you have permission to test (get it in writing!)
- Some tests may impact system performance (hence `--safe-mode`)
- The authors are not responsible for misuse (don't make us regret this)
- Always follow responsible disclosure practices (be a good human)

## Version

GraphQL Hunter v1.0 - November 2025

*Built with coffee ☕, sarcasm, and a genuine desire to make GraphQL APIs more secure*

---

**[+] Happy (Ethical) Hunting!** 

*Remember: With great power comes great responsibility. And great findings come with great remediation work. Good luck! 🎯*
