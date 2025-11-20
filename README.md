# GraphQL Hunter

```
   ____                 _      ___  _       _   _             _            
  / ___|_ __ __ _ _ __ | |__  / _ \| |     | | | |_   _ _ __ | |_ ___ _ __ 
 | |  _| '__/ _` | '_ \| '_ \| | | | |     | |_| | | | | '_ \| __/ _ \ '__|
 | |_| | | | (_| | |_) | | | | |_| | |___  |  _  | |_| | | | | ||  __/ |   
  \____|_|  \__,_| .__/|_| |_|\__\_\_____| |_| |_|\__,_|_| |_|\__\___|_|   
                 |_|                                                        
```

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

### [+] User-Friendly Interface

*"Friendly" being relative when it's roasting your security posture*

- Colored terminal output (red means panic, green means celebrate)
- Real-time progress reporting (watch the findings roll in!)
- Detailed descriptions with CWE references (so you can sound smart in meetings)
- Severity-based classification (CRITICAL = update your resume)
- JSON export (for when you need to prove this to management)

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

# Run a test scan (prepare for bad news)
python graphql-hunter.py -u https://countries.trevorblades.com/graphql
```

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

### Output Options

```bash
# Save results to JSON (for posterity and blame assignment)
python graphql-hunter.py -u https://api.example.com/graphql -o results.json

# Verbose mode (ALL the details, prepare for information overload)
python graphql-hunter.py -u https://api.example.com/graphql -v

# Disable colors (for logs that'll outlive us all)
python graphql-hunter.py -u https://api.example.com/graphql --no-color > scan.txt
```

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
  --skip-xss                    Skip XSS tests
  --skip-jwt                    Skip JWT security tests

Output Options:
  -o, --output FILE             Output JSON file path
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

- `0` - No critical or high severity findings (you can sleep tonight!)
- `1` - High severity findings detected (coffee time)
- `2` - Critical severity findings detected (update your LinkedIn profile)
- `130` - Scan interrupted by user (Ctrl+C is your friend)

### Interpreting Findings

*How to read the tea leaves*

Example critical finding:
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
   // Using graphql-rate-limit
   import { createRateLimitDirective } from 'graphql-rate-limit';
   
   const rateLimitDirective = createRateLimitDirective({
     identifyContext: (ctx) => ctx.user.id  // Per-user limits
   });
   ```

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
  Critical: 1  😱
  High: 2      😬
  Medium: 1    😐
  Low: 1       🤷

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

## Project Structure

*For the curious and the contributors*

```
graphql-hunter/
├── graphql-hunter.py           # The main show
├── requirements.txt            # Dependencies (not many!)
├── README.md                   # You are here
├── quickstart.bat              # For Windows folks
├── test_tool.py                # Self-test script
├── config/
│   └── payloads.yaml          # Attack payloads (the spicy stuff)
├── lib/
│   ├── graphql_client.py      # Talks to GraphQL
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
