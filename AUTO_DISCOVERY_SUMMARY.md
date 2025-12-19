# Auto-Discovery Feature - Summary

## What It Does

The auto-discovery feature automatically figures out how to authenticate and configure GraphQL Hunter from:
- 📝 Text notes files
- 📄 JSON files (Postman collections, configs, requests)
- 📋 YAML files (configs, requests)
- 🔤 Plain text strings

**Just provide your notes/files and the tool figures out the rest!**

## Quick Start

```bash
# Provide your notes file
python graphql-hunter.py --auto-discover notes.txt

# See what was discovered (without running scan)
python graphql-hunter.py --auto-discover notes.txt --show-discovery

# Discover from multiple sources
python graphql-hunter.py --auto-discover notes.txt config.json request.yaml
```

## Real Example: Notes File

You provide notes like:
```
email: user@example.com
password: secret123
url: https://api.example.com/graphql/
apikey: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**The tool automatically:**
1. ✅ Found the URL
2. ✅ Detected email/password → identified `tokenAuth` method
3. ✅ Found JWT token
4. ✅ Generated command with appropriate `--auth-profile`
5. ✅ Auto-configured and ran the scan

**No manual configuration needed!**

## What Gets Discovered

### URLs
- GraphQL endpoints
- API URLs
- Recognizes: `url:`, `endpoint:`, `graphql_url:`, etc.

### Authentication
- **tokenAuth** mutations (email/password)
- JWT tokens in headers
- OAuth patterns
- API keys

### Credentials
- Email addresses
- Passwords
- Access codes
- UIDs (PDT, patient, etc.)

### Tokens
- JWT tokens (`eyJ...` format)
- Refresh tokens (hex format)
- API keys

### Headers
- Token headers
- Authorization headers
- Custom headers

## Auto-Configuration

When discoveries are made, the tool automatically:

1. **Sets URL** - Uses discovered URL if `-u` not provided
2. **Configures Auth** - Sets `--auth-profile` if credentials found
3. **Sets Auth Vars** - Automatically sets `--auth-var email=...` etc.
4. **Adds Headers** - Adds `-H "Token: ..."` if tokens found
5. **Runs Scan** - Executes scan with discovered configuration

## Pattern Recognition

The tool recognizes patterns like:

```
email: user@example.com          → Discovers email
password: secret123               → Discovers password
url: https://api.example.com/... → Discovers URL
Token: eyJ...                     → Discovers JWT token
apikey: eyJ...                    → Discovers API key
refreshToken: abc123...           → Discovers refresh token
```

## Integration

Works seamlessly with:
- ✅ Request import (`--import`)
- ✅ Auth profiles (`--auth-profile`)
- ✅ Auth validation (`--validate-auth`)
- ✅ All scan profiles (`-p quick/standard/deep/stealth`)

## Use Cases

### 1. Client Provides Notes
```bash
# Client sends you a notes file
python graphql-hunter.py --auto-discover client_notes.txt
```

### 2. Postman Collection
```bash
# Import and auto-discover from Postman
python graphql-hunter.py --auto-discover collection.json
```

### 3. Multiple Sources
```bash
# Combine notes, config, and requests
python graphql-hunter.py \
  --auto-discover notes.txt config.json requests.yaml \
  -p deep -o results.json
```

### 4. Quick Discovery
```bash
# Just see what would be discovered
python graphql-hunter.py --auto-discover notes.txt --show-discovery
```

## Benefits

1. **Zero Configuration** - Just provide notes/files
2. **Saves Time** - No manual typing of credentials
3. **Reduces Errors** - Automatic extraction prevents typos
4. **Smart Detection** - Recognizes common patterns
5. **Ready-to-Run** - Generates commands you can copy/paste

## Example Output

```
[*] Auto-Discovery
----------------------------------------------------------------------
[+] Discovered URL: https://api.example.com/graphql/
[+] Detected Auth Method: tokenAuth
[i] Discovered Credentials:
[i]   email: user@example.com
[i]   password: ****************
[i] Discovered Tokens:
[i]   access_token: eyJhbGciOiJIUzI1NiIsInR5cCI6Ik...
[i]   refresh_token: abc123def456...

[*] Recommendations
----------------------------------------------------------------------
[i] Ready-to-run command:
python graphql-hunter.py \
  -u https://api.example.com/graphql/ \
  --auth-profile token_auth \
  --auth-var email=user@example.com \
  --auth-var password=secret123 \
  --validate-auth
```

## Files Created

- ✅ `lib/auto_discover.py` - Auto-discovery engine
- ✅ `AUTO_DISCOVERY.md` - Detailed documentation
- ✅ `AUTO_DISCOVERY_SUMMARY.md` - This summary

## Next Steps

1. Try it with your notes: `python graphql-hunter.py --auto-discover notes.txt`
2. Review discoveries: Add `--show-discovery` to see what was found
3. Run scans: The tool automatically configures and runs

**The tool now "figures it out" from your notes!** 🎯
