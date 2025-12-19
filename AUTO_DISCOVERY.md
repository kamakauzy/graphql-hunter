# Auto-Discovery Feature

## Overview

The auto-discovery feature automatically figures out authentication, configuration, and setup from notes, JSON files, YAML files, or any text input. Just provide your notes/files and the tool will:

- ✅ Extract URLs and endpoints
- ✅ Detect authentication methods
- ✅ Find credentials (email, password, tokens)
- ✅ Discover headers and tokens
- ✅ Generate ready-to-run commands
- ✅ Auto-configure auth profiles

## Usage

### Basic Usage

```bash
# Auto-discover from notes file
python graphql-hunter.py --auto-discover notes.txt

# Auto-discover from multiple sources
python graphql-hunter.py --auto-discover notes.txt config.json request.yaml

# Just show what was discovered (don't run scan)
python graphql-hunter.py --auto-discover notes.txt --show-discovery

# Auto-discover and run scan
python graphql-hunter.py --auto-discover notes.txt -p deep -o results.json
```

### From Text Notes

```bash
# Provide notes directly
python graphql-hunter.py --discover-notes "email: user@example.com
password: secret123
url: https://api.example.com/graphql"
```

## What It Discovers

### 1. URLs and Endpoints
- Extracts GraphQL endpoint URLs
- Recognizes patterns like `url:`, `endpoint:`, `graphql_url:`
- Handles both full URLs and relative paths

### 2. Authentication Methods
- **tokenAuth** - Detects GraphQL tokenAuth mutations
- **token_header** - Detects JWT tokens in headers
- **OAuth** - Detects OAuth patterns
- **API Key** - Detects API key patterns

### 3. Credentials
- Email addresses
- Passwords
- Access codes
- UIDs (PDT, patient, careteams, etc.)

### 4. Tokens
- JWT tokens (detects `eyJ...` format)
- Refresh tokens (hex format)
- API keys

### 5. Headers
- Token headers
- Authorization headers
- Custom headers

### 6. Queries and Mutations
- Extracts from JSON/YAML files
- Extracts from Postman collections
- Parses GraphQL queries/mutations

## Example: Notes File

Given a notes file like:

```
email: user@example.com
password: secret123
url: https://api.example.com/graphql/
apikey: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
refreshToken: abc123def456...
```

The tool will:
1. ✅ Discover the URL
2. ✅ Detect email/password → suggests `tokenAuth` method
3. ✅ Find the JWT token
4. ✅ Generate command with appropriate `--auth-profile`
5. ✅ Auto-configure and run the scan

## Supported File Formats

### Text Files (.txt, .md, .notes)
- Plain text notes
- Key-value pairs
- Free-form text

### JSON Files (.json)
- Postman collections
- Request files
- Configuration files
- Generic JSON (searches recursively)

### YAML Files (.yaml, .yml)
- Request files
- Configuration files
- Generic YAML

## Pattern Recognition

The tool recognizes common patterns:

### URLs
- `url:`, `endpoint:`, `graphql_url:`, `api_url:`
- Full URLs starting with `http://` or `https://`

### Credentials
- `email:`, `username:`, `user:`
- `password:`, `pwd:`, `pass:`
- `access_code:`, `accessCode:`

### Tokens
- JWT format: `eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+`
- Refresh tokens: Hex strings (32+ characters)
- `token:`, `apikey:`, `api_key:`, `jwt:`

### Headers
- `Token:`, `Authorization:`, `X-API-Key:`
- Custom header patterns

## Auto-Configuration

When discoveries are made, the tool automatically:

1. **Sets URL** - If `-u` not provided, uses discovered URL
2. **Configures Auth** - If credentials found, sets `--auth-profile`
3. **Sets Auth Vars** - Automatically sets `--auth-var email=...` etc.
4. **Adds Headers** - If tokens found, adds `-H "Token: ..."`

## Generated Commands

The tool generates ready-to-run commands:

```bash
# Example output
python graphql-hunter.py \
  -u https://api.example.com/graphql/ \
  --auth-profile token_auth \
  --auth-var email=user@example.com \
  --auth-var password=secret123 \
  --validate-auth
```

## Integration with Other Features

Auto-discovery works seamlessly with:

- **Request Import** - Can discover from imported files
- **Auth Profiles** - Auto-generates profiles when needed
- **Auth Validation** - Automatically validates discovered auth
- **Scanning** - Runs scans with discovered configuration

## Examples

### Example 1: Notes File
```bash
# Create notes.txt with credentials
echo "email: user@example.com
password: secret123
url: https://api.example.com/graphql" > notes.txt

# Auto-discover and scan
python graphql-hunter.py --auto-discover notes.txt
```

### Example 2: JSON Configuration
```bash
# Auto-discover from JSON config
python graphql-hunter.py --auto-discover config.json --show-discovery
```

### Example 3: Multiple Sources
```bash
# Combine notes, JSON, and YAML
python graphql-hunter.py \
  --auto-discover notes.txt config.json requests.yaml \
  -p deep -o results.json
```

## Limitations

- Pattern matching may have false positives
- Complex nested structures may not be fully parsed
- Some custom formats may not be recognized
- Always verify discovered credentials before use

## Best Practices

1. **Review Discoveries** - Use `--show-discovery` first to verify
2. **Secure Storage** - Don't commit notes files with secrets to git
3. **Verify Auth** - Use `--validate-auth` to confirm authentication works
4. **Test First** - Start with `-p quick` before deep scans

## Future Enhancements

Potential improvements:
- Machine learning for better pattern recognition
- Support for more file formats (Insomnia, HTTPie, etc.)
- Automatic schema discovery from SDL files
- Smart query generation from discovered mutations
- Batch discovery from multiple sources
