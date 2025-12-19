# How Authentication Validation Works

## Overview

The `validate_auth()` method in `GraphQLClient` determines if authentication is working by **comparing two identical requests** - one with your auth headers and one without.

## Step-by-Step Process

### 1. **Make Request WITH Auth Headers**
```python
# Uses your configured headers (Token, Cookie, Authorization, etc.)
result_with_auth = self.query(test_query, variables=test_variables)
status_with_auth = result_with_auth.get('_status_code', 0)
```

**What it sends:**
- All your custom headers (`-H` flags)
- Token header (if provided)
- Cookie header (if provided)
- Any auth headers from `--auth-profile`
- Default `Content-Type: application/json`

### 2. **Make Request WITHOUT Auth Headers**
```python
# Creates a minimal client with ONLY Content-Type
unauth_headers = {'Content-Type': 'application/json'}
unauth_client = GraphQLClient(url=self.url, headers=unauth_headers, ...)
result_without_auth = unauth_client.query(test_query, variables=test_variables, bypass_auth=True)
status_without_auth = result_without_auth.get('_status_code', 0)
```

**What it sends:**
- Only `Content-Type: application/json`
- NO auth headers
- NO cookies
- NO tokens

### 3. **Compare the Results**

The tool analyzes the differences between the two responses:

#### **Scenario A: Auth is WORKING** ✅
```
With Auth:    HTTP 200, returns data
Without Auth: HTTP 401/403, "Unauthorized" error
```
**Conclusion:** Authentication is required and working correctly.

#### **Scenario B: Auth is WORKING (Different Data)** ✅
```
With Auth:    HTTP 200, returns user-specific data
Without Auth: HTTP 200, returns public/default data
```
**Conclusion:** Authentication is working - different data shows auth is being used.

#### **Scenario C: Auth is WORKING (Different Errors)** ✅
```
With Auth:    HTTP 200, "Permission denied" error
Without Auth: HTTP 200, "Authentication required" error
```
**Conclusion:** Authentication is working - server recognizes authenticated vs unauthenticated requests.

#### **Scenario D: Auth NOT Required** ⚠️
```
With Auth:    HTTP 200, same response
Without Auth: HTTP 200, same response
```
**Conclusion:** Authentication may not be required - identical responses suggest auth headers aren't being checked.

#### **Scenario E: Permission Errors (Ambiguous)** ⚠️
```
With Auth:    HTTP 200, "You do not have permission" error
Without Auth: HTTP 200, "You do not have permission" error
```
**Conclusion:** Authentication appears to be checked (permission errors indicate auth flow), but same error suggests:
- Token may be expired/invalid
- Token not required for this endpoint
- Permission check happens regardless of auth

## Decision Logic Flowchart

```
                    Start Validation
                           |
                           v
            ┌──────────────────────────────┐
            │  Send request WITH auth       │
            │  (all your headers)           │
            └──────────────────────────────┘
                           |
                           v
            ┌──────────────────────────────┐
            │  Send request WITHOUT auth   │
            │  (only Content-Type)         │
            └──────────────────────────────┘
                           |
                           v
            ┌──────────────────────────────┐
            │  Compare HTTP status codes   │
            └──────────────────────────────┘
                           |
        ┌──────────────────┼──────────────────┐
        |                  |                  |
        v                  v                  v
   401/403 vs 200    Same status      Different data
        |                  |                  |
        v                  v                  v
   Auth WORKING    Check error msgs   Auth WORKING
        |                  |                  |
        |                  v                  |
        |         Permission errors?          |
        |                  |                  |
        |                  v                  |
        |         Auth WORKING (ambiguous)    |
        |                                      |
        └──────────────────────────────────────┘
```

## Key Indicators

### ✅ **Auth is WORKING if:**
1. **Status codes differ:** 401/403 without auth, 200 with auth
2. **Error messages differ:** "Unauthorized" without auth, success/data with auth
3. **Data differs:** Different responses show auth is being used
4. **Permission errors:** Even if same, permission errors indicate auth flow is active

### ⚠️ **Auth may NOT be required if:**
1. **Identical responses:** Same status code, same errors, same data
2. **Both succeed:** Both return 200 with identical data
3. **Same validation errors:** Both fail with same validation/business logic errors

### ❓ **Ambiguous cases:**
1. **Same permission errors:** Could mean:
   - Token is expired/invalid (auth checked but token bad)
   - Token not required (auth not checked)
   - Permission check happens regardless of auth

## Example Analysis

### Example 1: Working Auth
```json
With Auth:    {"status": 200, "data": {"user": {"id": 123}}}
Without Auth: {"status": 401, "errors": [{"message": "Unauthorized"}]}
```
**Result:** ✅ Auth is WORKING - clear difference shows auth is required and working.

### Example 2: Not Required
```json
With Auth:    {"status": 200, "data": {"__typename": "Query"}}
Without Auth: {"status": 200, "data": {"__typename": "Query"}}
```
**Result:** ⚠️ Auth may NOT be required - identical responses.

### Example 3: Permission Error (Your Case)
```json
With Auth:    {"status": 200, "errors": [{"message": "You do not have permission"}]}
Without Auth: {"status": 200, "errors": [{"message": "You do not have permission"}]}
```
**Result:** ⚠️ Auth appears to be checked (permission errors), but same error suggests:
- Token may be expired/invalid
- Token not being validated
- Permission check happens regardless

## Usage

```bash
# Basic validation (uses simple __typename query)
python graphql-hunter.py -u <URL> -H "Token: ..." --validate-auth

# With custom mutation/query
python graphql-hunter.py -u <URL> -H "Token: ..." --validate-auth \
  --auth-test-query "mutation { ... }" \
  --auth-test-variables '{"key": "value"}'
```

## What Gets Tested

The validation compares:
- ✅ HTTP status codes
- ✅ Error messages (looking for auth-related keywords)
- ✅ Response data (checking if different)
- ✅ Permission errors (indicating auth flow)

## Limitations

1. **False positives:** Some endpoints may return same errors for different reasons
2. **Permission vs Auth:** Permission errors don't always mean auth is working
3. **Token expiration:** Expired tokens may still pass validation if server doesn't check
4. **Endpoint-specific:** Different mutations may have different auth requirements
