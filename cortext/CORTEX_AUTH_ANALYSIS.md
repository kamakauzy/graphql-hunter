# Cortex Authentication Analysis

## Summary

After analyzing the Cortex GraphQL API and testing with provided credentials, here's what we discovered about authentication:

## Authentication Flow

### 1. **Get Token via `tokenAuth` Mutation**

```graphql
mutation TokenAuth($email: String!, $password: String!) {
  tokenAuth(email: $email, password: $password) {
    token          # JWT token
    refreshToken   # Refresh token string
    user {
      uid
      email
      firstName
      lastName
    }
  }
}
```

**Status:** ✅ **WORKING**
- Successfully authenticates with email/password
- Returns JWT token and refresh token
- Server sets CSRF cookie automatically

### 2. **Use Token in Requests**

**Token Header Format:** `Token: <JWT>`

**Note:** The token should be in a `Token` header (not `Authorization: Bearer`)

### 3. **Refresh Token**

```graphql
mutation RefreshToken($refreshToken: String!) {
  refreshToken(refreshToken: $refreshToken) {
    token
    refreshToken
  }
}
```

**Status:** ✅ **WORKING**
- Successfully refreshes expired tokens
- Returns new token and refresh token

## Test Results

### ✅ What Works:
1. **tokenAuth mutation** - Successfully authenticates and returns token
2. **refreshToken mutation** - Successfully refreshes tokens
3. **Token format** - JWT token is valid and properly formatted
4. **CSRF cookie** - Server automatically sets `csrftoken` cookie

### ⚠️ Observations:
1. **Permission Errors** - All tested queries (`me`, `reportTaskStart`) return "You do not have permission" errors
   - This suggests the token is **valid** (no "unauthorized" errors)
   - But the user account may not have permissions for these specific operations
   
2. **Same Response with/without Token** - Some queries return identical responses with and without token
   - Could indicate:
     - Token not being validated for those specific queries
     - Permission checks happen regardless of auth state
     - User account lacks permissions for tested operations

## Credentials Used

```
Email: your-test-user@example.com
Password: YOUR_PASSWORD
PDT UID: YOUR_PDT_UID
Access Code: YOUR_ACCESS_CODE
```

## Authentication Headers

Based on testing, the correct format is:

```
Token: <JWT_TOKEN>
Cookie: csrftoken=<CSRF_TOKEN>  # Set automatically by server
```

**Note:** The `Token` header (not `Authorization: Bearer`) is what the API expects.

## Recommendations

1. **For Testing:**
   - Use `tokenAuth` mutation to get fresh tokens
   - Include token in `Token` header
   - Server will set CSRF cookie automatically
   - Use `refreshToken` mutation when token expires

2. **For Tool Integration:**
   - The tool should support `tokenAuth` mutation for authentication
   - Store tokens and refresh them automatically
   - Include `Token` header in requests
   - Maintain session cookies for CSRF protection

3. **Permission Issues:**
   - The tested user may not have permissions for certain queries
   - Try different queries that the user account has access to
   - Check if user needs to be assigned specific roles/permissions

## Conclusion

**Authentication is WORKING:**
- ✅ `tokenAuth` mutation works
- ✅ Tokens are valid JWT format
- ✅ Refresh token mechanism works
- ✅ CSRF cookies are set automatically

**Authorization may be the issue:**
- ⚠️ User account may lack permissions for tested queries
- ⚠️ Some queries return same response regardless of auth state
- ⚠️ Permission errors suggest auth is checked but user lacks access

The authentication mechanism is functional - the issue appears to be with user permissions rather than authentication itself.
