#!/usr/bin/env python3
"""
Test different token header formats to find the correct one
"""

import sys
import json
from pathlib import Path

# Add lib directory to path
sys.path.insert(0, str(Path(__file__).parent / "lib"))

from graphql_client import GraphQLClient

CREDENTIALS = {
    "email": "YOUR_EMAIL@example.com",
    "password": "YOUR_PASSWORD"
}

URL = "https://api.example.com/graphql/"

# Query that should require auth
TEST_QUERY = """query {
  me {
    uid
    email
    firstName
    lastName
  }
}"""

def test_token_formats():
    """Test different token header formats"""
    print("=" * 70)
    print("TOKEN HEADER FORMAT TEST")
    print("=" * 70)
    
    # Get token
    token_auth_query = """mutation TokenAuth($email: String!, $password: String!) {
      tokenAuth(email: $email, password: $password) {
        token
        refreshToken
      }
    }"""
    
    client = GraphQLClient(
        url=URL,
        headers={"Content-Type": "application/json"},
        verbose=False,
        test_connection=False
    )
    
    auth_result = client.query(
        query=token_auth_query,
        variables={"email": CREDENTIALS["email"], "password": CREDENTIALS["password"]},
        operation_name="TokenAuth"
    )
    
    if not auth_result.get('data') or not auth_result['data'].get('tokenAuth'):
        print("[FAIL] Authentication failed")
        return
    
    token = auth_result['data']['tokenAuth']['token']
    print(f"[SUCCESS] Got token: {token[:50]}...\n")
    
    # Test different header formats
    header_formats = [
        {"Token": token},
        {"Authorization": f"Bearer {token}"},
        {"Authorization": token},
        {"X-Auth-Token": token},
        {"X-Token": token},
        {"authToken": token},
        {"token": token},
    ]
    
    print("=" * 70)
    print("Testing different token header formats")
    print("=" * 70)
    
    results = []
    
    for headers in header_formats:
        header_name = list(headers.keys())[0]
        print(f"\n{'='*70}")
        print(f"Testing: {header_name}: <token>")
        print(f"{'='*70}")
        
        test_client = GraphQLClient(
            url=URL,
            headers={**headers, "Content-Type": "application/json"},
            verbose=True,
            test_connection=False
        )
        
        result = test_client.query(query=TEST_QUERY)
        
        status = result.get('_status_code', 0)
        errors = result.get('errors', [])
        data = result.get('data')
        
        print(f"Status: {status}")
        if errors:
            error_msgs = [e.get('message', '') for e in errors]
            print(f"Errors: {error_msgs}")
        if data and data.get('me'):
            print(f"[SUCCESS] Got user data: {json.dumps(data['me'], indent=2)}")
            results.append({
                'header': header_name,
                'status': 'SUCCESS',
                'data': data['me']
            })
        elif data and data.get('me') is None:
            print(f"[INFO] Query executed but me is null")
            results.append({
                'header': header_name,
                'status': 'NULL_RESPONSE',
                'errors': errors
            })
        else:
            print(f"[RESULT] {json.dumps(result, indent=2)[:300]}")
            results.append({
                'header': header_name,
                'status': 'ERROR',
                'errors': errors
            })
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    success = [r for r in results if r['status'] == 'SUCCESS']
    if success:
        print(f"[SUCCESS] Working header format(s):")
        for r in success:
            print(f"  - {r['header']}: {r['header']} header works!")
    else:
        print("[INFO] No header format returned user data")
        print("This could mean:")
        print("  1. The 'me' query requires different permissions")
        print("  2. Token needs to be in a different format")
        print("  3. Additional headers/cookies are required")
    
    # Check if any format produced different results
    all_same = len(set(str(r.get('errors', [])) for r in results)) == 1
    if all_same:
        print("\n[WARN] All header formats produced same response")
        print("  - Token may not be validated via headers")
        print("  - May require session/cookie-based auth")
        print("  - May require different authentication method")

if __name__ == "__main__":
    test_token_formats()
