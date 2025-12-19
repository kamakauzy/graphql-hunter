#!/usr/bin/env python3
"""
Test script to validate if Postman-Token header is required
"""

import sys
import json
from pathlib import Path

# Add lib directory to path
sys.path.insert(0, str(Path(__file__).parent / "lib"))

from graphql_client import GraphQLClient

# Mutation from the request
MUTATION_QUERY = """mutation ReportTaskStart(
  $pdtUid: String!
  $startTime: DateTime!
  $moduleNumber: Int!
  $taskNumber: Int!
) {
  reportTaskStart(
    pdtUid: $pdtUid
    startTime: $startTime
    moduleNumber: $moduleNumber
    taskNumber: $taskNumber
  ) {
    taskData {
      uid
      startTime
      completeTime
      moduleNumber
      taskNumber
      appData
      __typename
    }
    __typename
  }
}"""

MUTATION_VARIABLES = {
    "pdtUid": "BxgXBrgwswcX58wFNwhVfv",
    "startTime": "2025-12-15T17:32:32+00:00",
    "moduleNumber": 1,
    "taskNumber": 1
}

def test_postman_token():
    """Test if Postman-Token header is required"""
    url = "https://api.example.com/graphql/"
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImNobG9lLnNjb3R0K3NsZWVwaW93ZWxsbmVzc3Rlc3RAYmlnaGVhbHRoLmNvbSIsImV4cCI6MTc2NjA3NjE4Miwib3JpZ0lhdCI6MTc2NjA3NTg4Mn0.kgTN66JqHncXaZr_xvR1imEb-z-M__Bb5KCcmrmHIO0"
    csrf_token = "deiPMVkXB6kpOhvH1ubIhfwWFkVyTbDE"
    postman_token_1 = "52cceb0e-c3e6-4366-a200-1c2e332223e3"  # From first request
    postman_token_2 = "cc81bcae-a38d-4006-9a03-f841681e79cc"  # From second request
    
    print("=" * 70)
    print("POSTMAN-TOKEN HEADER VALIDATION TEST")
    print("=" * 70)
    print(f"Target: {url}\n")
    print("Testing if Postman-Token header is required for authentication\n")
    
    scenarios = [
        {
            "name": "Full Original Request (Token + Cookie + Postman-Token)",
            "headers": {
                "Token": token,
                "Cookie": f"csrftoken={csrf_token}",
                "Postman-Token": postman_token_2,
                "User-Agent": "PostmanRuntime/7.51.0",
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate, br"
            }
        },
        {
            "name": "Without Postman-Token (Token + Cookie only)",
            "headers": {
                "Token": token,
                "Cookie": f"csrftoken={csrf_token}",
                "User-Agent": "PostmanRuntime/7.51.0",
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate, br"
            }
        },
        {
            "name": "Postman-Token Only (no other auth)",
            "headers": {
                "Postman-Token": postman_token_2,
                "User-Agent": "PostmanRuntime/7.51.0",
                "Accept": "*/*"
            }
        },
        {
            "name": "Different Postman-Token value",
            "headers": {
                "Token": token,
                "Cookie": f"csrftoken={csrf_token}",
                "Postman-Token": postman_token_1,  # Different value
                "User-Agent": "PostmanRuntime/7.51.0",
                "Accept": "*/*"
            }
        },
        {
            "name": "Invalid Postman-Token format",
            "headers": {
                "Token": token,
                "Cookie": f"csrftoken={csrf_token}",
                "Postman-Token": "invalid-token-12345",
                "User-Agent": "PostmanRuntime/7.51.0",
                "Accept": "*/*"
            }
        }
    ]
    
    results = []
    
    for scenario in scenarios:
        print(f"\n{'='*70}")
        print(f"Testing: {scenario['name']}")
        print(f"{'='*70}")
        
        # Redact sensitive headers in output
        display_headers = dict(scenario['headers'])
        if 'Token' in display_headers:
            display_headers['Token'] = display_headers['Token'][:20] + "...[REDACTED]"
        if 'Cookie' in display_headers:
            display_headers['Cookie'] = "csr***REDACTED***"
        print(f"Headers: {json.dumps(display_headers, indent=2)}")
        
        try:
            client = GraphQLClient(
                url=url,
                headers=scenario['headers'],
                verbose=True,
                test_connection=False
            )
            
            print(f"\n[TEST] Executing mutation: ReportTaskStart")
            result = client.query(
                query=MUTATION_QUERY,
                variables=MUTATION_VARIABLES,
                operation_name="ReportTaskStart"
            )
            
            status = result.get('_status_code', 0)
            print(f"\n[RESULT] Status Code: {status}")
            
            if result.get('errors'):
                error_messages = [e.get('message', '') for e in result.get('errors', [])]
                print(f"[RESULT] Errors: {json.dumps(result['errors'], indent=2)}")
                
                # Analyze error messages
                if any('authentication' in msg.lower() or 'unauthorized' in msg.lower() 
                       for msg in error_messages):
                    auth_status = "FAILED - Auth required"
                elif any('permission' in msg.lower() for msg in error_messages):
                    auth_status = "PARTIAL - Permission error (auth may be working)"
                else:
                    auth_status = "WORKING - Error is NOT auth-related"
            elif result.get('data'):
                print(f"[RESULT] Data: {json.dumps(result['data'], indent=2)}")
                if result['data'].get('reportTaskStart'):
                    auth_status = "WORKING - Mutation succeeded"
                else:
                    auth_status = "UNKNOWN - Check data structure"
            else:
                auth_status = "UNKNOWN - No errors or data"
            
            print(f"[AUTH STATUS] {auth_status}")
            
            results.append({
                'scenario': scenario['name'],
                'status_code': status,
                'auth_status': auth_status,
                'has_errors': bool(result.get('errors')),
                'has_data': bool(result.get('data')),
                'errors': result.get('errors', []),
                'has_postman_token': 'Postman-Token' in scenario['headers']
            })
                
        except Exception as e:
            print(f"[ERROR] Exception occurred: {e}")
            import traceback
            traceback.print_exc()
            results.append({
                'scenario': scenario['name'],
                'status': 'ERROR',
                'error': str(e),
                'has_postman_token': 'Postman-Token' in scenario['headers']
            })
        
        print()
    
    # Print comparison summary
    print("\n" + "=" * 70)
    print("COMPARISON SUMMARY")
    print("=" * 70)
    print(f"{'Scenario':<50} {'Status':<8} {'Has Postman-Token':<18} {'Result':<30}")
    print("-" * 110)
    for r in results:
        status_code = r.get('status_code', 'N/A')
        auth_status = r.get('auth_status', r.get('status', 'ERROR'))
        has_pt = "Yes" if r.get('has_postman_token') else "No"
        # Truncate long status messages
        if len(auth_status) > 28:
            auth_status = auth_status[:25] + "..."
        print(f"{r['scenario']:<50} {str(status_code):<8} {has_pt:<18} {auth_status:<30}")
    
    print("\n" + "=" * 70)
    print("CONCLUSION")
    print("=" * 70)
    
    # Compare scenarios with and without Postman-Token
    full_auth = next((r for r in results if 'Full Original' in r.get('scenario', '')), None)
    without_pt = next((r for r in results if 'Without Postman-Token' in r.get('scenario', '')), None)
    pt_only = next((r for r in results if 'Postman-Token Only' in r.get('scenario', '')), None)
    
    if full_auth and without_pt:
        if full_auth.get('status_code') != without_pt.get('status_code'):
            print("[RESULT] Postman-Token header IS REQUIRED")
            print(f"  - With Postman-Token: {full_auth.get('status_code')}")
            print(f"  - Without Postman-Token: {without_pt.get('status_code')}")
        elif full_auth.get('errors') != without_pt.get('errors'):
            print("[RESULT] Postman-Token header affects response")
            print("  - Different errors returned")
        else:
            print("[RESULT] Postman-Token header is NOT REQUIRED")
            print("  - Same response with and without Postman-Token")
    
    if pt_only:
        if pt_only.get('status_code') == 200 and pt_only.get('has_data'):
            print("\n[INFO] Postman-Token alone may be sufficient for auth")
        elif pt_only.get('status_code') in [401, 403]:
            print("\n[INFO] Postman-Token alone is NOT sufficient for auth")
        else:
            print(f"\n[INFO] Postman-Token alone: {pt_only.get('auth_status')}")

if __name__ == "__main__":
    test_postman_token()
