#!/usr/bin/env python3
"""
Test script to validate the NEW token from tokenAuth mutation response
"""

import sys
import json
from pathlib import Path

# Add lib directory to path
sys.path.insert(0, str(Path(__file__).parent / "lib"))

from graphql_client import GraphQLClient

# New token from the tokenAuth response
NEW_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImNobG9lLnNjb3R0K3NsZWVwaW93ZWxsbmVzc3Rlc3RAYmlnaGVhbHRoLmNvbSIsImV4cCI6MTc2NjEwODIwMSwib3JpZ0lhdCI6MTc2NjEwNzkwMX0.Tb_kVCY0BkAoZY2zinyMjatDEG7WFpd0gBkwrDqT3-g"
REFRESH_TOKEN = "1fb805c17a0145889c2335c96cacb0866d2dff77"
CSRF_TOKEN = "deiPMVkXB6kpOhvH1ubIhfwWFkVyTbDE"  # From Set-Cookie header

# Mutation to test
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

def test_new_token():
    """Test the new token from tokenAuth response"""
    url = "https://api.example.com/graphql/"
    
    print("=" * 70)
    print("NEW TOKEN VALIDATION TEST")
    print("=" * 70)
    print(f"Target: {url}\n")
    print("Testing token from tokenAuth mutation response\n")
    
    scenarios = [
        {
            "name": "NEW Token + Cookie (Full Auth)",
            "headers": {
                "Token": NEW_TOKEN,
                "Cookie": f"csrftoken={CSRF_TOKEN}",
                "User-Agent": "PostmanRuntime/7.51.0",
                "Accept": "*/*"
            }
        },
        {
            "name": "NEW Token Only (No Cookie)",
            "headers": {
                "Token": NEW_TOKEN,
                "User-Agent": "PostmanRuntime/7.51.0",
                "Accept": "*/*"
            }
        },
        {
            "name": "OLD Token + Cookie (for comparison)",
            "headers": {
                "Token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImNobG9lLnNjb3R0K3NsZWVwaW93ZWxsbmVzc3Rlc3RAYmlnaGVhbHRoLmNvbSIsImV4cCI6MTc2NjA3NjE4Miwib3JpZ0lhdCI6MTc2NjA3NTg4Mn0.kgTN66JqHncXaZr_xvR1imEb-z-M__Bb5KCcmrmHIO0",
                "Cookie": f"csrftoken={CSRF_TOKEN}",
                "User-Agent": "PostmanRuntime/7.51.0",
                "Accept": "*/*"
            }
        },
        {
            "name": "No Auth Headers (baseline)",
            "headers": {
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
        
        # Redact token in output
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
                    auth_status = "SUCCESS - Mutation executed successfully!"
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
                'data': result.get('data')
            })
                
        except Exception as e:
            print(f"[ERROR] Exception occurred: {e}")
            import traceback
            traceback.print_exc()
            results.append({
                'scenario': scenario['name'],
                'status': 'ERROR',
                'error': str(e)
            })
        
        print()
    
    # Print comparison summary
    print("\n" + "=" * 70)
    print("COMPARISON SUMMARY")
    print("=" * 70)
    print(f"{'Scenario':<45} {'Status':<8} {'Result':<50}")
    print("-" * 105)
    for r in results:
        status_code = r.get('status_code', 'N/A')
        auth_status = r.get('auth_status', r.get('status', 'ERROR'))
        # Truncate long status messages
        if len(auth_status) > 48:
            auth_status = auth_status[:45] + "..."
        print(f"{r['scenario']:<45} {str(status_code):<8} {auth_status:<50}")
    
    print("\n" + "=" * 70)
    print("CONCLUSION")
    print("=" * 70)
    
    # Compare new vs old token
    new_token_full = next((r for r in results if 'NEW Token + Cookie' in r.get('scenario', '')), None)
    old_token_full = next((r for r in results if 'OLD Token' in r.get('scenario', '')), None)
    no_auth = next((r for r in results if 'No Auth' in r.get('scenario', '')), None)
    
    if new_token_full and old_token_full:
        if new_token_full.get('has_data') and not old_token_full.get('has_data'):
            print("[SUCCESS] NEW token is WORKING - mutation succeeded!")
            print("  - OLD token returned permission error")
            print("  - NEW token from tokenAuth mutation is valid and working")
        elif new_token_full.get('errors') != old_token_full.get('errors'):
            print("[INFO] NEW token produces different response than OLD token")
            print(f"  - NEW token: {new_token_full.get('auth_status')}")
            print(f"  - OLD token: {old_token_full.get('auth_status')}")
        else:
            print("[WARN] NEW token produces same response as OLD token")
            print("  - Both tokens may be expired/invalid or not required")
    
    if new_token_full and no_auth:
        if new_token_full.get('has_data') and not no_auth.get('has_data'):
            print("\n[SUCCESS] NEW token authentication is WORKING!")
            print("  - Request with NEW token succeeds")
            print("  - Request without token fails")
        elif new_token_full.get('status_code') != no_auth.get('status_code'):
            print(f"\n[INFO] NEW token affects response (status: {new_token_full.get('status_code')} vs {no_auth.get('status_code')})")
        else:
            print("\n[WARN] NEW token may not be required - same response with/without token")

if __name__ == "__main__":
    test_new_token()
