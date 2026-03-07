#!/usr/bin/env python3
"""
Test script to validate Token header authentication
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

def test_token_auth():
    """Test Token header authentication"""
    url = "https://api.example.com/graphql/"
    token = "YOUR_ACCESS_TOKEN"
    csrf_token = "YOUR_CSRF_TOKEN"
    
    print("=" * 70)
    print("TOKEN HEADER AUTHENTICATION VALIDATION TEST")
    print("=" * 70)
    print(f"Target: {url}\n")
    
    scenarios = [
        {
            "name": "Token + Cookie (Full Auth)",
            "headers": {
                "Token": token,
                "Cookie": f"csrftoken={csrf_token}",
                "User-Agent": "PostmanRuntime/7.51.0",
                "Accept": "*/*"
            }
        },
        {
            "name": "Token Only (No Cookie)",
            "headers": {
                "Token": token,
                "User-Agent": "PostmanRuntime/7.51.0",
                "Accept": "*/*"
            }
        },
        {
            "name": "Cookie Only (No Token)",
            "headers": {
                "Cookie": f"csrftoken={csrf_token}",
                "User-Agent": "PostmanRuntime/7.51.0",
                "Accept": "*/*"
            }
        },
        {
            "name": "No Auth Headers",
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
                print(f"[RESULT] Errors: {json.dumps(result['errors'], indent=2)}")
                error_messages = [e.get('message', '') for e in result.get('errors', [])]
                
                # Analyze error messages
                if any('authentication' in msg.lower() or 'unauthorized' in msg.lower() or 'forbidden' in msg.lower() 
                       for msg in error_messages):
                    auth_status = "FAILED - Auth required but not working"
                elif any('csrf' in msg.lower() for msg in error_messages):
                    auth_status = "FAILED - CSRF token validation failed"
                elif any('permission' in msg.lower() or 'authorization' in msg.lower() 
                         for msg in error_messages):
                    auth_status = "PARTIAL - Authenticated but insufficient permissions"
                elif status == 401 or status == 403:
                    auth_status = f"FAILED - HTTP {status} indicates auth failure"
                else:
                    auth_status = "WORKING - Error is NOT auth-related (likely validation/business logic)"
                    print(f"[ANALYSIS] Status {status} with generic error suggests auth passed")
            elif result.get('data'):
                print(f"[RESULT] Data: {json.dumps(result['data'], indent=2)}")
                if result['data'].get('reportTaskStart'):
                    auth_status = "WORKING - Mutation executed successfully"
                else:
                    auth_status = "UNKNOWN - Check data structure"
            else:
                print(f"[RESULT] Full Response: {json.dumps(result, indent=2)}")
                auth_status = "UNKNOWN - No errors or data"
            
            print(f"[AUTH STATUS] {auth_status}")
            
            results.append({
                'scenario': scenario['name'],
                'status_code': status,
                'auth_status': auth_status,
                'has_errors': bool(result.get('errors')),
                'has_data': bool(result.get('data')),
                'errors': result.get('errors', [])
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
    print(f"{'Scenario':<35} {'Status':<8} {'Auth Status':<50}")
    print("-" * 95)
    for r in results:
        status_code = r.get('status_code', 'N/A')
        auth_status = r.get('auth_status', r.get('status', 'ERROR'))
        # Truncate long status messages
        if len(auth_status) > 48:
            auth_status = auth_status[:45] + "..."
        print(f"{r['scenario']:<35} {str(status_code):<8} {auth_status:<50}")
    
    print("\n" + "=" * 70)
    print("CONCLUSION")
    print("=" * 70)
    
    # Analyze results
    token_only = next((r for r in results if 'Token Only' in r.get('scenario', '')), None)
    cookie_only = next((r for r in results if 'Cookie Only' in r.get('scenario', '')), None)
    full_auth = next((r for r in results if 'Full Auth' in r.get('scenario', '')), None)
    no_auth = next((r for r in results if 'No Auth' in r.get('scenario', '')), None)
    
    if full_auth and no_auth:
        if full_auth.get('status_code') == 200 and no_auth.get('status_code') in [401, 403]:
            print("[OK] Token header authentication is WORKING")
            print("  - Requests with Token succeed")
            print("  - Requests without Token are rejected")
        elif full_auth.get('status_code') == no_auth.get('status_code'):
            if full_auth.get('has_data') and not no_auth.get('has_data'):
                print("[OK] Token header authentication is WORKING")
                print("  - Different data returned with vs without Token")
            elif full_auth.get('errors') != no_auth.get('errors'):
                print("[OK] Token header authentication appears to be WORKING")
                print("  - Different errors with vs without Token")
            else:
                print("[WARN] Token header may NOT be required")
                print("  - Similar responses with and without Token")
        else:
            print("[INFO] Mixed results - review individual scenarios above")
    
    if token_only and cookie_only:
        if token_only.get('status_code') == 200 and cookie_only.get('status_code') != 200:
            print("\n[INFO] Token header is REQUIRED, Cookie may not be")
        elif cookie_only.get('status_code') == 200 and token_only.get('status_code') != 200:
            print("\n[INFO] Cookie may be required, Token may not be")
        elif token_only.get('status_code') == cookie_only.get('status_code') == 200:
            print("\n[INFO] Both Token and Cookie work independently")

if __name__ == "__main__":
    test_token_auth()
