#!/usr/bin/env python3
"""
Test script to validate authentication by testing the actual mutation from the request
"""

import sys
import json
from pathlib import Path

# Add lib directory to path
sys.path.insert(0, str(Path(__file__).parent / "lib"))

from graphql_client import GraphQLClient

# Original mutation from the request
MUTATION_QUERY = """mutation selfServeCreatePatient(
          $accessCode: String!
          $address: String
          $city: String
          $country: String
          $dateOfBirth: DateTime!
          $email: String!
          $firstName: String!
          $gender: String
          $initialAppVersion: String
          $language: String
          $lastName: String!
          $notIntendedToTreatAcknowledgedAt: String
          $password: String!
          $pdtUid: String!
          $phone: String
          $postalCode: String
          $safetyAcknowledgedAt: String
          $state: String
          $termsAndPrivacyAcknowledgedAt: String
        ){
          selfServeCreatePatient(
            accessCode: $accessCode,
            address: $address,
            city: $city,
            country: $country,
            dateOfBirth: $dateOfBirth,
            email: $email,
            firstName: $firstName,
            gender: $gender,
            initialAppVersion: $initialAppVersion,
            language: $language,
            lastName: $lastName,
            notIntendedToTreatAcknowledgedAt: $notIntendedToTreatAcknowledgedAt,
            password: $password,
            pdtUid: $pdtUid,
            phone: $phone,
            postalCode: $postalCode,
            safetyAcknowledgedAt: $safetyAcknowledgedAt,
            state: $state,
            termsAndPrivacyAcknowledgedAt: $termsAndPrivacyAcknowledgedAt){
            success
            patient{
              uid
              user{
                uid
                email
                emailVerified
                firstName
                lastName
                createdAt
                isActive
              }
            }
          }
        }"""

MUTATION_VARIABLES = {
    "accessCode": "YOUR_ACCESS_CODE",
    "address": "123 Example Street",
    "city": "Example City",
    "country": "US",
    "dateOfBirth": "2005-01-01T13:10:20Z",
    "email": "your-test-user@example.com",
    "firstName": "Example",
    "gender": "M",    
    "initialAppVersion": "3.0",
    "language": "EN",
    "lastName": "User",
    "notIntendedToTreatAcknowledgedAt": "2024-01-01T13:10:20Z",
    "password": "YOUR_PASSWORD",
    "pdtUid": "YOUR_PDT_UID",
    "phone": "8005551234",
    "postalCode": "12345",
    "safetyAcknowledgedAt": "2024-01-01T13:10:20Z",
    "state": "ExampleState",
    "termsAndPrivacyAcknowledgedAt": "2024-01-01T13:10:20Z"
}

def test_auth_scenarios():
    """Test different auth scenarios"""
    url = "https://api.example.com/graphql/"
    
    print("=" * 70)
    print("AUTHENTICATION VALIDATION TEST")
    print("=" * 70)
    print(f"Target: {url}\n")
    
    results = []
    
    scenarios = [
        {
            "name": "Original Request Headers (with Cookie)",
            "headers": {
                "User-Agent": "PostmanRuntime/7.51.0",
                "Accept": "*/*",
                "Postman-Token": "52cceb0e-c3e6-4366-a200-1c2e332223e3",
                "Accept-Encoding": "gzip, deflate, br",
                "Cookie": "csrftoken=YOUR_CSRF_TOKEN"
            }
        },
        {
            "name": "Cookie Only",
            "headers": {
                "Cookie": "csrftoken=YOUR_CSRF_TOKEN"
            }
        },
        {
            "name": "No Auth Headers",
            "headers": {}
        }
    ]
    
    for scenario in scenarios:
        print(f"\n{'='*70}")
        print(f"Testing: {scenario['name']}")
        print(f"{'='*70}")
        print(f"Headers: {json.dumps(scenario['headers'], indent=2)}")
        
        try:
            client = GraphQLClient(
                url=url,
                headers=scenario['headers'],
                verbose=True,
                test_connection=False  # Skip initial connection test
            )
            
            print(f"\n[TEST] Executing mutation: selfServeCreatePatient")
            result = client.query(
                query=MUTATION_QUERY,
                variables=MUTATION_VARIABLES,
                operation_name="selfServeCreatePatient"
            )
            
            status = result.get('_status_code', 0)
            print(f"\n[RESULT] Status Code: {status}")
            
            if result.get('errors'):
                print(f"[RESULT] Errors: {json.dumps(result['errors'], indent=2)}")
                error_messages = [e.get('message', '') for e in result.get('errors', [])]
                
                # Analyze error messages
                if any('authentication' in msg.lower() or 'unauthorized' in msg.lower() or 'forbidden' in msg.lower() 
                       for msg in error_messages):
                    print(f"[AUTH STATUS] FAILED - Auth required but not working")
                elif any('csrf' in msg.lower() for msg in error_messages):
                    print(f"[AUTH STATUS] FAILED - CSRF token validation failed")
                elif any('permission' in msg.lower() or 'authorization' in msg.lower() 
                         for msg in error_messages):
                    print(f"[AUTH STATUS] PARTIAL - Authenticated but insufficient permissions")
                elif status == 401 or status == 403:
                    print(f"[AUTH STATUS] FAILED - HTTP {status} indicates auth failure")
                else:
                    print(f"[AUTH STATUS] WORKING - Error is NOT auth-related (likely validation/business logic)")
                    print(f"[ANALYSIS] Status {status} with generic error suggests auth passed, mutation rejected for other reasons")
            elif result.get('data'):
                print(f"[RESULT] Data: {json.dumps(result['data'], indent=2)}")
                if result['data'].get('selfServeCreatePatient'):
                    print(f"[AUTH STATUS] WORKING - Mutation executed successfully")
                else:
                    print(f"[AUTH STATUS] UNKNOWN - Check data structure")
            else:
                print(f"[RESULT] Full Response: {json.dumps(result, indent=2)}")
                print(f"[AUTH STATUS] ⚠️  UNKNOWN STATUS - No errors or data")
                
        except Exception as e:
            print(f"[ERROR] Exception occurred: {e}")
            import traceback
            traceback.print_exc()
            results.append({
                'scenario': scenario['name'],
                'status': 'ERROR',
                'error': str(e)
            })
        else:
            # Store result for comparison
            auth_status = "UNKNOWN"
            if result.get('errors'):
                error_msgs = [e.get('message', '') for e in result.get('errors', [])]
                if any('authentication' in m.lower() or 'unauthorized' in m.lower() 
                       for m in error_msgs) or status in [401, 403]:
                    auth_status = "FAILED"
                else:
                    auth_status = "WORKING (validation error)"
            elif result.get('data'):
                auth_status = "WORKING"
            
            results.append({
                'scenario': scenario['name'],
                'status_code': status,
                'auth_status': auth_status,
                'has_errors': bool(result.get('errors')),
                'has_data': bool(result.get('data'))
            })
        
        print()
    
    # Print comparison summary
    print("\n" + "=" * 70)
    print("COMPARISON SUMMARY")
    print("=" * 70)
    print(f"{'Scenario':<40} {'Status':<8} {'Auth Status':<30}")
    print("-" * 70)
    for r in results:
        status_code = r.get('status_code', 'N/A')
        auth_status = r.get('auth_status', r.get('status', 'ERROR'))
        print(f"{r['scenario']:<40} {str(status_code):<8} {auth_status:<30}")
    
    print("\n" + "=" * 70)
    print("CONCLUSION")
    print("=" * 70)
    
    # Analyze results
    all_same = len(set(r.get('auth_status', r.get('status', '')) for r in results)) == 1
    all_200 = all(r.get('status_code') == 200 for r in results if 'status_code' in r)
    
    if all_same and all_200:
        print("All scenarios returned HTTP 200 with similar responses.")
        print("This indicates:")
        print("  - Authentication is NOT the blocking issue")
        print("  - The server accepts requests regardless of auth headers")
        print("  - Errors are likely due to validation/business logic, not auth")
        print("\nRECOMMENDATION: The provided Cookie/CSRF token may not be required")
        print("  OR the mutation requires additional authentication (e.g., JWT token)")
        print("  OR the mutation is failing due to invalid data (duplicate email, etc.)")
    elif any(r.get('status_code') in [401, 403] for r in results if 'status_code' in r):
        print("Some scenarios returned 401/403, indicating authentication IS required.")
        print("Compare which scenarios worked vs failed to identify required auth.")
    else:
        print("Mixed results - review individual scenario outputs above.")

if __name__ == "__main__":
    test_auth_scenarios()
