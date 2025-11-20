#!/usr/bin/env python3
"""
JWT Scanner - Tests for JWT token vulnerabilities
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from graphql_client import GraphQLClient
from reporter import Reporter
from utils import create_finding
from typing import List, Dict
import re


class JWTScanner:
    """Scanner for JWT vulnerabilities"""
    
    def __init__(self, client: GraphQLClient, reporter: Reporter, config: Dict):
        """
        Initialize JWT scanner
        
        Args:
            client: GraphQL client instance
            reporter: Reporter instance
            config: Scanner configuration
        """
        self.client = client
        self.reporter = reporter
        self.config = config
    
    def scan(self) -> List[Dict]:
        """
        Run JWT scan
        
        Returns:
            List of findings
        """
        findings = []
        
        # Check if JWT tokens are used
        self.reporter.print_info("Checking for JWT usage...")
        findings.extend(self._check_jwt_usage())
        
        return findings
    
    def _check_jwt_usage(self) -> List[Dict]:
        """Check if the API uses JWT tokens"""
        findings = []
        
        # Check if Authorization header with JWT is being used
        if 'Authorization' in self.client.headers:
            auth_value = self.client.headers['Authorization']
            
            # Check for JWT pattern (three base64 segments separated by dots)
            jwt_pattern = r'^Bearer\s+([A-Za-z0-9-_]+)\.([A-Za-z0-9-_]+)\.([A-Za-z0-9-_]+)$'
            
            if re.match(jwt_pattern, auth_value):
                findings.append(create_finding(
                    title="JWT Token Authentication Detected",
                    severity="INFO",
                    description="The application uses JWT tokens for authentication. Ensure proper validation and security measures are in place.",
                    impact="If JWT tokens are not properly validated, attackers may forge tokens, bypass authentication, or escalate privileges.",
                    remediation="Ensure JWT tokens are: 1) Validated on every request, 2) Use strong signing algorithms (RS256, not 'none'), 3) Have appropriate expiration times, 4) Include audience and issuer claims, 5) Are not accepted with algorithm 'none'.",
                    cwe="CWE-347: Improper Verification of Cryptographic Signature",
                    evidence={
                        'jwt_detected': True
                    },
                url=self.client.url
            ))
                
                # Test for 'none' algorithm vulnerability
                findings.extend(self._test_none_algorithm())
        
        return findings
    
    def _test_none_algorithm(self) -> List[Dict]:
        """Test if server accepts JWT with 'none' algorithm"""
        findings = []
        
        # Try a query with a forged JWT using 'none' algorithm
        # This is a common JWT vulnerability
        # Format: header.payload.signature where header specifies "alg":"none"
        
        # Base64 encode {"alg":"none","typ":"JWT"}
        forged_header = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
        # Base64 encode {"sub":"1234567890","name":"Admin","admin":true}
        forged_payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiYWRtaW4iOnRydWV9"
        # No signature for 'none' algorithm
        forged_jwt = f"{forged_header}.{forged_payload}."
        
        # Create a test client with forged JWT
        test_headers = self.client.headers.copy()
        test_headers['Authorization'] = f'Bearer {forged_jwt}'
        
        test_client = GraphQLClient(
            url=self.client.url,
            headers=test_headers,
            proxy=self.client.proxies.get('http') if self.client.proxies else None,
            delay=0,
            verbose=False
        )
        
        # Try introspection with forged token
        try:
            result = test_client.query('{ __typename }')
            
            if result.get('data') and not result.get('errors'):
                findings.append(create_finding(
                    title="JWT 'none' Algorithm Vulnerability",
                    severity="CRITICAL",
                    description="The server accepted a JWT token with algorithm 'none', allowing complete authentication bypass. This is a critical security flaw.",
                    impact="Attackers can forge any JWT token and impersonate any user, including administrators, leading to complete authentication bypass.",
                    remediation="IMMEDIATELY disable acceptance of JWT tokens with 'none' algorithm. Implement strict algorithm validation and only accept secure algorithms like RS256 or ES256.",
                    cwe="CWE-347: Improper Verification of Cryptographic Signature",
                    evidence={
                        'forged_token_accepted': True,
                        'algorithm': 'none'
                    },
                    poc=f"Authorization: Bearer {forged_jwt}"
                ))
        except Exception:
            # If it fails, that's actually good - means server is validating properly
            pass
        
        return findings

