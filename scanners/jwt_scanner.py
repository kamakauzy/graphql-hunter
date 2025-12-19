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
                
                # Test token expiration
                findings.extend(self._test_token_expiration())
        
        # Also check for Token header (custom JWT header)
        elif 'Token' in self.client.headers:
            token_value = self.client.headers['Token']
            # Check if it's a JWT
            jwt_pattern = r'^([A-Za-z0-9-_]+)\.([A-Za-z0-9-_]+)\.([A-Za-z0-9-_]+)$'
            if re.match(jwt_pattern, token_value):
                findings.append(create_finding(
                    title="JWT Token Authentication Detected (Custom Header)",
                    severity="INFO",
                    description="The application uses JWT tokens in a custom 'Token' header for authentication.",
                    impact="If JWT tokens are not properly validated, attackers may forge tokens, bypass authentication, or escalate privileges.",
                    remediation="Ensure JWT tokens are: 1) Validated on every request, 2) Use strong signing algorithms (RS256, not 'none'), 3) Have appropriate expiration times, 4) Include audience and issuer claims.",
                    cwe="CWE-347: Improper Verification of Cryptographic Signature",
                    evidence={
                        'jwt_detected': True,
                        'header': 'Token'
                    },
                    url=self.client.url
                ))
                findings.extend(self._test_token_expiration())
        
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
    
    def _test_token_expiration(self) -> List[Dict]:
        """Test token expiration enforcement"""
        findings = []
        
        import base64
        import json
        import time
        
        # Get current token
        token = None
        if 'Authorization' in self.client.headers:
            auth_value = self.client.headers['Authorization']
            if auth_value.startswith('Bearer '):
                token = auth_value[7:]
        elif 'Token' in self.client.headers:
            token = self.client.headers['Token']
        
        if not token:
            return findings
        
        try:
            # Decode JWT (without verification)
            parts = token.split('.')
            if len(parts) != 3:
                return findings
            
            # Decode payload
            payload_b64 = parts[1]
            # Add padding if needed
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += '=' * padding
            
            payload_json = base64.urlsafe_b64decode(payload_b64)
            payload = json.loads(payload_json)
            
            # Check expiration
            exp = payload.get('exp')
            iat = payload.get('iat')
            
            if exp:
                current_time = int(time.time())
                expires_at = int(exp)
                time_until_expiry = expires_at - current_time
                
                if time_until_expiry < 0:
                    # Token is already expired
                    findings.append(create_finding(
                        title="Expired JWT Token Detected",
                        severity="MEDIUM",
                        description=f"The current JWT token has expired (exp: {expires_at}, current: {current_time}). Testing if expired tokens are still accepted.",
                        impact="If expired tokens are still accepted, attackers can use old tokens indefinitely, bypassing token expiration security controls.",
                        remediation="Ensure the server validates token expiration (exp claim) on every request and rejects expired tokens immediately.",
                        cwe="CWE-613: Improper Authentication",
                        evidence={
                            'token_expired': True,
                            'exp_claim': expires_at,
                            'current_time': current_time
                        },
                        url=self.client.url
                    ))
                    
                    # Test if expired token still works
                    result = self.client.query('{ __typename }')
                    if result.get('data') and not result.get('errors'):
                        findings.append(create_finding(
                            title="Expired JWT Token Still Accepted",
                            severity="HIGH",
                            description="The server accepted a query using an expired JWT token, indicating token expiration is not properly enforced.",
                            impact="Expired tokens should be rejected immediately. If they're still accepted, attackers can use compromised or old tokens indefinitely.",
                            remediation="IMMEDIATELY fix token validation to check the 'exp' claim and reject expired tokens. Ensure token validation happens on every request.",
                            cwe="CWE-613: Improper Authentication",
                            evidence={
                                'expired_token_accepted': True,
                                'exp_claim': expires_at
                            },
                            poc="Use expired token in Authorization header",
                            url=self.client.url
                        ))
                else:
                    # Token is still valid
                    hours_until_expiry = time_until_expiry / 3600
                    if hours_until_expiry > 24:
                        findings.append(create_finding(
                            title="Long-Lived JWT Token",
                            severity="LOW",
                            description=f"JWT token has a long expiration time ({hours_until_expiry:.1f} hours until expiry). Long-lived tokens increase the risk if compromised.",
                            impact="If a long-lived token is compromised, attackers can use it for an extended period. Shorter token lifetimes limit the window of opportunity for attackers.",
                            remediation="Consider implementing shorter token lifetimes (e.g., 1-4 hours) with refresh tokens for longer sessions. Implement token rotation and revocation mechanisms.",
                            cwe="CWE-613: Improper Authentication",
                            evidence={
                                'hours_until_expiry': round(hours_until_expiry, 1),
                                'exp_claim': expires_at
                            },
                            url=self.client.url
                        ))
            
            # Check for refresh token mechanism
            if iat and exp:
                token_lifetime = exp - iat
                if token_lifetime > 0:
                    findings.append(create_finding(
                        title="JWT Token Expiration Information",
                        severity="INFO",
                        description=f"JWT token has expiration configured (lifetime: {token_lifetime // 3600} hours). Verify expiration is enforced server-side.",
                        impact="Token expiration helps limit the impact of token compromise. Ensure expiration is properly validated.",
                        remediation="Verify that the server checks the 'exp' claim on every request and rejects expired tokens. Implement refresh token mechanism for seamless re-authentication.",
                        evidence={
                            'token_lifetime_hours': token_lifetime // 3600,
                            'iat': iat,
                            'exp': exp
                        },
                        url=self.client.url
                    ))
        
        except Exception as e:
            # If we can't decode the token, that's okay - just skip expiration testing
            pass
        
        return findings

