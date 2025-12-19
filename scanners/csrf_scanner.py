#!/usr/bin/env python3
"""
CSRF Scanner - Tests for Cross-Site Request Forgery vulnerabilities
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from graphql_client import GraphQLClient
from reporter import Reporter
from utils import create_finding
from typing import List, Dict
from urllib.parse import urlparse


class CSRFScanner:
    """Scanner for CSRF vulnerabilities"""
    
    def __init__(self, client: GraphQLClient, reporter: Reporter, config: Dict):
        """
        Initialize CSRF scanner
        
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
        Run CSRF scan
        
        Returns:
            List of findings
        """
        findings = []
        
        # Check if client uses cookies (session-based auth)
        has_cookies = self._has_cookie_based_auth()
        
        if not has_cookies:
            self.reporter.print_info("No cookie-based authentication detected, skipping CSRF tests")
            return findings
        
        # Test mutations for CSRF vulnerabilities
        if not self.client.schema:
            self.reporter.print_warning("Schema not available, skipping CSRF tests")
            return findings
        
        mutations = self.client.get_mutations()
        if not mutations:
            self.reporter.print_info("No mutations found, skipping CSRF tests")
            return findings
        
        self.reporter.print_info("Testing mutations for CSRF vulnerabilities...")
        findings.extend(self._test_missing_origin(mutations))
        findings.extend(self._test_origin_mismatch(mutations))
        findings.extend(self._test_csrf_token_validation(mutations))
        
        return findings
    
    def _has_cookie_based_auth(self) -> bool:
        """Check if client uses cookie-based authentication"""
        # Check headers for Cookie
        if 'Cookie' in self.client.headers:
            return True
        
        # Check if session has cookies
        if hasattr(self.client, 'session') and self.client.session:
            if self.client.session.cookies:
                return True
        
        return False
    
    def _test_missing_origin(self, mutations: List[Dict]) -> List[Dict]:
        """Test mutations with missing Origin header"""
        findings = []
        
        # Find a mutation to test
        test_mutation = self._find_testable_mutation(mutations)
        if not test_mutation:
            return findings
        
        mutation_name = test_mutation.get('name')
        args = test_mutation.get('args', [])
        
        # Build mutation
        variables = self._build_mutation_variables(args)
        mutation_query = self._build_mutation_query(mutation_name, args, variables)
        
        # Test without Origin header
        headers_without_origin = dict(self.client.headers)
        if 'Origin' in headers_without_origin:
            del headers_without_origin['Origin']
        if 'Referer' in headers_without_origin:
            del headers_without_origin['Referer']
        
        # Create test client without Origin
        test_client = GraphQLClient(
            url=self.client.url,
            headers=headers_without_origin,
            proxy=self.client.proxies.get('http') if self.client.proxies else None,
            delay=self.client.delay,
            verbose=False,
            test_connection=False
        )
        
        # Copy session cookies if available
        if hasattr(self.client, 'session') and self.client.session:
            test_client.session.cookies.update(self.client.session.cookies)
        
        result = test_client.query(mutation_query, variables=variables if variables else None)
        
        # If mutation succeeds without Origin, it may be vulnerable
        if result.get('data') and not result.get('errors'):
            findings.append(create_finding(
                title="CSRF Vulnerability: Missing Origin Header Validation",
                severity="HIGH",
                description=f"Mutation {mutation_name} executed successfully without an Origin header, indicating potential CSRF vulnerability.",
                impact="Without Origin header validation, attackers can craft malicious websites that perform unauthorized mutations on behalf of authenticated users. This can lead to data modification, account takeover, or other unauthorized actions.",
                remediation="Implement CSRF protection: 1) Validate Origin/Referer headers for state-changing operations, 2) Use CSRF tokens, 3) Implement SameSite cookie attributes, 4) Require custom headers (X-Requested-With) for mutations.",
                cwe="CWE-352: Cross-Site Request Forgery (CSRF)",
                evidence={
                    'mutation': mutation_name,
                    'origin_header': 'missing',
                    'mutation_succeeded': True
                },
                poc=mutation_query,
                url=self.client.url
            ))
        elif result.get('errors'):
            # Check if error is CSRF-related
            error_text = str(result['errors']).lower()
            if 'csrf' in error_text or 'origin' in error_text or 'referer' in error_text:
                findings.append(create_finding(
                    title="CSRF Protection Detected",
                    severity="INFO",
                    description=f"Mutation {mutation_name} rejected requests without Origin header, indicating CSRF protection is implemented.",
                    impact="CSRF protection helps prevent unauthorized cross-site requests.",
                    remediation="Ensure CSRF protection is consistently applied to all state-changing operations.",
                    evidence={
                        'mutation': mutation_name,
                        'protection_detected': True
                    },
                    url=self.client.url
                ))
        
        return findings
    
    def _test_origin_mismatch(self, mutations: List[Dict]) -> List[Dict]:
        """Test mutations with mismatched Origin header"""
        findings = []
        
        test_mutation = self._find_testable_mutation(mutations)
        if not test_mutation:
            return findings
        
        mutation_name = test_mutation.get('name')
        args = test_mutation.get('args', [])
        
        variables = self._build_mutation_variables(args)
        mutation_query = self._build_mutation_query(mutation_name, args, variables)
        
        # Get the actual origin from URL
        parsed_url = urlparse(self.client.url)
        actual_origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Test with wrong origin
        headers_with_wrong_origin = dict(self.client.headers)
        headers_with_wrong_origin['Origin'] = 'https://evil.com'
        headers_with_wrong_origin['Referer'] = 'https://evil.com/attack'
        
        test_client = GraphQLClient(
            url=self.client.url,
            headers=headers_with_wrong_origin,
            proxy=self.client.proxies.get('http') if self.client.proxies else None,
            delay=self.client.delay,
            verbose=False,
            test_connection=False
        )
        
        if hasattr(self.client, 'session') and self.client.session:
            test_client.session.cookies.update(self.client.session.cookies)
        
        result = test_client.query(mutation_query, variables=variables if variables else None)
        
        if result.get('data') and not result.get('errors'):
            findings.append(create_finding(
                title="CSRF Vulnerability: Origin Header Not Validated",
                severity="HIGH",
                description=f"Mutation {mutation_name} executed successfully with a mismatched Origin header (evil.com), indicating CSRF protection is not properly implemented.",
                impact="Attackers can craft malicious websites that perform unauthorized mutations by sending requests with arbitrary Origin headers. This allows cross-site request forgery attacks.",
                remediation="Validate Origin and Referer headers to match the expected domain. Reject requests with missing or mismatched Origin headers for state-changing operations.",
                cwe="CWE-352: Cross-Site Request Forgery (CSRF)",
                evidence={
                    'mutation': mutation_name,
                    'origin_header': 'https://evil.com',
                    'expected_origin': actual_origin,
                    'mutation_succeeded': True
                },
                poc=mutation_query,
                url=self.client.url
            ))
        
        return findings
    
    def _test_csrf_token_validation(self, mutations: List[Dict]) -> List[Dict]:
        """Test if CSRF tokens are validated"""
        findings = []
        
        # Check if CSRF token is in headers or cookies
        has_csrf_token = False
        csrf_token_name = None
        
        # Check headers
        for header_name in self.client.headers:
            if 'csrf' in header_name.lower() or 'xsrf' in header_name.lower():
                has_csrf_token = True
                csrf_token_name = header_name
                break
        
        # Check cookies
        if not has_csrf_token and hasattr(self.client, 'session'):
            for cookie_name in self.client.session.cookies.keys():
                if 'csrf' in cookie_name.lower() or 'xsrf' in cookie_name.lower():
                    has_csrf_token = True
                    csrf_token_name = cookie_name
                    break
        
        if not has_csrf_token:
            findings.append(create_finding(
                title="CSRF Token Not Detected",
                severity="MEDIUM",
                description="No CSRF token found in headers or cookies. The application may rely solely on Origin/Referer validation or may be vulnerable to CSRF.",
                impact="Without CSRF tokens, the application may be vulnerable to CSRF attacks if Origin/Referer validation is insufficient or can be bypassed.",
                remediation="Implement CSRF tokens for all state-changing operations. Tokens should be unique per session and validated on the server side.",
                cwe="CWE-352: Cross-Site Request Forgery (CSRF)",
                evidence={
                    'csrf_token_detected': False
                },
                url=self.client.url
            ))
        else:
            findings.append(create_finding(
                title="CSRF Token Detected",
                severity="INFO",
                description=f"CSRF token found ({csrf_token_name}), indicating CSRF protection may be implemented.",
                impact="CSRF tokens help protect against cross-site request forgery attacks.",
                remediation="Ensure CSRF tokens are validated for all mutations and cannot be bypassed.",
                evidence={
                    'csrf_token_detected': True,
                    'token_location': csrf_token_name
                },
                url=self.client.url
            ))
        
        return findings
    
    def _find_testable_mutation(self, mutations: List[Dict]) -> Dict:
        """Find a mutation suitable for testing"""
        # Prefer mutations with minimal required arguments
        for mutation in mutations:
            args = mutation.get('args', [])
            # Prefer mutations with 0-2 arguments
            if len(args) <= 2:
                return mutation
        
        # Fallback to first mutation
        if mutations:
            return mutations[0]
        
        return None
    
    def _build_mutation_variables(self, args: List[Dict]) -> Dict:
        """Build variables for mutation"""
        variables = {}
        for arg in args[:2]:  # Limit to first 2 args
            arg_name = arg.get('name')
            arg_type = self._extract_type_name(arg.get('type', {}))
            
            if arg_type == 'String' or arg_type == 'ID':
                variables[arg_name] = "test"
            elif arg_type == 'Int':
                variables[arg_name] = 1
            elif arg_type == 'Boolean':
                variables[arg_name] = True
            elif arg_type == 'Float':
                variables[arg_name] = 1.0
        
        return variables
    
    def _build_mutation_query(self, mutation_name: str, args: List[Dict], variables: Dict) -> str:
        """Build mutation query string"""
        if not variables:
            return f'mutation {{ {mutation_name} {{ __typename }} }}'
        
        var_decls = []
        var_calls = []
        for arg_name, value in variables.items():
            arg = next((a for a in args if a.get('name') == arg_name), None)
            if arg:
                arg_type = self._extract_type_name(arg.get('type', {}))
                var_decls.append(f'${arg_name}: {arg_type}!')
                var_calls.append(f'{arg_name}: ${arg_name}')
        
        var_decl_str = ', '.join(var_decls)
        var_call_str = ', '.join(var_calls)
        
        return f'mutation TestCSRF({var_decl_str}) {{ {mutation_name}({var_call_str}) {{ __typename }} }}'
    
    def _extract_type_name(self, type_def: Dict) -> str:
        """Extract type name from type definition"""
        if not type_def:
            return "String"
        
        if type_def.get('name'):
            return type_def['name']
        
        if type_def.get('ofType'):
            return self._extract_type_name(type_def['ofType'])
        
        return "String"
