#!/usr/bin/env python3
"""
Authentication/Authorization Bypass Scanner - Tests for auth vulnerabilities
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from graphql_client import GraphQLClient
from reporter import Reporter
from utils import create_finding
from typing import List, Dict


class AuthBypassScanner:
    """Scanner for authentication and authorization vulnerabilities"""
    
    def __init__(self, client: GraphQLClient, reporter: Reporter, config: Dict):
        """
        Initialize auth bypass scanner
        
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
        Run authentication/authorization bypass scan
        
        Returns:
            List of findings
        """
        findings = []
        
        # Test unauthenticated introspection
        self.reporter.print_info("Testing unauthenticated access...")
        findings.extend(self._test_unauthenticated_access())
        
        # Test for common admin/sensitive queries
        if self.client.schema:
            self.reporter.print_info("Testing for sensitive operations...")
            findings.extend(self._test_sensitive_operations())
        
        # Test field-level authorization
        self.reporter.print_info("Testing field-level authorization...")
        findings.extend(self._test_field_level_auth())
        
        # Test login mutations for brute-force protection
        if self.client.schema:
            self.reporter.print_info("Testing login mutations for brute-force protection...")
            findings.extend(self._test_login_brute_force())
        
        return findings
    
    def _test_unauthenticated_access(self) -> List[Dict]:
        """Test if API allows unauthenticated access"""
        findings = []
        
        # Create a client without auth headers
        unauth_client = GraphQLClient(
            url=self.client.url,
            headers={'Content-Type': 'application/json'},
            proxy=self.client.proxies.get('http') if self.client.proxies else None,
            delay=self.client.delay,
            verbose=False
        )
        
        # Try introspection without auth
        schema = unauth_client.introspect()
        if schema:
                findings.append(create_finding(
                    title="Unauthenticated Introspection Access",
                    severity="HIGH",
                    description="The GraphQL endpoint allows full introspection queries without authentication. This enables anonymous attackers to discover the entire API structure.",
                    impact="Unauthenticated introspection allows anyone to map the complete API surface, including potentially sensitive queries and mutations. This significantly aids in reconnaissance and attack planning.",
                    remediation="Require authentication for introspection queries. Implement authentication middleware that validates credentials before processing introspection requests.",
                    cwe="CWE-306: Missing Authentication for Critical Function",
                    evidence={
                        'unauthenticated_introspection': 'SUCCESS'
                    },
                    poc="{ __schema { queryType { name } } }",
                    url=self.client.url
                ))
        
        # Try a simple query without auth
        result = unauth_client.query('{ __typename }')
        if result.get('data') and not result.get('errors'):
            # Check if it's the same as authenticated
            auth_result = self.client.query('{ __typename }')
            
            if result.get('data') == auth_result.get('data'):
                findings.append(create_finding(
                    title="API Accessible Without Authentication",
                    severity="MEDIUM",
                    description="The GraphQL endpoint responds to queries without requiring authentication.",
                    impact="If the API contains sensitive data or operations, lack of authentication allows unauthorized access. This depends on what data is actually exposed.",
                    remediation="Implement authentication requirements for the GraphQL endpoint. Use middleware to validate authentication tokens before processing queries.",
                    cwe="CWE-306: Missing Authentication for Critical Function",
                    evidence={
                        'unauthenticated_query': 'SUCCESS'
                    },
                    poc="{ __typename }",
                    url=self.client.url
                ))
        
        return findings
    
    def _test_sensitive_operations(self) -> List[Dict]:
        """Test for sensitive operations that may bypass authorization"""
        findings = []
        
        if not self.client.schema:
            return findings
        
        queries = self.client.get_queries()
        mutations = self.client.get_mutations()
        
        if not queries:
            queries = []
        if not mutations:
            mutations = []
        
        # Look for admin/user/privilege-related operations
        sensitive_keywords = [
            'admin', 'user', 'delete', 'remove', 'privilege', 'permission',
            'role', 'grant', 'revoke', 'password', 'secret', 'token'
        ]
        
        sensitive_queries = []
        sensitive_mutations = []
        
        for query in queries:
            query_name = query.get('name', '').lower()
            if any(keyword in query_name for keyword in sensitive_keywords):
                sensitive_queries.append(query.get('name'))
        
        for mutation in mutations:
            mutation_name = mutation.get('name', '').lower()
            if any(keyword in mutation_name for keyword in sensitive_keywords):
                sensitive_mutations.append(mutation.get('name'))
        
        if sensitive_queries:
            findings.append(create_finding(
                title="Sensitive Queries Discovered",
                severity="INFO",
                description=f"Found {len(sensitive_queries)} queries with names suggesting sensitive operations: {', '.join(sensitive_queries[:5])}",
                impact="These queries may expose or manipulate sensitive data. Ensure they have proper authorization checks to prevent unauthorized access.",
                remediation="Review authorization logic for these queries. Implement field-level and object-level authorization checks. Use role-based access control (RBAC).",
                evidence={
                    'sensitive_queries': sensitive_queries
                },
                poc=f"{{ {sensitive_queries[0]} }}",
                url=self.client.url
            ))
        
        if sensitive_mutations:
            findings.append(create_finding(
                title="Sensitive Mutations Discovered",
                severity="MEDIUM",
                description=f"Found {len(sensitive_mutations)} mutations with names suggesting privileged operations: {', '.join(sensitive_mutations[:5])}",
                impact="These mutations can modify sensitive data or system state. If authorization is not properly implemented, attackers could perform privileged operations.",
                remediation="Ensure all sensitive mutations require proper authentication and authorization. Implement checks for user roles and permissions before executing mutations.",
                cwe="CWE-862: Missing Authorization",
                evidence={
                    'sensitive_mutations': sensitive_mutations
                },
                poc=f"mutation {{ {sensitive_mutations[0]} {{ __typename }} }}",
                url=self.client.url
            ))
        
        return findings
    
    def _test_field_level_auth(self) -> List[Dict]:
        """Test field-level authorization"""
        findings = []
        
        # Try to query multiple fields that might have different auth requirements
        test_queries = [
            # Try to access common user fields
            '''
            query TestFieldAuth {
              __typename
            }
            ''',
        ]
        
        # If we have schema, try to query fields that look sensitive
        if self.client.schema:
            types = self.client.get_types()
            
            # Look for User or Admin types
            user_type = None
            for t in types:
                if t.get('kind') == 'OBJECT' and t.get('name', '').lower() in ['user', 'admin', 'account']:
                    user_type = t
                    break
            
            if user_type:
                # Try to query all fields of user type
                fields = user_type.get('fields', [])
                if fields:
                    field_names = [f.get('name') for f in fields[:5]]  # Limit to 5
                    
                    # Note: We can't easily test this without knowing the schema structure
                    findings.append(create_finding(
                        title="User/Account Type Found - Review Field-Level Authorization",
                        severity="INFO",
                        description=f"Found {user_type.get('name')} type with {len(fields)} fields. These fields may contain sensitive information that requires field-level authorization.",
                        impact="If field-level authorization is not implemented, users may be able to access fields they shouldn't see (e.g., other users' emails, passwords, private data).",
                        remediation="Implement field-level authorization using GraphQL middleware or resolver-level checks. Ensure users can only access their own data or data they're authorized to see.",
                        cwe="CWE-639: Authorization Bypass Through User-Controlled Key",
                        evidence={
                            'type': user_type.get('name'),
                            'field_count': len(fields),
                            'sample_fields': field_names
                        }
                    ))
        
        return findings
    
    def _test_login_brute_force(self) -> List[Dict]:
        """Test login mutations for brute-force protection"""
        findings = []
        
        mutations = self.client.get_mutations()
        if not mutations:
            return findings
        
        # Find login/auth mutations
        login_mutations = []
        for mutation in mutations:
            mutation_name = mutation.get('name', '').lower()
            if 'login' in mutation_name or 'auth' in mutation_name or 'signin' in mutation_name:
                login_mutations.append(mutation)
        
        if not login_mutations:
            return findings
        
        # Test brute-force protection
        brute_force_attempts = self.config.get('brute_force_attempts', 20)
        
        # Skip if safe mode
        if self.config.get('safe_mode', False):
            self.reporter.print_info("Safe mode enabled, skipping brute-force tests")
            return findings
        
        for login_mutation in login_mutations[:1]:  # Test first login mutation
            mutation_name = login_mutation.get('name')
            args = login_mutation.get('args', [])
            
            # Find email/username and password arguments
            email_arg = None
            password_arg = None
            
            for arg in args:
                arg_name = arg.get('name', '').lower()
                if 'email' in arg_name or 'username' in arg_name or 'user' in arg_name:
                    email_arg = arg
                elif 'password' in arg_name or 'pass' in arg_name:
                    password_arg = arg
            
            if not email_arg or not password_arg:
                continue
            
            # Build mutation
            email_var = f'${email_arg.get("name")}: String!'
            password_var = f'${password_arg.get("name")}: String!'
            mutation_query = f'mutation TestBruteForce({email_var}, {password_var}) {{ {mutation_name}({email_arg.get("name")}: ${email_arg.get("name")}, {password_arg.get("name")}: ${password_arg.get("name")}) {{ __typename }} }}'
            
            # Send rapid requests with wrong password
            rate_limited = False
            account_locked = False
            captcha_required = False
            success_count = 0
            error_count = 0
            status_codes = {}
            
            test_email = "test@example.com"  # Use a test email
            wrong_passwords = ["wrongpass" + str(i) for i in range(brute_force_attempts)]
            
            for i, wrong_password in enumerate(wrong_passwords):
                variables = {
                    email_arg.get('name'): test_email,
                    password_arg.get('name'): wrong_password
                }
                
                result = self.client.query(mutation_query, variables=variables)
                status = result.get('_status_code', 0)
                status_codes[status] = status_codes.get(status, 0) + 1
                
                if status == 429:
                    rate_limited = True
                    break
                
                if result.get('errors'):
                    error_text = str(result['errors']).lower()
                    if 'lock' in error_text or 'block' in error_text or 'suspended' in error_text:
                        account_locked = True
                        break
                    if 'captcha' in error_text or 'recaptcha' in error_text:
                        captcha_required = True
                        break
                    error_count += 1
                elif result.get('data'):
                    success_count += 1
            
            # Analyze results
            if rate_limited:
                findings.append(create_finding(
                    title="Brute-Force Protection: Rate Limiting Detected",
                    severity="INFO",
                    description=f"Login mutation {mutation_name} returned 429 (Too Many Requests) after {i+1} failed attempts, indicating rate limiting protection.",
                    impact="Rate limiting helps protect against brute-force attacks by limiting the number of login attempts.",
                    remediation="Ensure rate limiting is properly configured with appropriate thresholds and reset windows. Consider implementing progressive delays or account lockout after multiple failures.",
                    cwe="CWE-307: Improper Restriction of Excessive Authentication Attempts",
                    evidence={
                        'mutation': mutation_name,
                        'rate_limited_after_attempts': i+1,
                        'total_attempts': brute_force_attempts
                    },
                    poc=mutation_query,
                    url=self.client.url
                ))
            elif account_locked:
                findings.append(create_finding(
                    title="Brute-Force Protection: Account Lockout Detected",
                    severity="INFO",
                    description=f"Login mutation {mutation_name} indicated account lockout after {i+1} failed attempts, indicating account lockout protection.",
                    impact="Account lockout helps protect against brute-force attacks by temporarily disabling accounts after multiple failed attempts.",
                    remediation="Ensure account lockout is properly configured. Consider implementing temporary lockouts (e.g., 15-30 minutes) rather than permanent locks to avoid DoS.",
                    cwe="CWE-307: Improper Restriction of Excessive Authentication Attempts",
                    evidence={
                        'mutation': mutation_name,
                        'account_locked_after_attempts': i+1
                    },
                    poc=mutation_query,
                    url=self.client.url
                ))
            elif captcha_required:
                findings.append(create_finding(
                    title="Brute-Force Protection: CAPTCHA Detected",
                    severity="INFO",
                    description=f"Login mutation {mutation_name} requires CAPTCHA after multiple attempts, indicating CAPTCHA protection.",
                    impact="CAPTCHA helps protect against automated brute-force attacks.",
                    remediation="Ensure CAPTCHA is properly implemented and cannot be easily bypassed.",
                    evidence={
                        'mutation': mutation_name,
                        'captcha_required': True
                    },
                    poc=mutation_query,
                    url=self.client.url
                ))
            else:
                # No protection detected
                findings.append(create_finding(
                    title="Brute-Force Protection Not Detected",
                    severity="MEDIUM",
                    description=f"Login mutation {mutation_name} did not show rate limiting, account lockout, or CAPTCHA after {brute_force_attempts} failed attempts. This may indicate missing brute-force protection.",
                    impact="Without brute-force protection, attackers can attempt unlimited password guesses, increasing the likelihood of successful account compromise.",
                    remediation="Implement brute-force protection: 1) Rate limiting (e.g., 5 attempts per 15 minutes), 2) Account lockout after multiple failures, 3) CAPTCHA after several attempts, 4) Progressive delays between attempts, 5) IP-based rate limiting.",
                    cwe="CWE-307: Improper Restriction of Excessive Authentication Attempts",
                    evidence={
                        'mutation': mutation_name,
                        'attempts_tested': brute_force_attempts,
                        'no_protection_detected': True,
                        'status_codes': status_codes
                    },
                    poc=mutation_query,
                    url=self.client.url
                ))
        
        return findings

