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
                }
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
                    }
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
                }
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
                }
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

