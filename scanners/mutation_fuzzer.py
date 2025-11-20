#!/usr/bin/env python3
"""
Mutation Fuzzer - Tests mutations for security issues
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from graphql_client import GraphQLClient
from reporter import Reporter
from utils import create_finding
from typing import List, Dict


class MutationFuzzer:
    """Scanner for mutation security issues"""
    
    def __init__(self, client: GraphQLClient, reporter: Reporter, config: Dict):
        """
        Initialize mutation fuzzer
        
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
        Run mutation fuzzing scan
        
        Returns:
            List of findings
        """
        findings = []
        
        if not self.client.schema:
            self.reporter.print_info("Schema not available, skipping mutation tests")
            return findings
        
        mutations = self.client.get_mutations()
        
        if not mutations:
            self.reporter.print_info("No mutations found in schema")
            return findings
        
        self.reporter.print_info(f"Found {len(mutations)} mutations to analyze")
        
        # Test for dangerous mutations
        findings.extend(self._identify_dangerous_mutations(mutations))
        
        # Test mutation access without auth
        findings.extend(self._test_unauth_mutations(mutations))
        
        # Test for IDOR in mutations
        findings.extend(self._test_idor_mutations(mutations))
        
        return findings
    
    def _identify_dangerous_mutations(self, mutations: List[Dict]) -> List[Dict]:
        """Identify potentially dangerous mutations"""
        findings = []
        
        if not mutations:
            return findings
        
        dangerous_keywords = [
            'delete', 'remove', 'drop', 'destroy', 'admin', 'privilege',
            'permission', 'role', 'grant', 'revoke', 'ban', 'disable'
        ]
        
        dangerous_mutations = []
        
        for mutation in mutations:
            if not mutation or not isinstance(mutation, dict):
                continue
            mutation_name = mutation.get('name', '').lower()
            
            for keyword in dangerous_keywords:
                if keyword in mutation_name:
                    dangerous_mutations.append({
                        'name': mutation.get('name'),
                        'keyword': keyword,
                        'args': mutation.get('args', [])
                    })
                    break
        
        if dangerous_mutations:
            mutation_names = ', '.join([m['name'] for m in dangerous_mutations[:5]])
            
            # Create POC with first dangerous mutation
            example_mutation = dangerous_mutations[0]['name'] if dangerous_mutations else 'deleteSomething'
            poc_query = f"mutation {{ {example_mutation} {{ __typename }} }}"
            
            findings.append(create_finding(
                title="Potentially Dangerous Mutations Found",
                severity="MEDIUM",
                description=f"Found {len(dangerous_mutations)} mutations with names suggesting destructive or privileged operations: {mutation_names}",
                impact="Mutations that modify critical data or permissions must have robust authorization checks. If these checks are missing or flawed, attackers could perform unauthorized privileged operations.",
                remediation="Ensure all dangerous mutations require strong authentication and authorization. Implement role-based access control (RBAC). Add audit logging for all sensitive mutations. Consider implementing mutation rate limiting.",
                cwe="CWE-862: Missing Authorization",
                evidence={
                    'dangerous_mutations': dangerous_mutations[:10]
                },
                poc=poc_query,
                url=self.client.url
            ))
        
        return findings
    
    def _test_unauth_mutations(self, mutations: List[Dict]) -> List[Dict]:
        """Test if mutations are accessible without authentication"""
        findings = []
        
        # Create unauthenticated client
        try:
            unauth_client = GraphQLClient(
                url=self.client.url,
                headers={'Content-Type': 'application/json'},
                proxy=self.client.proxies.get('http') if self.client.proxies else None,
                delay=self.client.delay,
                verbose=False
            )
            
            # Try to introspect mutations without auth
            schema = unauth_client.introspect()
            
            if schema:
                unauth_mutations = unauth_client.get_mutations()
                
                if unauth_mutations and len(unauth_mutations) > 0:
                    findings.append(create_finding(
                        title="Mutations Discoverable Without Authentication",
                        severity="MEDIUM",
                        description=f"Discovered {len(unauth_mutations)} mutations without authentication. While discovery doesn't mean they're exploitable, it aids in reconnaissance.",
                        impact="Attackers can discover all available mutations without authentication, allowing them to map the attack surface and identify potential targets.",
                        remediation="Consider requiring authentication even for introspection. This reduces information disclosure to unauthenticated users.",
                        cwe="CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
                        evidence={
                            'mutation_count': len(unauth_mutations)
                        },
                        poc="{ __schema { mutationType { name fields { name } } } }",
                        url=self.client.url
                    ))
        
        except Exception:
            # If unauthenticated access fails, that's actually good
            pass
        
        return findings
    
    def _test_idor_mutations(self, mutations: List[Dict]) -> List[Dict]:
        """Test for potential IDOR vulnerabilities in mutations"""
        findings = []
        
        if not mutations:
            return findings
        
        # Look for mutations that take ID arguments
        idor_candidates = []
        
        for mutation in mutations:
            if not mutation or not isinstance(mutation, dict):
                continue
            mutation_name = mutation.get('name', '')
            args = mutation.get('args', [])
            
            for arg in args:
                arg_name = arg.get('name', '').lower()
                arg_type = self._extract_type_name(arg.get('type', {}))
                
                # Look for ID-like arguments
                if 'id' in arg_name or arg_type == 'ID' or arg_type == 'Int':
                    idor_candidates.append({
                        'mutation': mutation_name,
                        'argument': arg.get('name'),
                        'type': arg_type
                    })
                    break
        
        if idor_candidates:
            sample_mutations = ', '.join([m['mutation'] for m in idor_candidates[:5]])
            
            # Create POC for testing IDOR
            example_mutation = idor_candidates[0]['mutation'] if idor_candidates else 'editItem'
            example_arg = idor_candidates[0]['argument'] if idor_candidates else 'id'
            poc_query = f"mutation {{ {example_mutation}({example_arg}: 999) {{ __typename }} }}"
            
            findings.append(create_finding(
                title="Potential IDOR Vulnerabilities in Mutations",
                severity="HIGH",
                description=f"Found {len(idor_candidates)} mutations that accept ID arguments: {sample_mutations}. These are potential IDOR (Insecure Direct Object Reference) targets.",
                impact="If these mutations don't properly validate that the user is authorized to modify the object identified by the ID, attackers could manipulate other users' data by simply changing the ID parameter.",
                remediation="Implement object-level authorization checks in all mutations. Verify that the authenticated user has permission to modify the specific object before executing the mutation. Never rely solely on possessing the ID as proof of authorization.",
                cwe="CWE-639: Authorization Bypass Through User-Controlled Key",
                evidence={
                    'idor_candidates': idor_candidates[:10]
                },
                poc=poc_query,
                url=self.client.url
            ))
        
        return findings
    
    def _extract_type_name(self, type_def: Dict) -> str:
        """Extract type name from type definition"""
        if not type_def:
            return "Unknown"
        
        if type_def.get('name'):
            return type_def['name']
        
        if type_def.get('ofType'):
            return self._extract_type_name(type_def['ofType'])
        
        return "Unknown"

