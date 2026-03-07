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
        
        # Test for mass assignment vulnerabilities
        findings.extend(self._test_mass_assignment(mutations))
        
        # Test for privilege escalation
        findings.extend(self._test_privilege_escalation(mutations))
        
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
                severity="INFO",
                description=f"Found {len(dangerous_mutations)} mutations with names suggesting destructive or privileged operations: {mutation_names}",
                impact="Mutations that modify critical data or permissions must have robust authorization checks. If these checks are missing or flawed, attackers could perform unauthorized privileged operations.",
                remediation="Ensure all dangerous mutations require strong authentication and authorization. Implement role-based access control (RBAC). Add audit logging for all sensitive mutations. Consider implementing mutation rate limiting.",
                cwe="CWE-862: Missing Authorization",
                scanner="mutation_fuzzer",
                classification={'kind': 'manual_review', 'family': 'authz'},
                confidence={'level': 'low', 'reasons': ['Mutation names matched destructive or privileged-operation heuristics']},
                manual_verification_required=True,
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
                        severity="INFO",
                        description=f"Discovered {len(unauth_mutations)} mutations without authentication. While discovery doesn't mean they're exploitable, it aids in reconnaissance.",
                        impact="Attackers can discover all available mutations without authentication, allowing them to map the attack surface and identify potential targets.",
                        remediation="Consider requiring authentication even for introspection. This reduces information disclosure to unauthenticated users.",
                        cwe="CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
                        scanner="mutation_fuzzer",
                        classification={'kind': 'exposure', 'family': 'graphql_surface'},
                        confidence={'level': 'confirmed', 'reasons': ['Unauthenticated introspection revealed mutation names']},
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
            
            id_args = []
            for arg in args:
                arg_name = arg.get('name', '').lower()
                arg_type = self._extract_type_name(arg.get('type', {}))
                
                # Look for ID-like arguments
                if 'id' in arg_name or arg_type == 'ID' or (arg_type == 'Int' and 'id' in arg_name):
                    id_args.append({
                        'name': arg.get('name'),
                        'type': arg_type
                    })
            
            if id_args:
                idor_candidates.append({
                    'mutation': mutation_name,
                    'id_arguments': id_args,
                    'all_args': args
                })
        
        if idor_candidates:
            sample_mutations = ', '.join([m['mutation'] for m in idor_candidates[:5]])
            
            # Create POC for testing IDOR
            example_mutation = idor_candidates[0]['mutation'] if idor_candidates else 'editItem'
            example_arg = idor_candidates[0]['id_arguments'][0]['name'] if idor_candidates[0]['id_arguments'] else 'id'
            poc_query = f"mutation {{ {example_mutation}({example_arg}: \"test-id-123\") {{ __typename }} }}"
            
            # Enhanced recommendations
            recommendations = [
                "Test with different user IDs to verify authorization checks",
                "Test with predictable IDs (sequential numbers, UUIDs)",
                "Test with IDs from other users' resources",
                "Verify server-side authorization before mutation execution",
                "Check if mutations validate user ownership of the resource"
            ]
            
            findings.append(create_finding(
                title="Potential IDOR/BOLA Vulnerabilities in Mutations",
                severity="INFO",
                description=f"Found {len(idor_candidates)} mutations that accept ID arguments: {sample_mutations}. These are potential IDOR (Insecure Direct Object Reference) or BOLA (Broken Object Level Authorization) targets.",
                impact="If these mutations don't properly validate that the user is authorized to modify the object identified by the ID, attackers could manipulate other users' data by simply changing the ID parameter. This is a common vulnerability in GraphQL APIs.",
                remediation="Implement object-level authorization checks in all mutations. Verify that the authenticated user has permission to modify the specific object before executing the mutation. Never rely solely on possessing the ID as proof of authorization. Test manually with multiple user accounts.",
                cwe="CWE-639: Authorization Bypass Through User-Controlled Key",
                scanner="mutation_fuzzer",
                classification={'kind': 'manual_review', 'family': 'authz'},
                confidence={'level': 'low', 'reasons': ['Mutation arguments include object identifiers, but no cross-user access differential was demonstrated']},
                manual_verification_required=True,
                evidence={
                    'idor_candidates': idor_candidates[:10],
                    'manual_testing_recommended': True,
                    'test_recommendations': recommendations
                },
                poc=poc_query,
                url=self.client.url
            ))
        
        return findings
    
    def _test_mass_assignment(self, mutations: List[Dict]) -> List[Dict]:
        """Test mutations for mass assignment vulnerabilities"""
        findings = []
        
        if not mutations:
            return findings
        
        # Sensitive fields that should not be assignable
        sensitive_fields = [
            'role', 'admin', 'isAdmin', 'is_admin',
            'permissions', 'privileges', 'accessLevel',
            'userId', 'user_id', 'ownerId', 'owner_id',
            'createdAt', 'created_at', 'updatedAt', 'updated_at',
            'deletedAt', 'deleted_at', 'version', 'id'
        ]
        
        mass_assignment_candidates = []
        
        for mutation in mutations:
            if not mutation or not isinstance(mutation, dict):
                continue
            
            mutation_name = mutation.get('name', '')
            args = mutation.get('args', [])
            
            # Look for mutations that take input objects
            input_args = []
            for arg in args:
                arg_type = self._extract_type_name(arg.get('type', {}))
                # Check if it's an Input type (usually ends with Input)
                if 'Input' in arg_type or arg_type not in ['String', 'Int', 'Float', 'Boolean', 'ID']:
                    input_args.append(arg)
            
            if input_args:
                # Get the input type definition to check for sensitive fields
                for input_arg in input_args:
                    input_type_name = self._extract_type_name(input_arg.get('type', {}))
                    # Get type from schema
                    input_type_def = None
                    types = self.client.get_types()
                    for type_def in types:
                        if type_def.get('name') == input_type_name:
                            input_type_def = type_def
                            break
                    
                    if input_type_def:
                        input_fields = input_type_def.get('inputFields', [])
                        field_names = [f.get('name', '') for f in input_fields]
                        
                        # Check if any sensitive fields are present
                        found_sensitive = [f for f in sensitive_fields if f in field_names or f.lower() in [n.lower() for n in field_names]]
                        
                        if found_sensitive:
                            mass_assignment_candidates.append({
                                'mutation': mutation_name,
                                'input_type': input_type_name,
                                'sensitive_fields': found_sensitive,
                                'all_fields': field_names
                            })
        
        if mass_assignment_candidates:
            sample_mutations = ', '.join([m['mutation'] for m in mass_assignment_candidates[:5]])
            
            findings.append(create_finding(
                title="Potential Mass Assignment Vulnerability",
                severity="INFO",
                description=f"Found {len(mass_assignment_candidates)} mutations with input types containing sensitive fields: {sample_mutations}. These may be vulnerable to mass assignment if the server accepts unexpected fields.",
                impact="Mass assignment allows attackers to set fields they shouldn't have access to by including them in mutation variables. For example, setting 'role: admin' in a user creation mutation could escalate privileges.",
                remediation="Implement strict input validation: 1) Use allowlists of fields that can be set, 2) Explicitly exclude sensitive fields from input types, 3) Use separate input types for different operations (create vs update), 4) Validate and sanitize all input fields server-side, 5) Never bind input directly to model objects without filtering.",
                cwe="CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes",
                scanner="mutation_fuzzer",
                classification={'kind': 'manual_review', 'family': 'authz'},
                confidence={'level': 'low', 'reasons': ['Sensitive-looking fields were present in input object definitions, but server-side binding behavior was not exercised']},
                manual_verification_required=True,
                evidence={
                    'mass_assignment_candidates': mass_assignment_candidates[:10],
                    'test_recommendation': 'Try adding unexpected sensitive fields to mutation variables and verify they are rejected'
                },
                poc=f"Test mutations by adding fields like 'role: \"admin\"' to input variables",
                url=self.client.url
            ))
        
        return findings
    
    def _test_privilege_escalation(self, mutations: List[Dict]) -> List[Dict]:
        """Test mutations for privilege escalation via mass assignment"""
        findings = []
        
        if not mutations:
            return findings
        
        # Look for user-related mutations
        user_mutations = []
        for mutation in mutations:
            if not mutation or not isinstance(mutation, dict):
                continue
            mutation_name = mutation.get('name', '').lower()
            if any(keyword in mutation_name for keyword in ['user', 'create', 'update', 'register', 'signup']):
                user_mutations.append(mutation)
        
        if user_mutations:
            # Test one user mutation for privilege escalation
            test_mutation = user_mutations[0]
            mutation_name = test_mutation.get('name')
            args = test_mutation.get('args', [])
            
            # Find input argument
            input_arg = None
            for arg in args:
                arg_type = self._extract_type_name(arg.get('type', {}))
                if 'Input' in arg_type:
                    input_arg = arg
                    break
            
            if input_arg:
                # Try to add sensitive fields
                sensitive_test_fields = {
                    'role': 'admin',
                    'isAdmin': True,
                    'permissions': ['all'],
                    'accessLevel': 999
                }
                
                findings.append(create_finding(
                    title="Privilege Escalation Testing Recommended",
                    severity="INFO",
                    description=f"Mutation {mutation_name} may be vulnerable to privilege escalation via mass assignment. Test by adding sensitive fields to input variables.",
                    impact="If mutations accept unexpected fields like 'role' or 'isAdmin', attackers could escalate privileges during user creation or profile updates.",
                    remediation="Explicitly validate and filter all input fields. Use separate input types for different privilege levels. Never allow clients to set sensitive fields directly.",
                    cwe="CWE-269: Improper Privilege Management",
                    scanner="mutation_fuzzer",
                    classification={'kind': 'manual_review', 'family': 'authz'},
                    confidence={'level': 'low', 'reasons': ['User-related mutation shape suggests manual privilege-escalation testing is warranted']},
                    manual_verification_required=True,
                    evidence={
                        'mutation': mutation_name,
                        'test_fields': sensitive_test_fields,
                        'manual_testing_required': True
                    },
                    poc=f"Test {mutation_name} by adding fields like 'role: \"admin\"' to variables",
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

