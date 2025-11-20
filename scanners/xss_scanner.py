#!/usr/bin/env python3
"""
XSS Scanner - Tests for Cross-Site Scripting vulnerabilities in GraphQL
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from graphql_client import GraphQLClient
from reporter import Reporter
from utils import create_finding
from typing import List, Dict


class XSSScanner:
    """Scanner for XSS vulnerabilities"""
    
    def __init__(self, client: GraphQLClient, reporter: Reporter, config: Dict):
        """
        Initialize XSS scanner
        
        Args:
            client: GraphQL client instance
            reporter: Reporter instance
            config: Scanner configuration
        """
        self.client = client
        self.reporter = reporter
        self.config = config
        
        # XSS payloads
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
        ]
    
    def scan(self) -> List[Dict]:
        """
        Run XSS scan
        
        Returns:
            List of findings
        """
        findings = []
        
        if not self.client.schema:
            self.reporter.print_warning("Schema not available, skipping XSS tests")
            return findings
        
        # Test mutations for XSS
        self.reporter.print_info("Testing mutations for XSS vulnerabilities...")
        findings.extend(self._test_mutation_xss())
        
        return findings
    
    def _test_mutation_xss(self) -> List[Dict]:
        """Test mutations for XSS vulnerabilities"""
        findings = []
        
        mutations = self.client.get_mutations()
        
        if not mutations or len(mutations) == 0:
            return findings
        
        tested_count = 0
        max_tests = 3  # Limit testing
        
        for mutation_def in mutations:
            if tested_count >= max_tests:
                break
            
            if not mutation_def or not isinstance(mutation_def, dict):
                continue
            
            mutation_name = mutation_def.get('name')
            args = mutation_def.get('args', [])
            
            if not args:
                continue
            
            # Test string arguments with XSS payloads
            for arg in args[:2]:  # Test first 2 args
                arg_name = arg.get('name')
                arg_type = self._extract_type_name(arg.get('type', {}))
                
                if arg_type != 'String':
                    continue
                
                for payload in self.xss_payloads[:2]:  # Test first 2 payloads
                    # Escape the payload for GraphQL
                    escaped_payload = payload.replace('"', '\\"')
                    mutation_str = f'mutation {{ {mutation_name}({arg_name}: "{escaped_payload}") {{ __typename }} }}'
                    
                    result = self.client.query(mutation_str)
                    
                    # Check if payload is reflected in response
                    response_text = str(result)
                    
                    if payload in response_text and '<script>' in payload:
                        findings.append(create_finding(
                            title="Potential XSS Vulnerability in Mutation",
                            severity="HIGH",
                            description=f"XSS payload was reflected in response when testing {mutation_name}.{arg_name}. The application may not be properly sanitizing user input.",
                            impact="Cross-Site Scripting allows attackers to inject malicious scripts that execute in victims' browsers, potentially stealing credentials, session tokens, or performing actions on behalf of users.",
                            remediation="Sanitize and encode all user input before rendering. Use context-aware output encoding. Implement Content Security Policy (CSP) headers.",
                            cwe="CWE-79: Cross-site Scripting (XSS)",
                            evidence={
                                'mutation': mutation_name,
                                'argument': arg_name,
                                'payload': payload
                            },
                            poc=mutation_str
                        ))
                        return findings  # Stop after first finding
                
                tested_count += 1
        
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

