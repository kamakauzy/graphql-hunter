#!/usr/bin/env python3
"""
Information Disclosure Scanner - Tests for debug mode, stack traces, and verbose errors
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from graphql_client import GraphQLClient
from reporter import Reporter
from utils import create_finding, detect_stack_trace
from typing import List, Dict


class InfoDisclosureScanner:
    """Scanner for information disclosure vulnerabilities"""
    
    def __init__(self, client: GraphQLClient, reporter: Reporter, config: Dict):
        """
        Initialize info disclosure scanner
        
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
        Run information disclosure scan
        
        Returns:
            List of findings
        """
        findings = []
        
        # Test for stack traces on syntax errors
        self.reporter.print_info("Testing for stack trace disclosure...")
        findings.extend(self._test_stack_traces())
        
        # Test for suggestions/hints feature
        self.reporter.print_info("Testing for field suggestions...")
        findings.extend(self._test_field_suggestions())
        
        # Test for debug information
        self.reporter.print_info("Testing for debug information...")
        findings.extend(self._test_debug_mode())
        
        # Test error message verbosity
        self.reporter.print_info("Testing error message verbosity...")
        findings.extend(self._test_error_verbosity())
        
        return findings
    
    def _test_stack_traces(self) -> List[Dict]:
        """Test if server returns stack traces"""
        findings = []
        
        # Send malformed query
        malformed_queries = [
            '{ invalid syntax here }',
            '{ __typename } extra',
            'query { }',
        ]
        
        for query in malformed_queries:
            result = self.client.query(query)
            
            if result.get('errors'):
                for error in result['errors']:
                    error_msg = str(error)
                    
                    # Check for stack trace
                    if detect_stack_trace(error_msg):
                        findings.append(create_finding(
                            title="Stack Trace Disclosure",
                            severity="MEDIUM",
                            description="The GraphQL endpoint returns stack traces in error messages, exposing internal implementation details, file paths, and technology stack information.",
                            impact="Stack traces can reveal sensitive information about the application's technology stack, file structure, library versions, and internal logic. This information aids attackers in identifying potential vulnerabilities.",
                            remediation="Configure the GraphQL server to suppress stack traces in production. Return generic error messages to clients while logging detailed errors server-side.",
                            cwe="CWE-209: Generation of Error Message Containing Sensitive Information",
                            evidence={
                                'query': query,
                                'error': error_msg[:500]
                            },
                            poc=f"Query: {query}\nReturns stack trace with internal paths"
                        ))
                        return findings  # One finding is enough
        
        return findings
    
    def _test_field_suggestions(self) -> List[Dict]:
        """Test if server provides field suggestions"""
        findings = []
        
        # Query with intentional typo
        test_query = '{ __typename nonExistentFieldNameThatDoesNotExist123 }'
        result = self.client.query(test_query)
        
        if result.get('errors'):
            for error in result['errors']:
                error_msg = error.get('message', '')
                
                # Check if error contains suggestions like "Did you mean..."
                if 'did you mean' in error_msg.lower() or 'suggestion' in error_msg.lower():
                    findings.append(create_finding(
                        title="Field Suggestion Feature Enabled",
                        severity="LOW",
                        description="The GraphQL endpoint provides field suggestions in error messages (e.g., 'Did you mean...?'). While helpful for developers, this aids attackers in discovering valid field names.",
                        impact="Field suggestions help attackers enumerate valid fields through typos and similar queries, making reconnaissance easier.",
                        remediation="Disable field suggestions in production environments. This is often controlled by GraphQL server configuration.",
                        cwe="CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
                        evidence={
                            'query': test_query,
                            'error_message': error_msg
                        },
                url=self.client.url
            ))
                    break
        
        return findings
    
    def _test_debug_mode(self) -> List[Dict]:
        """Test for debug mode indicators"""
        findings = []
        
        # Try a simple query and check response headers
        result = self.client.query('{ __typename }')
        headers = result.get('_headers', {})
        
        # Check for debug headers
        debug_indicators = [
            'X-Debug', 'X-Debug-Token', 'X-Debug-Mode',
            'X-Apollo-Tracing', 'X-GraphQL-Tracing'
        ]
        
        found_debug_headers = []
        for header in debug_indicators:
            if header.lower() in [h.lower() for h in headers.keys()]:
                found_debug_headers.append(header)
        
        if found_debug_headers:
            findings.append(create_finding(
                title="Debug Headers Present",
                severity="LOW",
                description=f"The GraphQL endpoint returns debug-related headers: {', '.join(found_debug_headers)}. These may expose performance metrics or debugging information.",
                impact="Debug headers can reveal performance characteristics, query execution details, or other internal information useful to attackers.",
                remediation="Disable debug headers in production environments. Remove or configure middleware that adds tracing/debug information.",
                evidence={
                    'headers': found_debug_headers
                },
                url=self.client.url
            ))
        
        # Check for tracing in response
        if result.get('extensions', {}).get('tracing'):
            findings.append(create_finding(
                title="Apollo Tracing Enabled",
                severity="LOW",
                description="Apollo tracing is enabled, which exposes detailed query execution timing and resolver information in the response.",
                impact="Tracing data reveals internal query execution paths, timing information, and resolver details that could aid attackers in understanding the application architecture.",
                remediation="Disable Apollo tracing in production. Set `tracing: false` in Apollo Server configuration.",
                evidence={
                    'tracing_enabled': True
                },
                url=self.client.url
            ))
        
        return findings
    
    def _test_error_verbosity(self) -> List[Dict]:
        """Test error message verbosity"""
        findings = []
        
        # Try to trigger a type error
        test_query = '{ __schema { types { name(arg: "invalid") } } }'
        result = self.client.query(test_query)
        
        if result.get('errors'):
            for error in result['errors']:
                error_msg = error.get('message', '')
                
                # Check if error contains detailed validation information
                verbose_indicators = [
                    'Argument', 'Expected type', 'Cannot query field',
                    'at line', 'at column', 'ValidationError'
                ]
                
                verbose_count = sum(1 for indicator in verbose_indicators 
                                  if indicator.lower() in error_msg.lower())
                
                if verbose_count >= 2:
                    findings.append(create_finding(
                        title="Verbose Error Messages",
                        severity="LOW",
                        description="The GraphQL endpoint returns very detailed error messages including validation details, line numbers, and schema information.",
                        impact="Verbose error messages help attackers understand the schema structure and validation rules, aiding in crafting valid attacks.",
                        remediation="Configure the GraphQL server to return less detailed error messages in production while logging full details server-side.",
                        evidence={
                            'error_message': error_msg
                        },
                url=self.client.url
            ))
                    break
        
        return findings

