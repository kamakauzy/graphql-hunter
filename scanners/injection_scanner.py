#!/usr/bin/env python3
"""
Injection Scanner - Tests for SQL, NoSQL, and Command injection vulnerabilities
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from graphql_client import GraphQLClient
from reporter import Reporter
from utils import create_finding, detect_sql_error, detect_nosql_error
from typing import List, Dict


class InjectionScanner:
    """Scanner for injection vulnerabilities"""
    
    def __init__(self, client: GraphQLClient, reporter: Reporter, config: Dict):
        """
        Initialize injection scanner
        
        Args:
            client: GraphQL client instance
            reporter: Reporter instance
            config: Scanner configuration
        """
        self.client = client
        self.reporter = reporter
        self.config = config
        
        # SQL injection payloads
        self.sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
            "admin'--",
            "' OR 'a'='a",
            "1; DROP TABLE users--",
            "' WAITFOR DELAY '0:0:5'--",
        ]
        
        # NoSQL injection payloads
        self.nosql_payloads = [
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$regex": ".*"}',
            '{$where: "1==1"}',
        ]
        
        # Command injection payloads
        self.command_payloads = [
            "; ls -la",
            "| whoami",
            "`id`",
            "$(whoami)",
            "&& dir",
            "; cat /etc/passwd",
        ]
    
    def scan(self) -> List[Dict]:
        """
        Run injection scan
        
        Returns:
            List of findings
        """
        findings = []
        
        if not self.client.schema:
            self.reporter.print_warning("Introspection not available, limited injection testing")
            # Still try some basic tests
            findings.extend(self._test_basic_injection())
            return findings
        
        # Get fields with arguments
        self.reporter.print_info("Testing SQL injection on fields with arguments...")
        findings.extend(self._test_sql_injection())
        
        if self.config.get('enable_deep_injection', True):
            self.reporter.print_info("Testing NoSQL injection...")
            findings.extend(self._test_nosql_injection())
            
            self.reporter.print_info("Testing command injection...")
            findings.extend(self._test_command_injection())
        
        return findings
    
    def _test_basic_injection(self) -> List[Dict]:
        """Test basic injection when schema is not available"""
        findings = []
        
        # Try a simple SQL injection in __typename (unlikely but worth trying)
        payload = "' OR '1'='1"
        query = f'{{ __typename(arg: "{payload}") }}'
        result = self.client.query(query)
        
        if result.get('errors'):
            error_text = str(result['errors'])
            if detect_sql_error(error_text):
                findings.append(create_finding(
                    title="Possible SQL Injection Vulnerability",
                    severity="CRITICAL",
                    description="The application returned SQL error messages when testing with injection payloads, indicating potential SQL injection vulnerability.",
                    impact="SQL injection can allow attackers to read, modify, or delete database contents, bypass authentication, and potentially execute commands on the database server.",
                    remediation="Use parameterized queries or prepared statements. Validate and sanitize all user input. Implement proper input encoding.",
                    cwe="CWE-89: SQL Injection",
                    evidence={
                        'payload': payload,
                        'error': error_text[:500]
                    },
                url=self.client.url
            ))
        
        return findings
    
    def _test_sql_injection(self) -> List[Dict]:
        """Test SQL injection on fields with arguments"""
        findings = []
        
        queries = self.client.get_queries()
        
        # Test first few queries with arguments
        tested_count = 0
        max_tests = 5  # Limit testing to avoid overwhelming the API
        
        for query_def in queries:
            if tested_count >= max_tests:
                break
            
            query_name = query_def.get('name')
            args = query_def.get('args', [])
            
            if not args:
                continue
            
            # Test each argument with SQL injection payloads
            for arg in args[:2]:  # Test first 2 args per query
                arg_name = arg.get('name')
                arg_type = arg.get('type', {})
                
                # Only test String arguments
                type_name = self._extract_type_name(arg_type)
                if type_name != 'String' and type_name != 'ID':
                    continue
                
                for payload in self.sql_payloads[:3]:  # Test first 3 payloads
                    query_str = f'query {{ {query_name}({arg_name}: "{payload}") {{ __typename }} }}'
                    result = self.client.query(query_str)
                    
                    if result.get('errors'):
                        error_text = str(result['errors'])
                        
                        if detect_sql_error(error_text):
                            findings.append(create_finding(
                                title="SQL Injection Vulnerability Detected",
                                severity="CRITICAL",
                                description=f"SQL error messages detected when testing {query_name}.{arg_name} with injection payload, indicating a SQL injection vulnerability.",
                                impact="SQL injection allows attackers to manipulate database queries, potentially leading to unauthorized data access, data modification, authentication bypass, or remote code execution.",
                                remediation="Use parameterized queries or ORM methods that prevent SQL injection. Never concatenate user input directly into SQL queries. Implement input validation.",
                                cwe="CWE-89: SQL Injection",
                                evidence={
                                    'query': query_name,
                                    'argument': arg_name,
                                    'payload': payload,
                                    'error': error_text[:500]
                                },
                                poc=query_str
                            ))
                            tested_count += 1
                            return findings  # Stop after first finding
                
                tested_count += 1
        
        return findings
    
    def _test_nosql_injection(self) -> List[Dict]:
        """Test NoSQL injection on fields with arguments"""
        findings = []
        
        queries = self.client.get_queries()
        
        tested_count = 0
        max_tests = 3
        
        for query_def in queries:
            if tested_count >= max_tests:
                break
            
            query_name = query_def.get('name')
            args = query_def.get('args', [])
            
            if not args:
                continue
            
            for arg in args[:1]:  # Test first arg only
                arg_name = arg.get('name')
                
                for payload in self.nosql_payloads[:2]:
                    # Try as string (JSON encoded)
                    query_str = f'query {{ {query_name}({arg_name}: "{payload}") {{ __typename }} }}'
                    result = self.client.query(query_str)
                    
                    if result.get('errors'):
                        error_text = str(result['errors'])
                        
                        if detect_nosql_error(error_text):
                            findings.append(create_finding(
                                title="Possible NoSQL Injection Vulnerability",
                                severity="HIGH",
                                description=f"NoSQL error messages detected when testing {query_name}.{arg_name}, suggesting potential NoSQL injection vulnerability.",
                                impact="NoSQL injection can allow attackers to bypass authentication, access unauthorized data, or perform unauthorized operations on the database.",
                                remediation="Sanitize and validate all user input. Use the database driver's built-in methods for constructing queries. Avoid using eval() or similar functions with user input.",
                                cwe="CWE-943: Improper Neutralization of Special Elements in Data Query Logic",
                                evidence={
                                    'query': query_name,
                                    'argument': arg_name,
                                    'payload': payload,
                                    'error': error_text[:500]
                                },
                url=self.client.url
            ))
                            return findings
                
                tested_count += 1
        
        return findings
    
    def _test_command_injection(self) -> List[Dict]:
        """Test command injection on fields with arguments"""
        findings = []
        
        queries = self.client.get_queries()
        
        tested_count = 0
        max_tests = 3
        
        for query_def in queries:
            if tested_count >= max_tests:
                break
            
            query_name = query_def.get('name')
            args = query_def.get('args', [])
            
            if not args:
                continue
            
            for arg in args[:1]:
                arg_name = arg.get('name')
                arg_type = arg.get('type', {})
                
                type_name = self._extract_type_name(arg_type)
                if type_name != 'String':
                    continue
                
                for payload in self.command_payloads[:2]:
                    query_str = f'query {{ {query_name}({arg_name}: "{payload}") {{ __typename }} }}'
                    result = self.client.query(query_str)
                    
                    # Look for command execution indicators in errors
                    if result.get('errors'):
                        error_text = str(result['errors'])
                        
                        # Check for shell-related errors
                        cmd_indicators = [
                            'sh:', 'bash:', 'command not found',
                            'Permission denied', '/bin/',
                            'cannot execute', 'ProcessException'
                        ]
                        
                        if any(indicator in error_text for indicator in cmd_indicators):
                            findings.append(create_finding(
                                title="Possible Command Injection Vulnerability",
                                severity="CRITICAL",
                                description=f"Command execution indicators detected when testing {query_name}.{arg_name}, suggesting potential command injection.",
                                impact="Command injection allows attackers to execute arbitrary operating system commands, potentially leading to full system compromise.",
                                remediation="Never pass user input directly to shell commands. Use safe APIs that don't invoke a shell. If shell execution is necessary, use strict allowlists and input validation.",
                                cwe="CWE-78: OS Command Injection",
                                evidence={
                                    'query': query_name,
                                    'argument': arg_name,
                                    'payload': payload,
                                    'error': error_text[:500]
                                },
                url=self.client.url
            ))
                            return findings
                
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

