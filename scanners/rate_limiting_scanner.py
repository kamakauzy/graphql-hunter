#!/usr/bin/env python3
"""
Rate Limiting Scanner - Tests for rate limiting and DoS via request flooding
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from graphql_client import GraphQLClient
from reporter import Reporter
from utils import create_finding
from typing import List, Dict
import time
import concurrent.futures


class RateLimitingScanner:
    """Scanner for rate limiting vulnerabilities"""
    
    def __init__(self, client: GraphQLClient, reporter: Reporter, config: Dict):
        """
        Initialize rate limiting scanner
        
        Args:
            client: GraphQL client instance
            reporter: Reporter instance
            config: Scanner configuration
        """
        self.client = client
        self.reporter = reporter
        self.config = config
        self.concurrency = config.get('rate_limit_concurrency', 100)
        self.max_requests = config.get('rate_limit_requests', 100)
    
    def scan(self) -> List[Dict]:
        """
        Run rate limiting scan
        
        Returns:
            List of findings
        """
        findings = []
        
        # Skip if safe mode is enabled
        if self.config.get('safe_mode', False):
            self.reporter.print_info("Safe mode enabled, skipping rate limiting tests")
            return findings
        
        # Test concurrent requests
        self.reporter.print_info(f"Testing rate limiting with {self.concurrency} concurrent requests...")
        findings.extend(self._test_concurrent_requests())
        
        # Test rate limit headers
        self.reporter.print_info("Checking for rate limit headers...")
        findings.extend(self._test_rate_limit_headers())
        
        # Test mutation rate limits
        if self.client.schema:
            self.reporter.print_info("Testing mutation rate limits...")
            findings.extend(self._test_mutation_rate_limits())
        
        return findings
    
    def _test_concurrent_requests(self) -> List[Dict]:
        """Test concurrent request flooding"""
        findings = []
        
        # Simple query to test
        test_query = '{ __typename }'
        
        # Track responses
        responses = []
        start_time = time.time()
        
        def make_request():
            """Make a single request"""
            try:
                result = self.client.query(test_query, bypass_auth=False)
                return {
                    'status_code': result.get('_status_code', 0),
                    'has_errors': bool(result.get('errors')),
                    'response_time': time.time()
                }
            except Exception as e:
                return {
                    'status_code': 0,
                    'error': str(e),
                    'response_time': time.time()
                }
        
        # Execute concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = [executor.submit(make_request) for _ in range(self.max_requests)]
            for future in concurrent.futures.as_completed(futures):
                try:
                    responses.append(future.result())
                except Exception as e:
                    responses.append({'error': str(e)})
        
        elapsed_time = time.time() - start_time
        
        # Analyze responses
        status_codes = {}
        error_count = 0
        timeout_count = 0
        rate_limited = 0
        
        for response in responses:
            status = response.get('status_code', 0)
            status_codes[status] = status_codes.get(status, 0) + 1
            
            if status == 429:
                rate_limited += 1
            elif status == 0:
                error_count += 1
                if 'timeout' in str(response.get('error', '')).lower():
                    timeout_count += 1
        
        # Check for rate limiting
        if rate_limited > 0:
            findings.append(create_finding(
                title="Rate Limiting Detected",
                severity="INFO",
                description=f"Server returned 429 (Too Many Requests) for {rate_limited} out of {self.max_requests} concurrent requests, indicating rate limiting is implemented.",
                impact="Rate limiting helps protect against DoS attacks and abuse. This is a positive security control.",
                remediation="Ensure rate limiting is properly configured with appropriate thresholds and reset windows.",
                cwe="CWE-307: Improper Restriction of Excessive Authentication Attempts",
                evidence={
                    'total_requests': self.max_requests,
                    'rate_limited_requests': rate_limited,
                    'concurrency': self.concurrency,
                    'elapsed_time': elapsed_time,
                    'status_codes': status_codes
                },
                poc=test_query,
                url=self.client.url
            ))
        elif error_count > self.max_requests * 0.5:
            # More than 50% errors suggests rate limiting or DoS protection
            findings.append(create_finding(
                title="Possible Rate Limiting or DoS Protection",
                severity="INFO",
                description=f"Server returned errors for {error_count} out of {self.max_requests} concurrent requests, suggesting rate limiting or DoS protection may be active.",
                impact="High error rate under load may indicate rate limiting, which is a positive security control.",
                remediation="Verify rate limiting configuration and ensure it's properly tuned for legitimate use cases.",
                cwe="CWE-307: Improper Restriction of Excessive Authentication Attempts",
                evidence={
                    'total_requests': self.max_requests,
                    'error_count': error_count,
                    'timeout_count': timeout_count,
                    'concurrency': self.concurrency,
                    'elapsed_time': elapsed_time
                },
                poc=test_query,
                url=self.client.url
            ))
        else:
            # No rate limiting detected
            findings.append(create_finding(
                title="No Rate Limiting Detected",
                severity="MEDIUM",
                description=f"Server processed {self.max_requests} concurrent requests without rate limiting (no 429 responses). This may indicate missing rate limiting protection.",
                impact="Without rate limiting, attackers can flood the API with requests, potentially causing DoS or enabling brute-force attacks.",
                remediation="Implement rate limiting at the API gateway or application level. Consider per-IP, per-user, and per-endpoint rate limits. Recommended: 100-1000 requests per minute per IP.",
                cwe="CWE-307: Improper Restriction of Excessive Authentication Attempts",
                evidence={
                    'total_requests': self.max_requests,
                    'successful_requests': self.max_requests - error_count,
                    'concurrency': self.concurrency,
                    'elapsed_time': elapsed_time,
                    'status_codes': status_codes
                },
                poc=test_query,
                url=self.client.url
            ))
        
        return findings
    
    def _test_rate_limit_headers(self) -> List[Dict]:
        """Check for rate limit headers in responses"""
        findings = []
        
        # Make a few requests to check headers
        test_query = '{ __typename }'
        
        # We need to check response headers, but our client doesn't expose them easily
        # This is a placeholder - would need to enhance GraphQLClient to return headers
        # For now, we'll note this limitation
        
        return findings
    
    def _test_mutation_rate_limits(self) -> List[Dict]:
        """Test mutation-specific rate limits"""
        findings = []
        
        mutations = self.client.get_mutations()
        if not mutations:
            return findings
        
        # Find a simple mutation to test
        test_mutation = None
        for mutation in mutations[:5]:  # Check first 5 mutations
            mutation_name = mutation.get('name', '')
            args = mutation.get('args', [])
            
            # Prefer mutations with minimal required args
            if len(args) <= 2:
                test_mutation = mutation
                break
        
        if not test_mutation:
            return findings
        
        mutation_name = test_mutation.get('name')
        args = test_mutation.get('args', [])
        
        # Build mutation with minimal variables
        variables = {}
        for arg in args[:2]:
            arg_name = arg.get('name')
            arg_type = self._extract_type_name(arg.get('type', {}))
            
            if arg_type == 'String' or arg_type == 'ID':
                variables[arg_name] = "test"
            elif arg_type == 'Int':
                variables[arg_name] = 1
            elif arg_type == 'Boolean':
                variables[arg_name] = True
        
        mutation_query = f'mutation {{ {mutation_name}'
        if variables:
            var_decl = ', '.join([f'${k}: {self._get_type_string(args, k)}' for k in variables.keys()])
            arg_call = ', '.join([f'{k}: ${k}' for k in variables.keys()])
            mutation_query = f'mutation TestMutation({var_decl}) {{ {mutation_name}({arg_call}) {{ __typename }} }}'
        else:
            mutation_query = f'mutation {{ {mutation_name} {{ __typename }} }}'
        
        # Test with fewer requests for mutations (more aggressive)
        mutation_requests = min(50, self.max_requests // 2)
        rate_limited = 0
        
        for i in range(mutation_requests):
            result = self.client.query(mutation_query, variables=variables if variables else None)
            if result.get('_status_code') == 429:
                rate_limited += 1
                break  # Stop after first rate limit
        
        if rate_limited > 0:
            findings.append(create_finding(
                title="Mutation Rate Limiting Detected",
                severity="INFO",
                description=f"Mutation {mutation_name} is rate limited, which is a positive security control.",
                impact="Rate limiting on mutations helps prevent abuse and DoS attacks.",
                remediation="Ensure mutation rate limits are appropriately configured.",
                evidence={
                    'mutation': mutation_name,
                    'rate_limited': True
                },
                poc=mutation_query,
                url=self.client.url
            ))
        else:
            findings.append(create_finding(
                title="Mutation Rate Limiting Not Detected",
                severity="LOW",
                description=f"Mutation {mutation_name} did not return rate limiting responses. Mutations should have stricter rate limits than queries.",
                impact="Mutations can modify data and should be protected with rate limiting to prevent abuse.",
                remediation="Implement rate limiting specifically for mutations. Consider lower limits than queries (e.g., 10-50 requests per minute).",
                evidence={
                    'mutation': mutation_name,
                    'test_requests': mutation_requests
                },
                poc=mutation_query,
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
    
    def _get_type_string(self, args: List[Dict], arg_name: str) -> str:
        """Get GraphQL type string for argument"""
        for arg in args:
            if arg.get('name') == arg_name:
                arg_type = arg.get('type', {})
                return self._extract_type_name(arg_type)
        return "String"
