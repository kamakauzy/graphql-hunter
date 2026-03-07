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
from introspection import SchemaParser
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
                scanner="rate_limiting",
                classification={'kind': 'control', 'family': 'dos'},
                confidence={'level': 'confirmed', 'reasons': ['Burst test produced HTTP 429 responses']},
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
                scanner="rate_limiting",
                classification={'kind': 'control', 'family': 'dos'},
                confidence={'level': 'low', 'reasons': ['High error rate under load may indicate a control, but no explicit rate-limit signal was observed']},
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
                scanner="rate_limiting",
                classification={'kind': 'hardening_gap', 'family': 'dos'},
                confidence={'level': 'medium', 'reasons': ['Burst test completed without 429 responses or strong throttling signals']},
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

        result = self.client.query('{ __typename }')
        headers = {str(key).lower(): value for key, value in (result.get('_headers') or {}).items()}
        rate_headers = {
            key: value for key, value in headers.items()
            if key.startswith('x-ratelimit') or key in {'ratelimit-limit', 'ratelimit-remaining', 'retry-after'}
        }

        if rate_headers:
            findings.append(create_finding(
                title="Rate Limit Headers Present",
                severity="INFO",
                description="The endpoint exposes rate-limiting headers in responses, indicating explicit throttling metadata is available.",
                impact="Visible rate-limit headers help clients back off appropriately and confirm that rate-limiting controls are in place.",
                remediation="No action needed. Ensure the headers reflect the true enforcement policy and do not leak sensitive implementation detail.",
                scanner="rate_limiting",
                classification={'kind': 'control', 'family': 'dos'},
                confidence={'level': 'confirmed', 'reasons': ['Response headers contained explicit rate-limit metadata']},
                evidence={'rate_limit_headers': rate_headers},
                url=self.client.url
            ))

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
        
        parser = SchemaParser(self.client.schema)
        built = parser.build_operation(test_mutation, operation_kind='mutation')
        if not built.get('testable'):
            return findings

        mutation_name = test_mutation.get('name')
        mutation_query = built['query']
        variables = built.get('variables')
        
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
                scanner="rate_limiting",
                classification={'kind': 'control', 'family': 'dos'},
                confidence={'level': 'confirmed', 'reasons': ['Mutation burst triggered HTTP 429 response']},
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
                scanner="rate_limiting",
                classification={'kind': 'hardening_gap', 'family': 'dos'},
                confidence={'level': 'low', 'reasons': ['Mutation burst did not trigger explicit throttling, but behavior can depend on server-side business logic']},
                manual_verification_required=True,
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
