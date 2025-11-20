#!/usr/bin/env python3
"""
Batching Scanner - Tests for batch query attacks
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from graphql_client import GraphQLClient
from reporter import Reporter
from utils import create_finding
from typing import List, Dict


class BatchingScanner:
    """Scanner for batching attack vulnerabilities"""
    
    def __init__(self, client: GraphQLClient, reporter: Reporter, config: Dict):
        """
        Initialize batching scanner
        
        Args:
            client: GraphQL client instance
            reporter: Reporter instance
            config: Scanner configuration
        """
        self.client = client
        self.reporter = reporter
        self.config = config
        self.batch_size = config.get('batch_size', 10)
    
    def scan(self) -> List[Dict]:
        """
        Run batching attack scan
        
        Returns:
            List of findings
        """
        findings = []
        
        # Test if batching is allowed
        self.reporter.print_info("Testing query batching support...")
        findings.extend(self._test_batching_allowed())
        
        # Test batch limits
        if self.config.get('enable_deep_injection', True):
            self.reporter.print_info("Testing batch size limits...")
            findings.extend(self._test_batch_limits())
        
        return findings
    
    def _test_batching_allowed(self) -> List[Dict]:
        """Test if query batching is allowed"""
        findings = []
        
        # Try to send multiple queries in a batch
        batch = [
            {'query': '{ __typename }'},
            {'query': '{ __schema { queryType { name } } }'},
            {'query': '{ __type(name: "Query") { name } }'}
        ]
        
        results = self.client.batch_query(batch)
        
        # Check if all queries were executed
        if len(results) >= len(batch):
            successful = sum(1 for r in results if r.get('data') and not r.get('errors'))
            
            if successful > 1:
                findings.append(create_finding(
                    title="Query Batching Enabled",
                    severity="MEDIUM",
                    description=f"The GraphQL endpoint allows query batching. Successfully executed {successful} queries in a single request.",
                    impact="Query batching can be exploited for various attacks including: rate limit bypass, credential stuffing, resource exhaustion, and amplification attacks where one HTTP request triggers multiple expensive operations.",
                    remediation="Consider disabling query batching or implementing strict limits. If batching is required, implement: per-batch rate limiting, maximum batch size limits, and complexity analysis that considers the entire batch.",
                    cwe="CWE-400: Uncontrolled Resource Consumption",
                    evidence={
                        'batch_size_tested': len(batch),
                        'successful_queries': successful
                    },
                    poc="Send array of queries: [{'query': '...'}, {'query': '...'}] to endpoint"
                ))
        
        return findings
    
    def _test_batch_limits(self) -> List[Dict]:
        """Test batch size limits"""
        findings = []
        
        # Try progressively larger batches
        test_sizes = [10, 25, 50, 100]
        
        for size in test_sizes:
            if size > self.batch_size * 2:  # Don't go too crazy
                break
            
            # Build a large batch
            batch = [{'query': f'{{ a{i}: __typename }}'} for i in range(size)]
            
            results = self.client.batch_query(batch)
            
            # Check if the batch was accepted
            if isinstance(results, list) and len(results) >= size:
                successful = sum(1 for r in results if r.get('data'))
                
                if successful >= size * 0.8:  # If 80%+ succeeded
                    if size >= 50:
                        findings.append(create_finding(
                            title="Large Batch Queries Accepted",
                            severity="HIGH",
                            description=f"The server accepted and processed a batch of {size} queries without error.",
                            impact="Large batch sizes can be exploited for severe resource exhaustion attacks. An attacker could send batches of expensive queries to overwhelm the server.",
                            remediation="Implement strict batch size limits (recommended: 5-10 queries maximum). Configure your GraphQL server to reject batches above this threshold.",
                            cwe="CWE-400: Uncontrolled Resource Consumption",
                            evidence={
                                'batch_size': size,
                                'successful_queries': successful
                            }
                        ))
                        return findings  # Found the issue, stop testing
            else:
                # Batch was rejected or limited
                findings.append(create_finding(
                    title="Batch Size Limit Enforced",
                    severity="INFO",
                    description=f"The server properly limits batch sizes. Batch of {size} was rejected or limited.",
                    impact="None - this is a security best practice.",
                    remediation="No action needed. Keep batch limiting enabled.",
                    evidence={
                        'batch_size_limit': size
                    }
                ))
                return findings  # Found the limit
        
        return findings

