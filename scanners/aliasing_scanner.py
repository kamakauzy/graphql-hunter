#!/usr/bin/env python3
"""
Aliasing Scanner - Tests for field aliasing abuse
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from graphql_client import GraphQLClient
from reporter import Reporter
from utils import create_finding
from typing import List, Dict
import time


class AliasingScanner:
    """Scanner for aliasing abuse vulnerabilities"""
    
    def __init__(self, client: GraphQLClient, reporter: Reporter, config: Dict):
        """
        Initialize aliasing scanner
        
        Args:
            client: GraphQL client instance
            reporter: Reporter instance
            config: Scanner configuration
        """
        self.client = client
        self.reporter = reporter
        self.config = config
        self.field_limit = config.get('field_limit', 20)
    
    def scan(self) -> List[Dict]:
        """
        Run aliasing abuse scan
        
        Returns:
            List of findings
        """
        findings = []
        
        # Test field aliasing
        self.reporter.print_info("Testing field aliasing abuse...")
        findings.extend(self._test_field_aliasing())
        
        # Test query cost with aliasing
        self.reporter.print_info("Testing query cost with aliases...")
        findings.extend(self._test_alias_cost())
        
        return findings
    
    def _test_field_aliasing(self) -> List[Dict]:
        """Test field aliasing for resource exhaustion"""
        findings = []
        
        # Test with increasing numbers of aliases
        test_counts = [10, 50, 100, 200]
        
        for count in test_counts:
            if count > self.field_limit * 3:
                break
            
            # Build query with many aliases of the same field
            aliases = []
            for i in range(count):
                aliases.append(f'alias{i}: __typename')
            
            query = '{ ' + ' '.join(aliases) + ' }'
            
            start_time = time.time()
            result = self.client.query(query)
            elapsed = time.time() - start_time
            
            # Check if query succeeded
            if result.get('data'):
                if count >= 100 or elapsed > 3:
                    findings.append(create_finding(
                        title="Field Aliasing Abuse Possible",
                        severity="HIGH",
                        description=f"The server accepted a query with {count} field aliases and took {elapsed:.2f} seconds to process.",
                        impact="Field aliasing can be exploited to multiply the cost of a single query by requesting the same expensive field multiple times under different aliases. This can lead to severe resource exhaustion and DoS.",
                        remediation="Implement query cost analysis that counts aliased fields. Each alias should contribute to the query cost. Consider limiting the total number of fields (including aliases) in a single query.",
                        cwe="CWE-400: Uncontrolled Resource Consumption",
                        evidence={
                            'alias_count': count,
                            'response_time': elapsed
                        },
                        poc=f"Query with {count} aliases: " + query[:200] + "..."
                    ))
                    return findings  # Found the issue
            
            # Check for errors indicating aliasing limit
            if result.get('errors'):
                for error in result['errors']:
                    error_msg = error.get('message', '')
                    if 'alias' in error_msg.lower() or 'field' in error_msg.lower() and 'limit' in error_msg.lower():
                        findings.append(create_finding(
                            title="Field Aliasing Limit Enforced",
                            severity="INFO",
                            description=f"The server properly limits field aliasing. Query with {count} aliases was rejected.",
                            impact="None - this is a security best practice.",
                            remediation="No action needed. Keep field count limiting enabled.",
                            evidence={
                                'alias_limit': count
                            }
                        ))
                        return findings
        
        return findings
    
    def _test_alias_cost(self) -> List[Dict]:
        """Test if aliases increase query cost"""
        findings = []
        
        if not self.client.schema:
            return findings
        
        # Try to find a query that takes arguments
        queries = self.client.get_queries()
        
        if not queries:
            return findings
        
        # Pick first query
        query_def = queries[0]
        query_name = query_def.get('name')
        
        # Build a query with aliases calling the same query multiple times
        aliases = []
        for i in range(20):
            aliases.append(f'call{i}: {query_name}')
        
        # This is a simplified test - in reality, would need to provide valid args
        query = '{ ' + ' '.join(aliases) + ' }'
        
        start_time = time.time()
        result = self.client.query(query)
        elapsed = time.time() - start_time
        
        # If it takes a long time or succeeds, that's interesting
        if elapsed > 2 or result.get('data'):
            # This finding is less severe as it depends on the specific query
            findings.append(create_finding(
                title="Multiple Aliased Query Calls Accepted",
                severity="MEDIUM",
                description=f"The server allowed calling the same query '{query_name}' multiple times using aliases.",
                impact="If the aliased query is expensive (e.g., database query, external API call), this could be exploited for amplification attacks.",
                remediation="Implement query cost analysis that accounts for all aliased calls. Consider caching results for identical queries within a request.",
                evidence={
                    'query': query_name,
                    'alias_count': 20,
                    'response_time': elapsed
                }
            ))
        
        return findings

