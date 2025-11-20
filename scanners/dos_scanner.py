#!/usr/bin/env python3
"""
DoS Scanner - Tests for Denial of Service vulnerabilities
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from graphql_client import GraphQLClient
from reporter import Reporter
from utils import create_finding
from typing import List, Dict
import time


class DoSScanner:
    """Scanner for DoS vulnerabilities"""
    
    def __init__(self, client: GraphQLClient, reporter: Reporter, config: Dict):
        """
        Initialize DoS scanner
        
        Args:
            client: GraphQL client instance
            reporter: Reporter instance
            config: Scanner configuration
        """
        self.client = client
        self.reporter = reporter
        self.config = config
        self.depth_limit = config.get('depth_limit', 5)
        self.field_limit = config.get('field_limit', 20)
    
    def scan(self) -> List[Dict]:
        """
        Run DoS scan
        
        Returns:
            List of findings
        """
        findings = []
        
        # Test deeply nested queries
        self.reporter.print_info("Testing deeply nested queries...")
        findings.extend(self._test_deep_nesting())
        
        # Test field duplication
        self.reporter.print_info("Testing field duplication...")
        findings.extend(self._test_field_duplication())
        
        # Test circular references (if schema available)
        if self.client.schema:
            self.reporter.print_info("Testing circular query handling...")
            findings.extend(self._test_circular_queries())
        
        # Test query complexity
        self.reporter.print_info("Testing query complexity limits...")
        findings.extend(self._test_complexity_limits())
        
        return findings
    
    def _test_deep_nesting(self) -> List[Dict]:
        """Test deeply nested queries"""
        findings = []
        
        # Build progressively deeper nested queries
        max_depth = min(self.depth_limit + 5, 15)  # Don't go crazy
        
        for depth in range(5, max_depth + 1):
            # Build nested query
            query = self._build_nested_query(depth)
            
            start_time = time.time()
            result = self.client.query(query)
            elapsed = time.time() - start_time
            
            # Check for timeout or error
            if result.get('_timeout'):
                findings.append(create_finding(
                    title="Deep Query Nesting Causes Timeout",
                    severity="HIGH",
                    description=f"A query with nesting depth of {depth} caused a timeout, indicating the server may be vulnerable to DoS via deeply nested queries.",
                    impact="Attackers can craft deeply nested queries to consume excessive server resources, potentially causing service degradation or denial of service.",
                    remediation="Implement query depth limiting. Most GraphQL servers support a maximum query depth configuration. Recommended limit: 5-7 levels.",
                    cwe="CWE-400: Uncontrolled Resource Consumption",
                    evidence={
                        'depth': depth,
                        'timeout': True
                    },
                    poc=query[:300] + "..."
                ))
                return findings  # Stop testing deeper queries
            
            # Check for errors indicating depth limit
            if result.get('errors'):
                for error in result['errors']:
                    error_msg = error.get('message', '')
                    if 'depth' in error_msg.lower() or 'nested' in error_msg.lower():
                        findings.append(create_finding(
                            title="Query Depth Limit Enforced",
                            severity="INFO",
                            description=f"The server properly rejects queries exceeding depth {depth}, indicating depth limiting is implemented.",
                            impact="None - this is the recommended secure configuration.",
                            remediation="No action needed. Keep depth limiting enabled.",
                            evidence={
                                'depth_limit': depth
                            },
                url=self.client.url
            ))
                        return findings  # Found the limit, stop testing
            
            # If query succeeded with high depth, that's a problem
            if result.get('data') and depth >= 10:
                findings.append(create_finding(
                    title="No Query Depth Limit Detected",
                    severity="HIGH",
                    description=f"The server accepted a query with nesting depth of {depth} without error, suggesting no depth limiting is in place.",
                    impact="Without depth limiting, attackers can craft arbitrarily deep queries to consume excessive server resources and cause DoS.",
                    remediation="Implement query depth limiting. Configure your GraphQL server to reject queries deeper than 5-7 levels.",
                    cwe="CWE-400: Uncontrolled Resource Consumption",
                    evidence={
                        'depth_tested': depth,
                        'accepted': True
                    },
                url=self.client.url
            ))
                return findings  # One finding is enough
        
        return findings
    
    def _test_field_duplication(self) -> List[Dict]:
        """Test field duplication (aliasing abuse preview)"""
        findings = []
        
        # Build query with many duplicated fields using aliases
        field_count = min(self.field_limit + 10, 50)
        
        aliases = []
        for i in range(field_count):
            aliases.append(f'field{i}: __typename')
        
        query = '{ ' + ' '.join(aliases) + ' }'
        
        start_time = time.time()
        result = self.client.query(query)
        elapsed = time.time() - start_time
        
        # Check if query succeeded
        if result.get('data') and elapsed > 2:
            findings.append(create_finding(
                title="Large Query With Field Duplication Accepted",
                severity="MEDIUM",
                description=f"The server accepted a query with {field_count} aliased fields and took {elapsed:.2f} seconds to process.",
                impact="Attackers can use field aliasing to multiply the work the server must do, causing resource exhaustion and potential DoS.",
                remediation="Implement query complexity analysis that counts aliased fields. Limit the total number of fields that can be queried.",
                cwe="CWE-400: Uncontrolled Resource Consumption",
                evidence={
                    'field_count': field_count,
                    'elapsed_time': elapsed
                },
                url=self.client.url
            ))
        
        return findings
    
    def _test_circular_queries(self) -> List[Dict]:
        """Test circular/recursive queries"""
        findings = []
        
        # Look for types that might have circular references
        types = self.client.get_types()
        
        for type_def in types[:10]:  # Check first 10 types
            if type_def.get('kind') != 'OBJECT':
                continue
            
            type_name = type_def.get('name', '')
            if type_name.startswith('__'):
                continue
            
            fields = type_def.get('fields', [])
            
            # Check if any field returns the same type (self-reference)
            for field in fields:
                field_type = self._extract_type_name(field.get('type', {}))
                
                if field_type == type_name:
                    # Found a circular reference - this is INFO level as it's not always bad
                    findings.append(create_finding(
                        title="Circular Type Reference Detected",
                        severity="INFO",
                        description=f"The type '{type_name}' has a field '{field.get('name')}' that returns the same type, creating a potential circular reference.",
                        impact="Circular references can be exploited to create deeply nested queries that consume excessive resources if not properly limited.",
                        remediation="Ensure query depth limiting is in place to prevent exploitation of circular references. This is a common pattern but must be protected.",
                        evidence={
                            'type': type_name,
                            'field': field.get('name')
                        },
                url=self.client.url
            ))
                    break  # One finding per type is enough
            
            if len(findings) >= 3:  # Limit findings for circular refs
                break
        
        return findings
    
    def _test_complexity_limits(self) -> List[Dict]:
        """Test if query complexity limits are enforced"""
        findings = []
        
        # Build a complex query (combination of depth and field count)
        complex_query = self._build_complex_query()
        
        result = self.client.query(complex_query)
        
        if result.get('errors'):
            for error in result['errors']:
                error_msg = error.get('message', '')
                if 'complexity' in error_msg.lower():
                    findings.append(create_finding(
                        title="Query Complexity Limit Enforced",
                        severity="INFO",
                        description="The server enforces query complexity limits, rejecting overly complex queries.",
                        impact="None - this is a security best practice that prevents DoS attacks.",
                        remediation="No action needed. Keep complexity limiting enabled.",
                        evidence={
                            'complexity_check': 'enabled'
                        },
                url=self.client.url
            ))
                    return findings
        
        # If complex query succeeded, complexity limiting may not be in place
        if result.get('data'):
            findings.append(create_finding(
                title="No Query Complexity Limit Detected",
                severity="MEDIUM",
                description="The server accepted a highly complex query without error, suggesting complexity analysis may not be implemented.",
                impact="Without complexity limits, attackers can craft expensive queries that consume excessive server resources.",
                remediation="Implement query complexity analysis. Tools like graphql-query-complexity can help. Set appropriate complexity thresholds.",
                cwe="CWE-400: Uncontrolled Resource Consumption",
                evidence={
                    'complex_query_accepted': True
                },
                url=self.client.url
            ))
        
        return findings
    
    def _build_nested_query(self, depth: int) -> str:
        """Build a nested query of specified depth"""
        # Use __schema introspection for nesting
        query = '__schema { '
        for i in range(depth - 1):
            query += 'types { name fields { name type { '
        
        query += 'name'
        
        for i in range(depth - 1):
            query += ' } } }'
        
        query += ' }'
        
        return '{ ' + query + ' }'
    
    def _build_complex_query(self) -> str:
        """Build a complex query with both depth and field duplication"""
        # Combine nesting with field duplication
        query = '''
        {
          a1: __schema { types { name } }
          a2: __schema { types { name } }
          a3: __schema { types { name fields { name } } }
          a4: __schema { types { name fields { name } } }
          a5: __schema { types { name fields { name } } }
        }
        '''
        return query
    
    def _extract_type_name(self, type_def: Dict) -> str:
        """Extract type name from type definition"""
        if not type_def:
            return "Unknown"
        
        if type_def.get('name'):
            return type_def['name']
        
        if type_def.get('ofType'):
            return self._extract_type_name(type_def['ofType'])
        
        return "Unknown"

