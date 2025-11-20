#!/usr/bin/env python3
"""
Circular Query Scanner - Tests circular reference handling
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from graphql_client import GraphQLClient
from reporter import Reporter
from utils import create_finding
from typing import List, Dict


class CircularQueryScanner:
    """Scanner for circular query vulnerabilities"""
    
    def __init__(self, client: GraphQLClient, reporter: Reporter, config: Dict):
        """
        Initialize circular query scanner
        
        Args:
            client: GraphQL client instance
            reporter: Reporter instance
            config: Scanner configuration
        """
        self.client = client
        self.reporter = reporter
        self.config = config
        self.depth_limit = config.get('depth_limit', 5)
    
    def scan(self) -> List[Dict]:
        """
        Run circular query scan
        
        Returns:
            List of findings
        """
        findings = []
        
        if not self.client.schema:
            self.reporter.print_info("Schema not available, skipping circular query tests")
            return findings
        
        # Find circular references in schema
        self.reporter.print_info("Analyzing schema for circular references...")
        circular_refs = self._find_circular_references()
        
        if circular_refs:
            self.reporter.print_info(f"Found {len(circular_refs)} potential circular references")
            findings.extend(self._test_circular_exploitation(circular_refs))
        else:
            self.reporter.print_info("No obvious circular references found")
        
        return findings
    
    def _find_circular_references(self) -> List[Dict]:
        """Find types that have circular references"""
        circular = []
        types = self.client.get_types()
        
        for type_def in types:
            if type_def.get('kind') != 'OBJECT':
                continue
            
            type_name = type_def.get('name', '')
            if type_name.startswith('__'):
                continue
            
            fields = type_def.get('fields', [])
            
            for field in fields:
                field_type = self._extract_type_name(field.get('type', {}))
                
                # Check for self-reference
                if field_type == type_name:
                    circular.append({
                        'type': type_name,
                        'field': field.get('name'),
                        'returns': field_type
                    })
                
                # Check for mutual references (A -> B -> A)
                # This is more complex and would require graph analysis
                # For now, just note the potential
        
        return circular
    
    def _test_circular_exploitation(self, circular_refs: List[Dict]) -> List[Dict]:
        """Test if circular references can be exploited"""
        findings = []
        
        # Take first circular reference and try to exploit it
        if not circular_refs:
            return findings
        
        ref = circular_refs[0]
        type_name = ref['type']
        field_name = ref['field']
        
        # Build a deeply nested query using the circular reference
        # Note: This might not work if we don't have the complete type info
        findings.append(create_finding(
            title="Circular Reference Detected",
            severity="INFO",
            description=f"The type '{type_name}' has a field '{field_name}' that returns the same type, creating a circular reference.",
            impact="Circular references can be exploited to create deeply nested queries if depth limiting is not properly implemented. This could lead to resource exhaustion.",
            remediation="Ensure query depth limiting is enforced. The limit should prevent exploitation of circular references regardless of the schema design.",
            evidence={
                'type': type_name,
                'field': field_name,
                'circular_refs_found': len(circular_refs)
            }
        ))
        
        # Try to build and execute a circular query if possible
        # This is complex without full type information, so we keep it simple
        
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

