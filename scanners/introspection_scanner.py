#!/usr/bin/env python3
"""
Introspection Scanner - Tests introspection availability and analyzes schema
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from graphql_client import GraphQLClient
from reporter import Reporter
from introspection import SchemaParser
from utils import create_finding
from typing import List, Dict


class IntrospectionScanner:
    """Scanner for introspection-related tests"""
    
    def __init__(self, client: GraphQLClient, reporter: Reporter, config: Dict):
        """
        Initialize introspection scanner
        
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
        Run introspection scan
        
        Returns:
            List of findings
        """
        findings = []
        
        # Test if introspection is enabled
        self.reporter.print_info("Testing introspection availability...")
        schema = self.client.introspect()
        
        if schema:
            self.reporter.print_warning("Introspection is ENABLED")
            
            # Add finding for introspection being enabled
            findings.append(create_finding(
                title="GraphQL Introspection Enabled",
                severity="MEDIUM",
                description="The GraphQL endpoint has introspection enabled, which allows attackers to discover the complete API schema including all queries, mutations, types, and fields.",
                impact="Attackers can map the entire API surface area, discover hidden or undocumented endpoints, and identify potential attack vectors. This significantly aids reconnaissance and can expose sensitive functionality.",
                remediation="Disable introspection in production environments. In most GraphQL implementations, this can be done through configuration settings. Keep introspection enabled only in development/testing environments.",
                cwe="CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
                evidence={
                    'introspection_response': 'Full schema retrieved successfully'
                }
            ))
            
            # Analyze the schema
            parser = SchemaParser(schema)
            
            # Check schema complexity
            complexity = parser.analyze_complexity()
            self.reporter.print_info(f"Schema contains {complexity['total_types']} types, "
                                    f"{complexity['total_queries']} queries, "
                                    f"{complexity['total_mutations']} mutations")
            
            # Look for sensitive field names
            sensitive_fields = parser.find_sensitive_field_names()
            if sensitive_fields:
                self.reporter.print_warning(f"Found {len(sensitive_fields)} fields with potentially sensitive names")
                
                # Sample some for the finding
                sample_fields = sensitive_fields[:5]
                field_list = ', '.join([f"{f['type']}.{f['field']}" for f in sample_fields])
                
                findings.append(create_finding(
                    title="Potentially Sensitive Fields Discovered",
                    severity="INFO",
                    description=f"Found {len(sensitive_fields)} fields with names suggesting they may contain sensitive data. Examples: {field_list}",
                    impact="These fields may contain sensitive information such as passwords, tokens, or private data. If accessible without proper authorization, this could lead to information disclosure.",
                    remediation="Review access controls for these fields. Ensure proper authentication and authorization checks are in place. Consider field-level permissions.",
                    evidence={
                        'sensitive_fields': sensitive_fields[:10]
                    }
                ))
            
            # Check for deprecated fields
            deprecated = parser.find_deprecated_fields()
            if deprecated:
                self.reporter.print_info(f"Found {len(deprecated)} deprecated fields")
                
                findings.append(create_finding(
                    title="Deprecated Fields Found",
                    severity="INFO",
                    description=f"The schema contains {len(deprecated)} deprecated fields. These may indicate legacy functionality or planned breaking changes.",
                    impact="Deprecated fields may have known vulnerabilities or may be removed in future versions. They could also indicate older, less secure code paths.",
                    remediation="Review deprecated fields and migrate away from them. Remove deprecated fields when no longer needed to reduce attack surface.",
                    evidence={
                        'deprecated_fields': deprecated[:10]
                    }
                ))
            
            # Check for fields with arguments (potential injection points)
            fields_with_args = parser.find_fields_with_args()
            if fields_with_args:
                self.reporter.print_info(f"Found {len(fields_with_args)} fields accepting arguments")
                
                findings.append(create_finding(
                    title="Fields With Arguments Identified",
                    severity="INFO",
                    description=f"Found {len(fields_with_args)} fields that accept arguments. These are potential injection points that should be tested.",
                    impact="Fields accepting arguments are common injection vectors for SQL injection, NoSQL injection, and other input-based attacks.",
                    remediation="Ensure all fields with arguments properly validate and sanitize input. Use parameterized queries and input validation.",
                    evidence={
                        'fields_count': len(fields_with_args),
                        'sample_fields': fields_with_args[:5]
                    }
                ))
            
            # Check if mutations exist
            if complexity['has_mutations']:
                mutation_count = complexity['total_mutations']
                self.reporter.print_info(f"Found {mutation_count} mutations")
                
                findings.append(create_finding(
                    title="Mutations Available",
                    severity="INFO",
                    description=f"The API exposes {mutation_count} mutations that can modify data.",
                    impact="Mutations can modify server-side state. If not properly protected, they could be exploited for unauthorized data modification.",
                    remediation="Ensure all mutations require proper authentication and authorization. Implement rate limiting on sensitive mutations.",
                    evidence={
                        'mutation_count': mutation_count
                    }
                ))
            
            # Check for subscriptions
            if complexity['has_subscriptions']:
                sub_count = complexity['total_subscriptions']
                self.reporter.print_info(f"Found {sub_count} subscriptions")
                
                findings.append(create_finding(
                    title="Subscriptions Available",
                    severity="INFO",
                    description=f"The API supports {sub_count} real-time subscriptions.",
                    impact="Subscriptions maintain persistent connections. If not properly secured, they could be exploited for DoS attacks or unauthorized data access.",
                    remediation="Implement connection limits and rate limiting for subscriptions. Ensure proper authentication for subscription endpoints.",
                    evidence={
                        'subscription_count': sub_count
                    }
                ))
            
        else:
            self.reporter.print_success("Introspection is DISABLED")
            
            findings.append(create_finding(
                title="Introspection Disabled",
                severity="INFO",
                description="GraphQL introspection is properly disabled, which is a security best practice for production environments.",
                impact="None - this is the recommended secure configuration.",
                remediation="No action needed. Keep introspection disabled in production.",
            ))
        
        return findings

