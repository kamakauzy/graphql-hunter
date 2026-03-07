#!/usr/bin/env python3
"""
XSS Scanner - Tests for Cross-Site Scripting vulnerabilities in GraphQL
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from graphql_client import GraphQLClient
from reporter import Reporter
from utils import create_finding, extract_type_name, is_validation_error, payload_reflected_in_data
from introspection import SchemaParser
from typing import List, Dict
import yaml


class XSSScanner:
    """Scanner for XSS vulnerabilities"""

    def __init__(self, client: GraphQLClient, reporter: Reporter, config: Dict):
        self.client = client
        self.reporter = reporter
        self.config = config
        self.xss_payloads = self._load_payloads()

    def _load_payloads(self):
        payload_file = Path(__file__).parent.parent / "config" / "payloads.yaml"
        try:
            with open(payload_file, 'r', encoding='utf-8') as handle:
                payloads = yaml.safe_load(handle) or {}
            return payloads.get('xss_payloads', [])
        except Exception:
            return ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]

    def scan(self) -> List[Dict]:
        findings = []

        if not self.client.schema:
            self.reporter.print_warning("Schema not available, skipping XSS tests")
            return findings

        self.reporter.print_info("Testing mutations for XSS vulnerabilities...")
        findings.extend(self._test_field_family('mutation', self.client.get_mutations()))

        self.reporter.print_info("Testing queries for XSS vulnerabilities...")
        findings.extend(self._test_field_family('query', self.client.get_queries()))

        return findings

    def _test_field_family(self, operation_kind: str, fields: List[Dict]) -> List[Dict]:
        findings = []
        parser = SchemaParser(self.client.schema)
        max_total_tests = self.config.get('max_xss_tests', 20)
        tests_run = 0

        for field in fields:
            if tests_run >= max_total_tests:
                break

            args = field.get('args', [])
            if not args:
                continue

            baseline = parser.build_operation(field, operation_kind=operation_kind)
            if not baseline.get('testable'):
                continue

            baseline_result = self.client.query(
                baseline['query'],
                variables=baseline.get('variables'),
                operation_name=baseline.get('operation_name'),
            )
            if is_validation_error(baseline_result):
                continue

            for arg in args[:3]:
                if tests_run >= max_total_tests:
                    break
                if extract_type_name(arg.get('type', {})) != 'String':
                    continue

                for payload in self.xss_payloads[:3]:
                    probe = parser.build_operation(field, operation_kind=operation_kind, overrides={arg.get('name'): payload})
                    if not probe.get('testable'):
                        continue

                    result = self.client.query(
                        probe['query'],
                        variables=probe.get('variables'),
                        operation_name=probe.get('operation_name'),
                    )
                    tests_run += 1

                    if payload_reflected_in_data(result, payload):
                        findings.append(create_finding(
                            title=f"Potential XSS Review Required in {operation_kind.title()}",
                            severity="MEDIUM",
                            description=f"An XSS payload was reflected in successful {operation_kind} response data while testing {field.get('name')}.{arg.get('name')}. Reflection alone does not prove browser execution, but it indicates that output encoding and sink handling should be reviewed carefully.",
                            impact="Unsafely rendered reflected or stored content can become a browser-exploitable XSS issue in downstream clients, dashboards, or admin consoles that display GraphQL responses.",
                            remediation="Ensure user-controlled content is contextually encoded at every browser/UI sink, sanitize rich-text inputs where appropriate, and validate that stored values cannot execute script in consuming applications.",
                            cwe="CWE-79: Cross-site Scripting (XSS)",
                            scanner="xss",
                            classification={'kind': 'manual_review', 'family': 'xss'},
                            confidence={'level': 'low', 'reasons': ['Payload reflection was observed in response data, but no browser sink or script execution was demonstrated']},
                            manual_verification_required=True,
                            evidence={
                                'operation_kind': operation_kind,
                                'field': field.get('name'),
                                'argument': arg.get('name'),
                                'payload': payload,
                                'reflected_in_data': True
                            },
                            request={
                                'query': probe['query'],
                                'variables': probe.get('variables'),
                                'operation_name': probe.get('operation_name')
                            },
                            poc=probe['query'],
                            url=self.client.url
                        ))
                        break

        return findings

