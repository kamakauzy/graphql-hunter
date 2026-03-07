#!/usr/bin/env python3
"""
Injection Scanner - Tests for SQL, NoSQL, and Command injection vulnerabilities
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from graphql_client import GraphQLClient
from reporter import Reporter
from utils import create_finding, detect_sql_error, detect_nosql_error, extract_error_messages, extract_type_name, is_validation_error
from introspection import SchemaParser
from typing import List, Dict
import yaml


class InjectionScanner:
    """Scanner for injection vulnerabilities"""

    def __init__(self, client: GraphQLClient, reporter: Reporter, config: Dict):
        self.client = client
        self.reporter = reporter
        self.config = config
        self.sql_payloads, self.nosql_payloads, self.command_payloads = self._load_payloads()

    def _load_payloads(self):
        payload_file = Path(__file__).parent.parent / "config" / "payloads.yaml"
        try:
            with open(payload_file, 'r', encoding='utf-8') as handle:
                payloads = yaml.safe_load(handle) or {}
            sql_payloads = (
                payloads.get('sql_injection', {}).get('basic', []) +
                payloads.get('sql_injection', {}).get('union_based', []) +
                payloads.get('sql_injection', {}).get('time_based', [])
            )
            nosql_payloads = payloads.get('nosql_injection', [])
            command_payloads = payloads.get('command_injection', [])
            return sql_payloads, nosql_payloads, command_payloads
        except Exception:
            return (
                ["' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"],
                ['{"$gt": ""}', '{"$ne": null}'],
                ['; ls -la', '| whoami'],
            )

    def scan(self) -> List[Dict]:
        findings = []

        if not self.client.schema:
            self.reporter.print_warning("Introspection not available, skipping schema-aware injection tests")
            return findings

        self.reporter.print_info("Testing SQL injection on queries with arguments...")
        findings.extend(self._test_query_family('query', self.client.get_queries(), self.sql_payloads[:4], detect_sql_error, "Possible SQL Injection Vulnerability", "CWE-89: SQL Injection"))

        self.reporter.print_info("Testing SQL injection on mutations...")
        findings.extend(self._test_query_family('mutation', self.client.get_mutations(), self.sql_payloads[:4], detect_sql_error, "Possible SQL Injection Vulnerability in Mutation", "CWE-89: SQL Injection"))

        if self.config.get('enable_deep_injection', True):
            self.reporter.print_info("Testing NoSQL injection...")
            findings.extend(self._test_query_family('query', self.client.get_queries(), self.nosql_payloads[:3], detect_nosql_error, "Possible NoSQL Injection Vulnerability", "CWE-943: Improper Neutralization of Special Elements in Data Query Logic"))

            self.reporter.print_info("Testing command injection...")
            findings.extend(self._test_command_injection())

        return findings

    def _test_query_family(self, operation_kind: str, fields: List[Dict], payloads: List[str], detector, title: str, cwe: str) -> List[Dict]:
        findings = []
        parser = SchemaParser(self.client.schema)
        max_fields = 5

        for field in fields[:max_fields]:
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
            baseline_errors = " | ".join(extract_error_messages(baseline_result))
            if is_validation_error(baseline_result):
                continue

            for arg in args[:2]:
                arg_name = arg.get('name')
                arg_type_name = extract_type_name(arg.get('type', {}))
                if arg_type_name not in {'String', 'ID'}:
                    continue

                for payload in payloads:
                    probe = parser.build_operation(field, operation_kind=operation_kind, overrides={arg_name: payload})
                    if not probe.get('testable'):
                        continue

                    result = self.client.query(
                        probe['query'],
                        variables=probe.get('variables'),
                        operation_name=probe.get('operation_name'),
                    )

                    error_text = " | ".join(extract_error_messages(result))
                    if error_text and detector(error_text) and not detector(baseline_errors):
                        finding_title = title
                        if operation_kind == 'mutation' and 'Mutation' not in title:
                            finding_title = f"{title} in Mutation"

                        findings.append(create_finding(
                            title=finding_title,
                            severity="HIGH",
                            description=f"Backend error patterns consistent with injection were observed while testing {field.get('name')}.{arg_name} with a crafted payload.",
                            impact="Injection flaws can allow attackers to manipulate backend queries or command execution paths, leading to unauthorized access, data tampering, or system compromise.",
                            remediation="Use parameterized queries or driver-native safe APIs, validate all inputs rigorously, and avoid directly concatenating user-controlled values into queries or shell commands.",
                            cwe=cwe,
                            scanner="injection",
                            classification={'kind': 'vulnerability', 'family': 'injection'},
                            confidence={'level': 'medium', 'reasons': ['Schema-valid baseline probe did not show the backend-specific error signature, while the injection payload did']},
                            evidence={
                                'operation_kind': operation_kind,
                                'field': field.get('name'),
                                'argument': arg_name,
                                'payload': payload,
                                'baseline_errors': baseline_errors[:500],
                                'payload_errors': error_text[:500]
                            },
                            request={
                                'query': probe['query'],
                                'variables': probe.get('variables'),
                                'operation_name': probe.get('operation_name')
                            },
                            poc=probe['query'],
                            url=self.client.url
                        ))
                        if len(findings) >= 3:
                            return findings
        return findings

    def _test_command_injection(self) -> List[Dict]:
        findings = []
        parser = SchemaParser(self.client.schema)
        cmd_indicators = [
            'sh:', 'bash:', 'command not found',
            'permission denied', '/bin/',
            'cannot execute', 'processexception'
        ]

        for query_def in self.client.get_queries()[:5]:
            args = query_def.get('args', [])
            if not args:
                continue

            baseline = parser.build_operation(query_def, operation_kind='query')
            if not baseline.get('testable'):
                continue

            baseline_result = self.client.query(
                baseline['query'],
                variables=baseline.get('variables'),
                operation_name=baseline.get('operation_name'),
            )
            baseline_errors = " | ".join(extract_error_messages(baseline_result)).lower()
            if is_validation_error(baseline_result):
                continue

            for arg in args[:2]:
                if extract_type_name(arg.get('type', {})) != 'String':
                    continue

                for payload in self.command_payloads[:3]:
                    probe = parser.build_operation(query_def, operation_kind='query', overrides={arg.get('name'): payload})
                    if not probe.get('testable'):
                        continue

                    result = self.client.query(
                        probe['query'],
                        variables=probe.get('variables'),
                        operation_name=probe.get('operation_name'),
                    )
                    error_text = " | ".join(extract_error_messages(result)).lower()
                    if any(indicator in error_text for indicator in cmd_indicators) and not any(indicator in baseline_errors for indicator in cmd_indicators):
                        findings.append(create_finding(
                            title="Possible Command Injection Vulnerability",
                            severity="HIGH",
                            description=f"Command-execution-like error patterns were observed while testing {query_def.get('name')}.{arg.get('name')} with a crafted payload.",
                            impact="Command injection can allow arbitrary operating-system command execution and may lead to full host compromise.",
                            remediation="Never concatenate user input into shell commands. Use safe APIs that avoid invoking a shell, and enforce strict allowlists when command execution is unavoidable.",
                            cwe="CWE-78: OS Command Injection",
                            scanner="injection",
                            classification={'kind': 'vulnerability', 'family': 'injection'},
                            confidence={'level': 'medium', 'reasons': ['Schema-valid baseline did not show shell-related errors, but the crafted payload did']},
                            evidence={
                                'field': query_def.get('name'),
                                'argument': arg.get('name'),
                                'payload': payload,
                                'baseline_errors': baseline_errors[:500],
                                'payload_errors': error_text[:500]
                            },
                            request={
                                'query': probe['query'],
                                'variables': probe.get('variables'),
                                'operation_name': probe.get('operation_name')
                            },
                            poc=probe['query'],
                            url=self.client.url
                        ))
                        if len(findings) >= 2:
                            return findings
        return findings

