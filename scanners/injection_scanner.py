#!/usr/bin/env python3
"""
Injection Scanner - Tests for SQL, NoSQL, and Command injection vulnerabilities
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from graphql_client import GraphQLClient
from reporter import Reporter
from utils import (
    create_finding,
    detect_sql_error,
    detect_nosql_error,
    exact_permutation_pvalue,
    extract_error_messages,
    extract_type_name,
    is_validation_error,
    median_abs_deviation,
    parse_expected_delay,
)
from introspection import SchemaParser
from typing import List, Dict
import yaml
import statistics
import time


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
            sql_payloads = payloads.get('sql_injection', {})
            sql_payloads = {
                'basic': sql_payloads.get('basic', []),
                'union_based': sql_payloads.get('union_based', []),
                'time_based': sql_payloads.get('time_based', []),
            }
            nosql_payloads = payloads.get('nosql_injection', [])
            command_payloads = payloads.get('command_injection', [])
            return sql_payloads, nosql_payloads, command_payloads
        except Exception:
            return (
                {
                    'basic': ["' OR '1'='1", "' OR 1=1--"],
                    'union_based': ["' UNION SELECT NULL--"],
                    'time_based': ["' WAITFOR DELAY '0:0:5'--", "' AND SLEEP(5)--", "'; SELECT PG_SLEEP(5)--"],
                },
                ['{"$gt": ""}', '{"$ne": null}'],
                ['; ls -la', '| whoami'],
            )

    def scan(self) -> List[Dict]:
        findings = []

        if not self.client.schema:
            self.client.introspect()

        if not self.client.schema:
            self.reporter.print_warning("Introspection not available, skipping schema-aware injection tests")
            return findings

        self.reporter.print_info("Testing SQL injection on queries with arguments...")
        sql_error_payloads = self.sql_payloads.get('basic', []) + self.sql_payloads.get('union_based', [])
        findings.extend(self._test_query_family('query', self.client.get_queries(), sql_error_payloads[:6], detect_sql_error, "Possible SQL Injection Vulnerability", "CWE-89: SQL Injection"))

        self.reporter.print_info("Testing SQL injection on mutations...")
        findings.extend(self._test_query_family('mutation', self.client.get_mutations(), sql_error_payloads[:6], detect_sql_error, "Possible SQL Injection Vulnerability in Mutation", "CWE-89: SQL Injection"))

        self.reporter.print_info("Testing time-based SQL injection...")
        findings.extend(self._test_time_based_query_family('query', self.client.get_queries(), self.sql_payloads.get('time_based', []), "Potential Time-Based SQL Injection Vulnerability", "CWE-89: SQL Injection"))

        if self.config.get('enable_deep_injection', True):
            self.reporter.print_info("Testing NoSQL injection...")
            findings.extend(self._test_query_family('query', self.client.get_queries(), self.nosql_payloads[:3], detect_nosql_error, "Possible NoSQL Injection Vulnerability", "CWE-943: Improper Neutralization of Special Elements in Data Query Logic"))

            self.reporter.print_info("Testing command injection...")
            findings.extend(self._test_command_injection())

        return findings

    def _measure_query(self, query: str, variables: Dict | None, operation_name: str | None) -> tuple[Dict, float]:
        """Execute a query and return result plus elapsed seconds."""
        started = time.perf_counter()
        result = self.client.query(query, variables=variables, operation_name=operation_name)
        elapsed = result.get('_elapsed_seconds')
        if elapsed is None:
            elapsed = time.perf_counter() - started
        return result, float(elapsed)

    def _extract_root_value(self, result: Dict, field_name: str):
        """Extract the root field value from GraphQL data."""
        data = result.get('data') or {}
        if not isinstance(data, dict):
            return None
        return data.get(field_name)

    def _is_boolean_probe_payload(self, payload: str) -> bool:
        """Identify boolean/tautology-oriented injection payloads."""
        lowered = (payload or "").lower()
        return any(token in lowered for token in ["1=1", "'a'='a", '"a"="a', "$gt", "$ne", "$regex"])

    def _looks_like_boolean_injection_diff(self, baseline_value, payload_value) -> bool:
        """Best-effort detection of suspicious data-shape expansion."""
        if isinstance(baseline_value, list) and isinstance(payload_value, list):
            return len(payload_value) > max(len(baseline_value) + 1, 1)
        if baseline_value in (None, [], {}) and payload_value not in (None, [], {}):
            return True
        return False

    def _test_query_family(self, operation_kind: str, fields: List[Dict], payloads: List[str], detector, title: str, cwe: str) -> List[Dict]:
        findings = []
        parser = SchemaParser(self.client.schema)
        max_fields = 5

        for field in fields[:max_fields]:
            args = field.get('args', [])
            if not args:
                continue

            common_overrides = {}
            if operation_kind == 'query':
                for extra_arg in args:
                    if extra_arg.get('name') == 'limit' and extract_type_name(extra_arg.get('type', {})) == 'Int':
                        common_overrides['limit'] = 5

            candidate_args = [arg for arg in args if extract_type_name(arg.get('type', {})) in {'String', 'ID'}]
            for arg in candidate_args[:3]:
                arg_name = arg.get('name')
                arg_type_name = extract_type_name(arg.get('type', {}))
                finding_emitted_for_arg = False

                arg_baseline_overrides = dict(common_overrides)
                if arg_type_name == 'String':
                    arg_baseline_overrides[arg_name] = "__gqlh_baseline__"
                elif arg_type_name == 'ID':
                    arg_baseline_overrides[arg_name] = "999999999"

                baseline = parser.build_operation(field, operation_kind=operation_kind, overrides=arg_baseline_overrides)
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

                for payload in payloads:
                    payload_variants = [payload]
                    if operation_kind == 'query' and arg_type_name == 'String' and payload[:1] in {"'", '"'}:
                        payload_variants.append(f"test {payload}")

                    for payload_variant in payload_variants:
                        probe_overrides = dict(common_overrides)
                        probe_overrides[arg_name] = payload_variant
                        probe = parser.build_operation(field, operation_kind=operation_kind, overrides=probe_overrides)
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
                                    'payload': payload_variant,
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
                            finding_emitted_for_arg = True
                            if len(findings) >= 3:
                                return findings
                            break
                        elif operation_kind == 'query' and self._is_boolean_probe_payload(payload_variant):
                            baseline_value = self._extract_root_value(baseline_result, field.get('name'))
                            payload_value = self._extract_root_value(result, field.get('name'))
                            if self._looks_like_boolean_injection_diff(baseline_value, payload_value):
                                findings.append(create_finding(
                                    title=title,
                                    severity="HIGH",
                                    description=f"Behavioral differences consistent with boolean-based injection were observed while testing {field.get('name')}.{arg_name} with a crafted payload.",
                                    impact="Boolean-based injection can let attackers bypass filters, exfiltrate data without verbose errors, or enumerate protected records through true/false response differences.",
                                    remediation="Use parameterized queries, validate and normalize user-controlled filter values, and avoid interpolating raw input into backend query fragments.",
                                    cwe=cwe,
                                    scanner="injection",
                                    classification={'kind': 'vulnerability', 'family': 'injection'},
                                    confidence={'level': 'medium', 'reasons': ['Schema-valid baseline and payload probes returned materially different data shapes for a tautology-style payload']},
                                    evidence={
                                        'operation_kind': operation_kind,
                                        'field': field.get('name'),
                                        'argument': arg_name,
                                        'payload': payload_variant,
                                        'baseline_value_type': type(baseline_value).__name__,
                                        'payload_value_type': type(payload_value).__name__,
                                        'baseline_count': len(baseline_value) if isinstance(baseline_value, list) else (0 if baseline_value in (None, {}) else 1),
                                        'payload_count': len(payload_value) if isinstance(payload_value, list) else (0 if payload_value in (None, {}) else 1),
                                    },
                                    request={
                                        'query': probe['query'],
                                        'variables': probe.get('variables'),
                                        'operation_name': probe.get('operation_name')
                                    },
                                    poc=probe['query'],
                                    url=self.client.url
                                ))
                                finding_emitted_for_arg = True
                                if len(findings) >= 3:
                                    return findings
                                break
                    if finding_emitted_for_arg:
                        break
        return findings

    def _test_time_based_query_family(self, operation_kind: str, fields: List[Dict], payloads: List[str], title: str, cwe: str) -> List[Dict]:
        findings = []
        parser = SchemaParser(self.client.schema)

        timing_baseline_samples = int(self.config.get('timing_baseline_samples', 5))
        timing_payload_samples = int(self.config.get('timing_payload_samples', 4))
        timing_control_samples = int(self.config.get('timing_control_samples', 3))
        timing_min_delta = float(self.config.get('timing_min_delta_seconds', 1.5))
        timing_expected_ratio = float(self.config.get('timing_expected_delay_ratio', 0.6))
        timing_consistency_ratio = float(self.config.get('timing_consistency_ratio', 0.5))
        timing_baseline_mad_floor = float(self.config.get('timing_baseline_mad_floor', 0.15))
        timing_baseline_mad_ratio = float(self.config.get('timing_baseline_mad_ratio', 0.25))
        timing_p_value = float(self.config.get('timing_p_value', 0.05))
        control_payload = (self.sql_payloads.get('basic') or ["' OR '1'='1"])[0]

        for field in fields[:3]:
            args = field.get('args', [])
            if not args:
                continue

            baseline = parser.build_operation(field, operation_kind=operation_kind)
            if not baseline.get('testable'):
                continue

            string_args = [arg for arg in args[:2] if extract_type_name(arg.get('type', {})) in {'String', 'ID'}]
            if not string_args:
                continue

            for arg in string_args[:1]:
                arg_name = arg.get('name')
                _, _ = self._measure_query(baseline['query'], baseline.get('variables'), baseline.get('operation_name'))  # warm-up

                baseline_samples = []
                baseline_results = []
                for _ in range(timing_baseline_samples):
                    result, elapsed = self._measure_query(baseline['query'], baseline.get('variables'), baseline.get('operation_name'))
                    if is_validation_error(result):
                        baseline_samples = []
                        break
                    baseline_samples.append(elapsed)
                    baseline_results.append(result)

                if len(baseline_samples) < timing_baseline_samples:
                    continue

                baseline_median = statistics.median(baseline_samples)
                baseline_mad = median_abs_deviation(baseline_samples)
                if baseline_mad > max(timing_baseline_mad_floor, timing_baseline_mad_ratio * max(baseline_median, 0.001)):
                    continue

                for payload in payloads[:3]:
                    probe = parser.build_operation(field, operation_kind=operation_kind, overrides={arg_name: payload})
                    if not probe.get('testable'):
                        continue

                    payload_results = []
                    payload_samples = []
                    for _ in range(timing_payload_samples):
                        result, elapsed = self._measure_query(probe['query'], probe.get('variables'), probe.get('operation_name'))
                        if is_validation_error(result):
                            payload_samples = []
                            break
                        payload_results.append(result)
                        payload_samples.append(elapsed)

                    if len(payload_samples) < timing_payload_samples:
                        continue

                    expected_delay = parse_expected_delay(payload)
                    payload_median = statistics.median(payload_samples)
                    observed_delta = payload_median - baseline_median
                    p_value = exact_permutation_pvalue(baseline_samples, payload_samples)
                    consistency_threshold = baseline_median + max(1.0, timing_consistency_ratio * expected_delay, 4 * baseline_mad)
                    consistent_samples = sum(1 for sample in payload_samples if sample >= consistency_threshold)

                    if observed_delta < max(timing_min_delta, timing_expected_ratio * expected_delay, 6 * baseline_mad):
                        continue
                    if consistent_samples < max(3, timing_payload_samples - 1):
                        continue
                    if p_value > timing_p_value:
                        continue

                    control_probe = parser.build_operation(field, operation_kind=operation_kind, overrides={arg_name: control_payload})
                    if not control_probe.get('testable'):
                        continue

                    control_samples = []
                    control_results = []
                    for _ in range(timing_control_samples):
                        result, elapsed = self._measure_query(control_probe['query'], control_probe.get('variables'), control_probe.get('operation_name'))
                        if is_validation_error(result):
                            control_samples = []
                            break
                        control_results.append(result)
                        control_samples.append(elapsed)

                    if len(control_samples) < timing_control_samples:
                        continue

                    control_median = statistics.median(control_samples)
                    control_delta = payload_median - control_median
                    if control_delta < max(1.0, timing_consistency_ratio * expected_delay):
                        continue

                    findings.append(create_finding(
                        title=title,
                        severity="HIGH",
                        description=f"Time-based injection payloads caused a consistent, statistically significant latency increase while testing {field.get('name')}.{arg_name}.",
                        impact="If an attacker can induce database sleep primitives, they may be able to confirm blind SQL injection and exfiltrate sensitive data without relying on verbose errors.",
                        remediation="Use parameterized queries, avoid string concatenation in database interactions, and ensure the backend does not execute user-controlled SQL fragments or timing primitives.",
                        cwe=cwe,
                        scanner="injection",
                        classification={'kind': 'vulnerability', 'family': 'injection'},
                        confidence={'level': 'medium', 'reasons': ['Time-based payload produced a consistent latency increase versus both baseline and non-timing control probes']},
                        evidence={
                            'operation_kind': operation_kind,
                            'field': field.get('name'),
                            'argument': arg_name,
                            'payload': payload,
                            'expected_delay_seconds': expected_delay,
                            'baseline_samples': baseline_samples,
                            'payload_samples': payload_samples,
                            'control_samples': control_samples,
                            'baseline_median': baseline_median,
                            'payload_median': payload_median,
                            'control_median': control_median,
                            'baseline_mad': baseline_mad,
                            'median_delta': observed_delta,
                            'control_delta': control_delta,
                            'p_value': p_value,
                            'baseline_errors': [extract_error_messages(r) for r in baseline_results],
                            'payload_errors': [extract_error_messages(r) for r in payload_results],
                            'control_errors': [extract_error_messages(r) for r in control_results],
                        },
                        request={
                            'query': probe['query'],
                            'variables': probe.get('variables'),
                            'operation_name': probe.get('operation_name'),
                        },
                        poc=probe['query'],
                        url=self.client.url,
                    ))
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

            candidate_args = [arg for arg in args if extract_type_name(arg.get('type', {})) == 'String']
            for arg in candidate_args[:3]:

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

