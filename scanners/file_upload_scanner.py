#!/usr/bin/env python3
"""
File Upload Scanner - Tests for file upload vulnerabilities
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from graphql_client import GraphQLClient
from reporter import Reporter
from utils import create_finding, extract_error_messages
from introspection import SchemaParser
from typing import List, Dict
import copy


class FileUploadScanner:
    """Scanner for file upload vulnerabilities"""
    
    def __init__(self, client: GraphQLClient, reporter: Reporter, config: Dict):
        """
        Initialize file upload scanner
        
        Args:
            client: GraphQL client instance
            reporter: Reporter instance
            config: Scanner configuration
        """
        self.client = client
        self.reporter = reporter
        self.config = config
        self.max_file_size = config.get('max_upload_test_size', 10 * 1024 * 1024)  # 10MB default
    
    def scan(self) -> List[Dict]:
        """
        Run file upload scan
        
        Returns:
            List of findings
        """
        findings = []

        if not self.client.schema:
            self.client.introspect()
        
        if not self.client.schema:
            self.reporter.print_warning("Schema not available, skipping file upload tests")
            return findings
        
        # Detect upload mutations
        upload_mutations = self._detect_upload_mutations()
        
        if not upload_mutations:
            self.reporter.print_info("No file upload mutations detected")
            return findings
        
        self.reporter.print_info(f"Found {len(upload_mutations)} mutation(s) with file upload capability")
        
        # Test each upload mutation
        for mutation in upload_mutations:
            mutation_name = mutation['mutation'].get('name')
            self.reporter.print_info(f"Testing {mutation_name} for file upload vulnerabilities...")
            
            findings.extend(self._test_path_traversal(mutation))
            findings.extend(self._test_oversized_files(mutation))
            findings.extend(self._test_malicious_extensions(mutation))
            findings.extend(self._test_filename_injection(mutation))
        
        return findings
    
    def _detect_upload_mutations(self) -> List[Dict]:
        """Detect mutations with Upload type args or upload-like string inputs."""
        mutations = self.client.get_mutations()
        if not mutations:
            return []

        parser = SchemaParser(self.client.schema)
        upload_mutations = []

        for mutation in mutations:
            upload_targets = parser.find_upload_targets(mutation)
            if upload_targets:
                upload_mutations.append({
                    'mutation': mutation,
                    'transport': 'multipart',
                    'upload_targets': upload_targets,
                    'parser': parser,
                })
                continue

            arg_names = {arg.get('name', '').lower(): arg for arg in mutation.get('args', [])}
            mutation_name = mutation.get('name', '').lower()
            has_filename = any(name in arg_names for name in {'filename', 'file', 'path'})
            has_content = any(name in arg_names for name in {'content', 'text', 'data', 'body'})
            if has_filename and has_content and any(keyword in mutation_name for keyword in {'upload', 'import', 'file', 'paste'}):
                upload_mutations.append({
                    'mutation': mutation,
                    'transport': 'string_upload',
                    'filename_arg': next(name for name in {'filename', 'file', 'path'} if name in arg_names),
                    'content_arg': next(name for name in {'content', 'text', 'data', 'body'} if name in arg_names),
                    'parser': parser,
                })

        return upload_mutations

    def _build_candidate_operation(self, candidate: Dict, overrides: Dict | None = None) -> Dict | None:
        """Build a schema-valid operation for an upload candidate."""
        parser = candidate['parser']
        built = parser.build_operation(candidate['mutation'], operation_kind='mutation', overrides=overrides or {})
        if not built.get('testable'):
            return None
        return built

    def _build_upload_specs(
        self,
        candidate: Dict,
        *,
        target_path: str | None = None,
        filename: str = "test.txt",
        content: bytes | str = b"upload-test",
        content_type: str = "text/plain",
    ) -> Dict[str, Dict]:
        """Build uploads mapping, setting benign files for sibling upload slots."""
        specs = {}
        for target in candidate.get('upload_targets', []):
            specs[target['variable_path']] = {
                'filename': filename if target_path is None or target['variable_path'] == target_path else 'benign.txt',
                'content': content if target_path is None or target['variable_path'] == target_path else b'benign',
                'content_type': content_type,
            }
        return specs

    def _execute_candidate_probe(
        self,
        candidate: Dict,
        *,
        filename: str,
        content: bytes | str,
        content_type: str = "text/plain",
    ) -> Dict:
        """Execute a live upload probe for multipart or string-based upload surfaces."""
        built = self._build_candidate_operation(candidate)
        if not built:
            return {'_untestable': True, 'errors': [{'message': 'Unable to auto-build upload mutation'}]}

        variables = copy.deepcopy(built.get('variables') or {})
        if candidate['transport'] == 'multipart':
            for target in candidate.get('upload_targets', []):
                self._set_value_at_path(variables, target['variable_path'].replace('variables.', ''), None)
            uploads = self._build_upload_specs(candidate, filename=filename, content=content, content_type=content_type)
            return self.client.query(
                built['query'],
                variables=variables,
                operation_name=built.get('operation_name'),
                uploads=uploads,
            )

        filename_key = candidate['filename_arg']
        content_key = candidate['content_arg']
        variables[filename_key] = filename
        variables[content_key] = content.decode('utf-8') if isinstance(content, bytes) else content
        return self.client.query(
            built['query'],
            variables=variables,
            operation_name=built.get('operation_name'),
        )

    def _set_value_at_path(self, obj: Dict, path: str, value) -> None:
        """Set nested dict/list path values using dotted notation."""
        tokens = path.split('.')
        cursor = obj
        for token in tokens[:-1]:
            if token.isdigit():
                cursor = cursor[int(token)]
            else:
                cursor = cursor[token]
        final = tokens[-1]
        if final.isdigit():
            cursor[int(final)] = value
        else:
            cursor[final] = value

    def _looks_like_successful_upload(self, result: Dict) -> bool:
        """Best-effort determination that an upload mutation was accepted."""
        return bool(result.get('data')) and not result.get('errors')
    
    def _test_path_traversal(self, mutation: Dict) -> List[Dict]:
        """Test for path traversal vulnerabilities"""
        findings = []
        
        mutation_name = mutation['mutation'].get('name')
        
        # Path traversal payloads
        path_traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
        ]
        
        for payload in path_traversal_payloads[:3]:
            result = self._execute_candidate_probe(mutation, filename=payload, content="upload-test")
            if result.get('_untestable'):
                break
            if self._looks_like_successful_upload(result):
                findings.append(create_finding(
                    title="Potential Path Traversal in File Upload",
                    severity="HIGH",
                    description=f"Upload-like mutation {mutation_name} accepted a dangerous filename payload ({payload}) without rejecting it. This suggests path traversal protections may be missing or weak.",
                    impact="If upload paths are not sanitized, attackers may write files outside the intended upload directory, overwrite application files, or plant malicious content in accessible locations.",
                    remediation="Normalize and validate filenames server-side, disallow directory separators and dot-dot sequences, generate server-side filenames, and store uploads outside executable or sensitive directories.",
                    cwe="CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
                    scanner="file_upload",
                    classification={'kind': 'vulnerability', 'family': 'upload'},
                    confidence={'level': 'medium', 'reasons': ['Live upload probe with a traversal-style filename was accepted successfully']},
                    evidence={
                        'mutation': mutation_name,
                        'payload': payload,
                        'transport': mutation['transport'],
                        'response': result.get('data')
                    },
                    manual_verification_required=True,
                    poc=f"Test {mutation_name} with filename={payload}",
                    url=self.client.url
                ))
                return findings

        findings.append(create_finding(
            title="File Upload Mutation Detected",
            severity="INFO",
            description=f"Mutation {mutation_name} accepts file uploads or upload-like inputs. Live probing did not conclusively demonstrate path traversal, so manual testing is still recommended.",
            impact="File uploads can be vulnerable to path traversal, malicious file execution, oversized upload DoS, and filename injection attacks.",
            remediation="Implement strict filename validation, path normalization, file type validation, size limits, and server-side generated filenames.",
            cwe="CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
            scanner="file_upload",
            classification={'kind': 'manual_review', 'family': 'upload'},
            confidence={'level': 'low', 'reasons': ['Upload surface was found, but traversal exploitability was not conclusively proven by automated probing']},
            manual_verification_required=True,
            evidence={
                'mutation': mutation_name,
                'transport': mutation['transport'],
                'test_payloads': path_traversal_payloads
            },
            poc=f"Test {mutation_name} with filenames: {', '.join(path_traversal_payloads[:3])}",
            url=self.client.url
        ))
        
        return findings
    
    def _test_oversized_files(self, mutation: Dict) -> List[Dict]:
        """Test for oversized file upload DoS"""
        findings = []
        
        mutation_name = mutation['mutation'].get('name')
        
        # Check safe mode
        if self.config.get('safe_mode', False):
            self.reporter.print_info("Safe mode enabled, skipping oversized file tests")
            return findings
        
        oversize_bytes = self.max_file_size + 1
        result = self._execute_candidate_probe(
            mutation,
            filename="oversized.txt",
            content=b"A" * oversize_bytes,
            content_type="text/plain",
        )

        if self._looks_like_successful_upload(result):
            findings.append(create_finding(
                title="Potential Missing File Size Limit",
                severity="MEDIUM",
                description=f"Upload-like mutation {mutation_name} accepted a payload slightly larger than the configured maximum upload test size ({self.max_file_size} bytes).",
                impact="Missing or weak size limits can enable storage exhaustion, memory pressure, and degraded service performance during large uploads.",
                remediation="Enforce hard server-side file size limits before processing uploaded content and reject oversized files as early as possible.",
                cwe="CWE-400: Uncontrolled Resource Consumption",
                scanner="file_upload",
                classification={'kind': 'hardening_gap', 'family': 'upload'},
                confidence={'level': 'medium', 'reasons': ['Oversized upload probe completed successfully instead of being rejected']},
                evidence={
                    'mutation': mutation_name,
                    'tested_size_bytes': oversize_bytes,
                    'configured_threshold_bytes': self.max_file_size
                },
                manual_verification_required=True,
                poc=f"Test {mutation_name} with file size {oversize_bytes} bytes",
                url=self.client.url
            ))
        else:
            findings.append(create_finding(
                title="File Upload Size Limit Testing Recommended",
                severity="INFO",
                description=f"Mutation {mutation_name} accepts file uploads. Oversized probing did not produce a clear result, so size-limit validation should still be reviewed manually.",
                impact="Without proper size limits, attackers can upload extremely large files to consume server storage and memory, potentially causing DoS.",
                remediation="Implement strict file size limits, reject oversized payloads early, and monitor upload endpoints for abnormal body sizes.",
                cwe="CWE-400: Uncontrolled Resource Consumption",
                scanner="file_upload",
                classification={'kind': 'manual_review', 'family': 'upload'},
                confidence={'level': 'low', 'reasons': ['Automated oversized upload probe was inconclusive']},
                manual_verification_required=True,
                evidence={
                    'mutation': mutation_name,
                    'tested_size_bytes': oversize_bytes
                },
                poc=f"Test {mutation_name} with file size {oversize_bytes} bytes",
                url=self.client.url
            ))
        
        return findings
    
    def _test_malicious_extensions(self, mutation: Dict) -> List[Dict]:
        """Test for malicious file extension vulnerabilities"""
        findings = []
        
        mutation_name = mutation['mutation'].get('name')
        
        # Malicious extensions to test
        malicious_extensions = [
            '.exe', '.php', '.jsp', '.asp', '.aspx',
            '.sh', '.bat', '.cmd', '.ps1', '.py',
            '.js', '.html', '.htm', '.svg',
        ]
        
        for extension in malicious_extensions[:5]:
            filename = f"payload{extension}"
            result = self._execute_candidate_probe(mutation, filename=filename, content="upload-test")
            if self._looks_like_successful_upload(result):
                findings.append(create_finding(
                    title="Potential Dangerous File Type Upload",
                    severity="MEDIUM",
                    description=f"Upload-like mutation {mutation_name} accepted a potentially dangerous filename extension ({extension}) without rejecting it.",
                    impact="If uploaded files are later served or executed, accepting dangerous file types can enable remote code execution, HTML/script injection, or stored client-side attacks.",
                    remediation="Use an allowlist of permitted file types, validate MIME types and magic bytes, reject double extensions, and store uploads outside executable or public web paths.",
                    cwe="CWE-434: Unrestricted Upload of File with Dangerous Type",
                    scanner="file_upload",
                    classification={'kind': 'hardening_gap', 'family': 'upload'},
                    confidence={'level': 'medium', 'reasons': ['Live upload probe with a dangerous extension was accepted successfully']},
                    evidence={
                        'mutation': mutation_name,
                        'filename': filename,
                        'transport': mutation['transport'],
                        'response': result.get('data')
                    },
                    manual_verification_required=True,
                    poc=f"Test {mutation_name} with filename={filename}",
                    url=self.client.url
                ))
                return findings

        findings.append(create_finding(
            title="File Upload Extension Validation Testing Recommended",
            severity="INFO",
            description=f"Mutation {mutation_name} accepts file uploads. Dangerous file extension probing was inconclusive, so extension and MIME validation should still be reviewed manually.",
            impact="If file type validation is insufficient, attackers may upload executable files or scripts that could be executed on the server.",
            remediation="Implement strict file type validation, reject double extensions, validate magic bytes, and avoid serving uploaded files from executable or public directories.",
            cwe="CWE-434: Unrestricted Upload of File with Dangerous Type",
            scanner="file_upload",
            classification={'kind': 'manual_review', 'family': 'upload'},
            confidence={'level': 'low', 'reasons': ['Automated dangerous-extension upload probes did not conclusively prove acceptance or rejection']},
            manual_verification_required=True,
            evidence={
                'mutation': mutation_name,
                'malicious_extensions': malicious_extensions
            },
            poc=f"Test {mutation_name} with files having extensions: {', '.join(malicious_extensions[:5])}",
            url=self.client.url
        ))
        
        return findings
    
    def _test_filename_injection(self, mutation: Dict) -> List[Dict]:
        """Test for filename injection vulnerabilities"""
        findings = []
        
        mutation_name = mutation['mutation'].get('name')
        
        # Filename injection payloads
        injection_payloads = [
            'file.txt\n\r',
            'file.txt%00.jpg',
            'file.txt\x00.jpg',
            'file.txt; rm -rf /',
            'file.txt|whoami',
            'file.txt`id`',
            'file.txt$(whoami)',
            'file.txt && cat /etc/passwd',
        ]
        
        for payload in injection_payloads[:3]:
            result = self._execute_candidate_probe(mutation, filename=payload, content="upload-test")
            if self._looks_like_successful_upload(result):
                findings.append(create_finding(
                    title="Potential Filename Injection Vulnerability",
                    severity="LOW",
                    description=f"Upload-like mutation {mutation_name} accepted a suspicious filename payload ({payload}) without rejecting it.",
                    impact="Unsanitized filenames can enable command injection, stored XSS, path traversal, or downstream parser confusion depending on how filenames are processed or displayed.",
                    remediation="Whitelist safe filename characters, strip or normalize control characters and separators, and never use user-provided filenames directly in shell commands or HTML output.",
                    cwe="CWE-78: OS Command Injection",
                    scanner="file_upload",
                    classification={'kind': 'hardening_gap', 'family': 'upload'},
                    confidence={'level': 'low', 'reasons': ['Live upload probe accepted a suspicious filename, but exploitability depends on downstream processing']},
                    evidence={
                        'mutation': mutation_name,
                        'filename_payload': payload,
                        'transport': mutation['transport']
                    },
                    manual_verification_required=True,
                    poc=f"Test {mutation_name} with filename={payload}",
                    url=self.client.url
                ))
                return findings

        findings.append(create_finding(
            title="Filename Injection Testing Recommended",
            severity="LOW",
            description=f"Mutation {mutation_name} accepts file uploads. Automated suspicious-filename probing was inconclusive, so filename sanitization should still be reviewed manually.",
            impact="Filename injection can allow command injection, path traversal, or stored XSS if filenames are processed unsafely.",
            remediation="Sanitize filenames, limit filename length, whitelist safe characters, and generate server-side names instead of trusting user input.",
            cwe="CWE-78: OS Command Injection",
            scanner="file_upload",
            classification={'kind': 'manual_review', 'family': 'upload'},
            confidence={'level': 'low', 'reasons': ['Automated suspicious-filename probes did not conclusively prove unsafe handling']},
            manual_verification_required=True,
            evidence={
                'mutation': mutation_name,
                'injection_payloads': injection_payloads
            },
            poc=f"Test {mutation_name} with filenames: {', '.join(injection_payloads[:3])}",
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
