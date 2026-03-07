#!/usr/bin/env python3
"""
File Upload Scanner - Tests for file upload vulnerabilities
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from graphql_client import GraphQLClient
from reporter import Reporter
from utils import create_finding
from typing import List, Dict
import os
import tempfile


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
            mutation_name = mutation.get('name')
            self.reporter.print_info(f"Testing {mutation_name} for file upload vulnerabilities...")
            
            findings.extend(self._test_path_traversal(mutation))
            findings.extend(self._test_oversized_files(mutation))
            findings.extend(self._test_malicious_extensions(mutation))
            findings.extend(self._test_filename_injection(mutation))
        
        return findings
    
    def _detect_upload_mutations(self) -> List[Dict]:
        """Detect mutations with Upload type arguments"""
        mutations = self.client.get_mutations()
        if not mutations:
            return []
        
        upload_mutations = []
        
        for mutation in mutations:
            args = mutation.get('args', [])
            for arg in args:
                arg_type = self._extract_type_name(arg.get('type', {}))
                # Check for Upload scalar type
                if arg_type == 'Upload' or 'Upload' in str(arg_type):
                    upload_mutations.append(mutation)
                    break
        
        return upload_mutations
    
    def _test_path_traversal(self, mutation: Dict) -> List[Dict]:
        """Test for path traversal vulnerabilities"""
        findings = []
        
        mutation_name = mutation.get('name')
        args = mutation.get('args', [])
        
        # Find Upload argument
        upload_arg = None
        for arg in args:
            arg_type = self._extract_type_name(arg.get('type', {}))
            if arg_type == 'Upload' or 'Upload' in str(arg_type):
                upload_arg = arg
                break
        
        if not upload_arg:
            return findings
        
        # Path traversal payloads
        path_traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
        ]
        
        # Note: Actual file upload testing requires multipart/form-data
        # This is a detection and recommendation finding
        findings.append(create_finding(
            title="File Upload Mutation Detected",
            severity="INFO",
            description=f"Mutation {mutation_name} accepts file uploads. Manual testing recommended for path traversal, file type validation, and size limits.",
            impact="File uploads can be vulnerable to: 1) Path traversal allowing access to sensitive files, 2) Malicious file execution if files are stored in web-accessible directories, 3) DoS via oversized files, 4) Filename injection attacks.",
            remediation="Implement: 1) Strict filename validation (whitelist allowed characters), 2) Path sanitization to prevent directory traversal, 3) File type validation (check MIME type, not just extension), 4) File size limits, 5) Store uploads outside web root, 6) Scan uploaded files for malware, 7) Use unique, random filenames.",
            cwe="CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
            scanner="file_upload",
            classification={'kind': 'manual_review', 'family': 'upload'},
            confidence={'level': 'low', 'reasons': ['Schema confirmed a file upload surface, but multipart upload exploitability was not exercised']},
            manual_verification_required=True,
            evidence={
                'mutation': mutation_name,
                'upload_argument': upload_arg.get('name'),
                'manual_testing_required': True,
                'test_payloads': path_traversal_payloads
            },
            poc=f"Test {mutation_name} with filenames: {', '.join(path_traversal_payloads[:3])}",
            url=self.client.url
        ))
        
        return findings
    
    def _test_oversized_files(self, mutation: Dict) -> List[Dict]:
        """Test for oversized file upload DoS"""
        findings = []
        
        mutation_name = mutation.get('name')
        
        # Check safe mode
        if self.config.get('safe_mode', False):
            self.reporter.print_info("Safe mode enabled, skipping oversized file tests")
            return findings
        
        # Recommend testing with large files
        large_file_sizes = [
            100 * 1024 * 1024,  # 100MB
            500 * 1024 * 1024,  # 500MB
            1024 * 1024 * 1024,  # 1GB
        ]
        
        findings.append(create_finding(
            title="File Upload Size Limit Testing Recommended",
            severity="INFO",
            description=f"Mutation {mutation_name} accepts file uploads. Test with oversized files to verify size limits are enforced.",
            impact="Without proper size limits, attackers can upload extremely large files to consume server storage and memory, potentially causing DoS. Large file processing can also cause timeouts or resource exhaustion.",
            remediation="Implement strict file size limits (e.g., 10-50MB for images, 100MB for documents). Reject files exceeding limits before processing. Consider streaming uploads for large files. Monitor upload sizes and rate limit large uploads.",
            cwe="CWE-400: Uncontrolled Resource Consumption",
            scanner="file_upload",
            classification={'kind': 'manual_review', 'family': 'upload'},
            confidence={'level': 'low', 'reasons': ['Upload surface exists, but oversized multipart handling was not exercised automatically']},
            manual_verification_required=True,
            evidence={
                'mutation': mutation_name,
                'recommended_test_sizes_mb': [size // (1024 * 1024) for size in large_file_sizes],
                'manual_testing_required': True
            },
            poc=f"Test {mutation_name} with files of sizes: {', '.join([f'{s//(1024*1024)}MB' for s in large_file_sizes])}",
            url=self.client.url
        ))
        
        return findings
    
    def _test_malicious_extensions(self, mutation: Dict) -> List[Dict]:
        """Test for malicious file extension vulnerabilities"""
        findings = []
        
        mutation_name = mutation.get('name')
        
        # Malicious extensions to test
        malicious_extensions = [
            '.exe', '.php', '.jsp', '.asp', '.aspx',
            '.sh', '.bat', '.cmd', '.ps1', '.py',
            '.js', '.html', '.htm', '.svg',
        ]
        
        findings.append(create_finding(
            title="File Upload Extension Validation Testing Recommended",
            severity="INFO",
            description=f"Mutation {mutation_name} accepts file uploads. Test with malicious file extensions to verify proper validation.",
            impact="If file type validation is insufficient, attackers may upload executable files or scripts that could be executed on the server, leading to remote code execution. Double extension attacks (e.g., 'file.php.jpg') may bypass validation.",
            remediation="Implement strict file type validation: 1) Check MIME type (not just extension), 2) Use allowlist of allowed file types, 3) Scan file contents (magic bytes), 4) Reject files with double extensions, 5) Rename uploaded files to safe extensions, 6) Store uploads outside web-accessible directories.",
            cwe="CWE-434: Unrestricted Upload of File with Dangerous Type",
            scanner="file_upload",
            classification={'kind': 'manual_review', 'family': 'upload'},
            confidence={'level': 'low', 'reasons': ['Upload surface exists, but file-type enforcement was not exercised automatically']},
            manual_verification_required=True,
            evidence={
                'mutation': mutation_name,
                'malicious_extensions': malicious_extensions,
                'manual_testing_required': True
            },
            poc=f"Test {mutation_name} with files having extensions: {', '.join(malicious_extensions[:5])}",
            url=self.client.url
        ))
        
        return findings
    
    def _test_filename_injection(self, mutation: Dict) -> List[Dict]:
        """Test for filename injection vulnerabilities"""
        findings = []
        
        mutation_name = mutation.get('name')
        
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
        
        findings.append(create_finding(
            title="Filename Injection Testing Recommended",
            severity="LOW",
            description=f"Mutation {mutation_name} accepts file uploads. Test with malicious filenames to verify proper sanitization.",
            impact="Filename injection can allow: 1) Command injection if filenames are used in shell commands, 2) Path traversal if filenames are not sanitized, 3) XSS if filenames are displayed without encoding.",
            remediation="Sanitize filenames: 1) Remove or encode special characters, 2) Limit filename length, 3) Use whitelist of allowed characters, 4) Generate unique filenames server-side, 5) Never use user-provided filenames in shell commands.",
            cwe="CWE-78: OS Command Injection",
            scanner="file_upload",
            classification={'kind': 'manual_review', 'family': 'upload'},
            confidence={'level': 'low', 'reasons': ['Upload surface exists, but filename handling was not exercised automatically']},
            manual_verification_required=True,
            evidence={
                'mutation': mutation_name,
                'injection_payloads': injection_payloads,
                'manual_testing_required': True
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
