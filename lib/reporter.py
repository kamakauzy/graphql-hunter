#!/usr/bin/env python3
"""
Reporter - Formats and displays findings with colored output
"""

from colorama import init, Fore, Back, Style
from typing import Dict, List
import json


# Initialize colorama for Windows support
init(autoreset=True)


class Reporter:
    """Handles output formatting and reporting"""
    
    def __init__(self, use_colors: bool = True, verbose: bool = False):
        """
        Initialize reporter
        
        Args:
            use_colors: Enable colored output
            verbose: Enable verbose output
        """
        self.use_colors = use_colors
        self.verbose = verbose
        
        # Color mappings
        self.colors = {
            'CRITICAL': Fore.RED + Style.BRIGHT,
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.CYAN,
            'INFO': Fore.BLUE,
            'SUCCESS': Fore.GREEN,
            'ERROR': Fore.RED + Style.BRIGHT,
            'WARNING': Fore.YELLOW,
            'DEBUG': Fore.MAGENTA,
        }
    
    def _colorize(self, text: str, color_key: str) -> str:
        """Apply color to text"""
        if not self.use_colors:
            return text
        color = self.colors.get(color_key, '')
        return f"{color}{text}{Style.RESET_ALL}"
    
    def print_banner(self):
        """Print tool banner"""
        banner = """
===============================================================
                                                               
   GRAPHQL HUNTER - Security Scanner v1.0                     
   Comprehensive GraphQL API Security Testing                 
                                                               
===============================================================
        """
        print(self._colorize(banner, 'INFO'))
    
    def print_separator(self):
        """Print separator line"""
        print(self._colorize("-" * 70, 'INFO'))
    
    def print_section_header(self, title: str):
        """Print section header"""
        print("\n" + self._colorize(f"[*] {title}", 'INFO'))
        print(self._colorize("-" * 70, 'INFO'))
    
    def print_info(self, message: str):
        """Print info message"""
        print(self._colorize(f"[i] {message}", 'INFO'))
    
    def print_success(self, message: str):
        """Print success message"""
        print(self._colorize(f"[+] {message}", 'SUCCESS'))
    
    def print_warning(self, message: str):
        """Print warning message"""
        print(self._colorize(f"[!] {message}", 'WARNING'))
    
    def print_error(self, message: str):
        """Print error message"""
        print(self._colorize(f"[-] {message}", 'ERROR'))
    
    def print_debug(self, message: str):
        """Print debug message (only in verbose mode)"""
        if self.verbose:
            print(self._colorize(f"[DEBUG] {message}", 'DEBUG'))
    
    def print_finding(self, finding: Dict):
        """
        Print a security finding
        
        Args:
            finding: Finding dictionary with title, severity, description, etc.
        """
        severity = finding.get('severity', 'INFO')
        title = finding.get('title', 'Unknown')
        description = finding.get('description', '')
        impact = finding.get('impact', '')
        remediation = finding.get('remediation', '')
        evidence = finding.get('evidence', {})
        poc = finding.get('poc', '')
        cwe = finding.get('cwe', '')
        
        # Print title with severity
        severity_label = f"[{severity}]"
        print(f"\n{self._colorize(severity_label, severity)} {self._colorize(title, severity)}")
        
        # Print description
        if description:
            print(f"  Description: {description}")
        
        # Print impact
        if impact:
            print(f"  {self._colorize('Impact:', 'WARNING')} {impact}")
        
        # Print CWE
        if cwe:
            print(f"  CWE: {cwe}")
        
        # Print evidence (in verbose mode)
        if evidence and self.verbose:
            print(f"  {self._colorize('Evidence:', 'DEBUG')}")
            if 'query' in evidence:
                print(f"    Query: {evidence['query'][:200]}...")
            if 'response' in evidence:
                resp_str = json.dumps(evidence['response'], indent=6)[:300]
                print(f"    Response: {resp_str}...")
        
        # Print PoC
        if poc:
            print(f"  {self._colorize('Proof of Concept:', 'INFO')}")
            for line in poc.split('\n'):
                print(f"    {line}")
        
        # Print remediation
        if remediation:
            print(f"  {self._colorize('Remediation:', 'SUCCESS')} {remediation}")
    
    def print_summary(self, findings: List[Dict]):
        """
        Print scan summary
        
        Args:
            findings: List of all findings
        """
        self.print_separator()
        print(self._colorize("\n[*] SCAN SUMMARY", 'INFO'))
        self.print_separator()
        
        # Count by severity
        counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }
        
        for finding in findings:
            severity = finding.get('severity', 'INFO')
            if severity in counts:
                counts[severity] += 1
        
        total = sum(counts.values())
        
        print(f"\nTotal Findings: {total}")
        if counts['CRITICAL'] > 0:
            print(self._colorize(f"  Critical: {counts['CRITICAL']}", 'CRITICAL'))
        if counts['HIGH'] > 0:
            print(self._colorize(f"  High: {counts['HIGH']}", 'HIGH'))
        if counts['MEDIUM'] > 0:
            print(self._colorize(f"  Medium: {counts['MEDIUM']}", 'MEDIUM'))
        if counts['LOW'] > 0:
            print(self._colorize(f"  Low: {counts['LOW']}", 'LOW'))
        if counts['INFO'] > 0:
            print(self._colorize(f"  Info: {counts['INFO']}", 'INFO'))
        
        # Risk assessment
        print()
        if counts['CRITICAL'] > 0:
            print(self._colorize("Overall Risk: CRITICAL - Immediate action required!", 'CRITICAL'))
        elif counts['HIGH'] > 0:
            print(self._colorize("Overall Risk: HIGH - Action required soon", 'HIGH'))
        elif counts['MEDIUM'] > 0:
            print(self._colorize("Overall Risk: MEDIUM - Should be addressed", 'MEDIUM'))
        elif counts['LOW'] > 0:
            print(self._colorize("Overall Risk: LOW - Minor issues found", 'LOW'))
        else:
            print(self._colorize("Overall Risk: MINIMAL - No significant issues", 'SUCCESS'))
        
        print()
    
    def get_summary_stats(self, findings: List[Dict]) -> Dict:
        """
        Get summary statistics
        
        Args:
            findings: List of all findings
            
        Returns:
            Dictionary with summary stats
        """
        counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }
        
        for finding in findings:
            severity = finding.get('severity', 'INFO')
            if severity in counts:
                counts[severity] += 1
        
        return {
            'total': sum(counts.values()),
            'by_severity': counts
        }

