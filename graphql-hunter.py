#!/usr/bin/env python3
"""
GraphQL Hunter - A comprehensive GraphQL security testing tool
"""

import argparse
import sys
import json
from datetime import datetime
from pathlib import Path

# Add lib directory to path
sys.path.insert(0, str(Path(__file__).parent / "lib"))
sys.path.insert(0, str(Path(__file__).parent / "scanners"))

from graphql_client import GraphQLClient
from reporter import Reporter
from introspection_scanner import IntrospectionScanner
from info_disclosure_scanner import InfoDisclosureScanner
from auth_bypass_scanner import AuthBypassScanner
from injection_scanner import InjectionScanner
from dos_scanner import DoSScanner
from batching_scanner import BatchingScanner
from aliasing_scanner import AliasingScanner
from circular_query_scanner import CircularQueryScanner
from mutation_fuzzer import MutationFuzzer


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='GraphQL Hunter - Comprehensive GraphQL Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python graphql-hunter.py -u https://api.example.com/graphql

  # Scan with authentication
  python graphql-hunter.py -u https://api.example.com/graphql -H "Authorization: Bearer TOKEN"

  # Deep scan with output file
  python graphql-hunter.py -u https://api.example.com/graphql -p deep -o results.json

  # Safe mode (skip DoS tests)
  python graphql-hunter.py -u https://api.example.com/graphql --safe-mode

  # Stealth mode with delays
  python graphql-hunter.py -u https://api.example.com/graphql -p stealth --delay 2
        """
    )
    
    # Required arguments
    parser.add_argument('-u', '--url', required=True, help='GraphQL endpoint URL')
    
    # Authentication & Headers
    parser.add_argument('-H', '--header', action='append', dest='headers',
                        help='Custom headers (can be used multiple times). Format: "Key: Value"')
    parser.add_argument('-t', '--token', help='Bearer token for authentication')
    
    # Scan configuration
    parser.add_argument('-p', '--profile', choices=['quick', 'standard', 'deep', 'stealth'],
                        default='standard', help='Scan profile (default: standard)')
    parser.add_argument('--safe-mode', action='store_true',
                        help='Skip potentially destructive DoS tests')
    parser.add_argument('--delay', type=float, default=0,
                        help='Delay between requests in seconds (default: 0)')
    
    # Scanner selection
    parser.add_argument('--skip-introspection', action='store_true',
                        help='Skip introspection scanner')
    parser.add_argument('--skip-info-disclosure', action='store_true',
                        help='Skip information disclosure checks')
    parser.add_argument('--skip-auth', action='store_true',
                        help='Skip authentication/authorization tests')
    parser.add_argument('--skip-injection', action='store_true',
                        help='Skip injection tests')
    parser.add_argument('--skip-dos', action='store_true',
                        help='Skip DoS vector tests')
    parser.add_argument('--skip-batching', action='store_true',
                        help='Skip batching attack tests')
    parser.add_argument('--skip-aliasing', action='store_true',
                        help='Skip aliasing abuse tests')
    parser.add_argument('--skip-circular', action='store_true',
                        help='Skip circular query tests')
    parser.add_argument('--skip-mutation-fuzzing', action='store_true',
                        help='Skip mutation fuzzing')
    
    # Output options
    parser.add_argument('-o', '--output', help='Output JSON file path')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output (show requests/responses)')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    
    # Proxy settings
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    
    return parser.parse_args()


def main():
    """Main entry point"""
    args = parse_args()
    
    # Initialize reporter
    reporter = Reporter(use_colors=not args.no_color, verbose=args.verbose)
    reporter.print_banner()
    
    # Parse custom headers
    custom_headers = {}
    if args.headers:
        for header in args.headers:
            if ':' in header:
                key, value = header.split(':', 1)
                custom_headers[key.strip()] = value.strip()
    
    # Add token if provided
    if args.token:
        custom_headers['Authorization'] = f'Bearer {args.token}'
    
    # Initialize GraphQL client
    try:
        client = GraphQLClient(
            url=args.url,
            headers=custom_headers,
            proxy=args.proxy,
            delay=args.delay,
            verbose=args.verbose
        )
        reporter.print_info(f"Target: {args.url}")
        reporter.print_info(f"Profile: {args.profile}")
        if args.safe_mode:
            reporter.print_info("Safe mode: ENABLED (DoS tests will be limited)")
        reporter.print_separator()
    except Exception as e:
        reporter.print_error(f"Failed to initialize client: {e}")
        return 1
    
    # Configure scan based on profile
    profile_config = get_profile_config(args.profile)
    
    # Apply safe mode
    if args.safe_mode:
        profile_config['enable_dos'] = False
    
    # Store all findings
    all_findings = []
    scan_metadata = {
        'target': args.url,
        'profile': args.profile,
        'safe_mode': args.safe_mode,
        'timestamp': datetime.utcnow().isoformat(),
    }
    
    # Run scanners
    scanners = []
    
    if not args.skip_introspection:
        scanners.append(('Introspection', IntrospectionScanner(client, reporter, profile_config)))
    
    if not args.skip_info_disclosure:
        scanners.append(('Information Disclosure', InfoDisclosureScanner(client, reporter, profile_config)))
    
    if not args.skip_auth:
        scanners.append(('Authentication/Authorization', AuthBypassScanner(client, reporter, profile_config)))
    
    if not args.skip_injection:
        scanners.append(('Injection', InjectionScanner(client, reporter, profile_config)))
    
    if not args.skip_dos and profile_config.get('enable_dos', True):
        scanners.append(('DoS Vectors', DoSScanner(client, reporter, profile_config)))
    
    if not args.skip_batching:
        scanners.append(('Batching Attacks', BatchingScanner(client, reporter, profile_config)))
    
    if not args.skip_aliasing:
        scanners.append(('Aliasing Abuse', AliasingScanner(client, reporter, profile_config)))
    
    if not args.skip_circular:
        scanners.append(('Circular Queries', CircularQueryScanner(client, reporter, profile_config)))
    
    if not args.skip_mutation_fuzzing:
        scanners.append(('Mutation Fuzzing', MutationFuzzer(client, reporter, profile_config)))
    
    # Execute scanners
    for scanner_name, scanner in scanners:
        reporter.print_section_header(scanner_name)
        try:
            findings = scanner.scan()
            all_findings.extend(findings)
            
            if findings:
                for finding in findings:
                    reporter.print_finding(finding)
            else:
                reporter.print_success("No issues found")
        except Exception as e:
            reporter.print_error(f"Scanner error: {e}")
            if args.verbose:
                import traceback
                reporter.print_debug(traceback.format_exc())
        
        reporter.print_separator()
    
    # Print summary
    reporter.print_summary(all_findings)
    
    # Save to JSON if requested
    if args.output:
        try:
            output_data = {
                'metadata': scan_metadata,
                'findings': all_findings,
                'summary': reporter.get_summary_stats(all_findings)
            }
            with open(args.output, 'w') as f:
                json.dump(output_data, f, indent=2)
            reporter.print_success(f"Results saved to {args.output}")
        except Exception as e:
            reporter.print_error(f"Failed to save output: {e}")
    
    # Return exit code based on findings
    critical_count = sum(1 for f in all_findings if f.get('severity') == 'CRITICAL')
    high_count = sum(1 for f in all_findings if f.get('severity') == 'HIGH')
    
    if critical_count > 0:
        return 2
    elif high_count > 0:
        return 1
    return 0


def get_profile_config(profile):
    """Get configuration for scan profile"""
    configs = {
        'quick': {
            'depth_limit': 3,
            'field_limit': 10,
            'enable_dos': False,
            'enable_deep_injection': False,
            'batch_size': 5,
        },
        'standard': {
            'depth_limit': 5,
            'field_limit': 20,
            'enable_dos': True,
            'enable_deep_injection': True,
            'batch_size': 10,
        },
        'deep': {
            'depth_limit': 10,
            'field_limit': 50,
            'enable_dos': True,
            'enable_deep_injection': True,
            'batch_size': 20,
        },
        'stealth': {
            'depth_limit': 3,
            'field_limit': 10,
            'enable_dos': False,
            'enable_deep_injection': False,
            'batch_size': 3,
        }
    }
    return configs.get(profile, configs['standard'])


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        sys.exit(1)

