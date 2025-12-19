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
from html_reporter import HTMLReporter
from introspection_scanner import IntrospectionScanner
from info_disclosure_scanner import InfoDisclosureScanner
from auth_bypass_scanner import AuthBypassScanner
from injection_scanner import InjectionScanner
from dos_scanner import DoSScanner
from batching_scanner import BatchingScanner
from aliasing_scanner import AliasingScanner
from circular_query_scanner import CircularQueryScanner
from mutation_fuzzer import MutationFuzzer
from xss_scanner import XSSScanner
from jwt_scanner import JWTScanner

from auth.manager import AuthManager
from auth.wizard import run_auth_wizard

# Import request importer
try:
    from request_importer import RequestImporter
except ImportError:
    # Fallback if not in path
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent / "lib"))
    from request_importer import RequestImporter

# Import auto-discovery
try:
    from lib.auto_discover import AutoDiscover
except ImportError:
    try:
        from auto_discover import AutoDiscover
    except ImportError:
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent / "lib"))
        from auto_discover import AutoDiscover

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
    
    # Target
    # Note: enforced in main() so --auth-wizard can run without -u.
    parser.add_argument('-u', '--url', required=False, help='GraphQL endpoint URL')
    
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
    parser.add_argument('--skip-xss', action='store_true',
                        help='Skip XSS tests')
    parser.add_argument('--skip-jwt', action='store_true',
                        help='Skip JWT security tests')
    
    # Output options
    parser.add_argument('-o', '--output', help='Output JSON file path')
    parser.add_argument('--html', help='Output HTML report file path')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output (show requests/responses)')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    
    # Proxy settings
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')

    # Auth workflow engine
    parser.add_argument('--auth-config', default=str(Path(__file__).parent / "config" / "auth.yaml"),
                        help='Auth config YAML path (default: config/auth.yaml)')
    parser.add_argument('--auth-profile', help='Auth profile name from auth config')
    parser.add_argument('--auth-var', action='append', dest='auth_vars',
                        help='Auth variable override KEY=VALUE (can be used multiple times)')
    parser.add_argument('--auth-detect', action='store_true', dest='auth_detect',
                        help='Enable best-effort auth/CSRF diagnostics (default)')
    parser.add_argument('--no-auth-detect', action='store_false', dest='auth_detect',
                        help='Disable best-effort auth/CSRF diagnostics')
    parser.set_defaults(auth_detect=True)
    parser.add_argument('--auth-wizard', action='store_true',
                        help='Interactive auth wizard (prints a ready-to-run command without exposing secrets)')
    parser.add_argument('--validate-auth', action='store_true',
                        help='Validate authentication before scanning by comparing responses with/without auth')
    parser.add_argument('--auth-test-query', help='Custom GraphQL query/mutation to use for auth validation')
    parser.add_argument('--auth-test-variables', help='JSON string of variables for auth test query')
    
    # Request import options
    parser.add_argument('--import', '--import-request', dest='import_file',
                        help='Import request from file (Postman collection, JSON, YAML, or cURL command file)')
    parser.add_argument('--import-curl', help='Import request from cURL command string')
    parser.add_argument('--import-raw-http', help='Import request from raw HTTP request string')
    parser.add_argument('--list-imported', action='store_true',
                        help='List all requests from imported collection and exit')
    
    # Auto-discovery
    parser.add_argument('--auto-discover', nargs='+', metavar='FILE_OR_TEXT',
                        help='Auto-discover authentication and config from notes, JSON, YAML files, or text. Can provide multiple sources.')
    parser.add_argument('--discover-notes', help='Auto-discover from text notes (same as --auto-discover with text)')
    parser.add_argument('--show-discovery', action='store_true',
                        help='Show discovered configuration and exit (use with --auto-discover)')
    
    return parser.parse_args()


def main():
    """Main entry point"""
    args = parse_args()
    
    # Initialize reporter
    reporter = Reporter(use_colors=not args.no_color, verbose=args.verbose)
    reporter.print_banner()

    # Wizard mode: run before requiring URL
    if getattr(args, "auth_wizard", False):
        return run_auth_wizard(args, reporter=reporter)
    
    # Auto-discovery mode
    if args.auto_discover or args.discover_notes:
        reporter.print_separator()
        reporter.print_section_header("Auto-Discovery")
        
        sources = args.auto_discover or []
        if args.discover_notes:
            sources.append(args.discover_notes)
        
        try:
            discoverer = AutoDiscover()
            results = discoverer.auto_discover(sources)
            
            reporter.print_info("Analyzing provided sources...")
            reporter.print_separator()
            
            # Display discoveries
            if results.get('url'):
                reporter.print_success(f"Discovered URL: {results['url']}")
            
            if results.get('auth_method'):
                reporter.print_success(f"Detected Auth Method: {results['auth_method']}")
            
            if results.get('credentials'):
                reporter.print_info("Discovered Credentials:")
                for key, value in results['credentials'].items():
                    if key == 'password':
                        reporter.print_info(f"  {key}: {'*' * len(str(value))}")
                    else:
                        reporter.print_info(f"  {key}: {value}")
            
            if results.get('tokens'):
                reporter.print_info("Discovered Tokens:")
                for key in results['tokens']:
                    token = results['tokens'][key]
                    reporter.print_info(f"  {key}: {token[:30]}...")
            
            if results.get('headers'):
                reporter.print_info("Discovered Headers:")
                for key, value in results['headers'].items():
                    if 'token' in key.lower() or 'auth' in key.lower():
                        reporter.print_info(f"  {key}: {value[:30]}...")
                    else:
                        reporter.print_info(f"  {key}: {value}")
            
            if results.get('queries'):
                reporter.print_info(f"Discovered {len(results['queries'])} queries")
            
            if results.get('mutations'):
                reporter.print_info(f"Discovered {len(results['mutations'])} mutations")
            
            # Show recommendations
            if results.get('recommendations'):
                recs = results['recommendations']
                reporter.print_separator()
                reporter.print_section_header("Recommendations")
                
                if recs.get('command'):
                    reporter.print_info("Ready-to-run command:")
                    # Print command in a readable format
                    cmd_lines = recs['command'].split(' \\\n  ')
                    for i, line in enumerate(cmd_lines):
                        if i == 0:
                            reporter.print_debug(line)
                        else:
                            reporter.print_debug(f"  {line}")
                    
                    # Also show simple one-liner
                    if recs.get('command_simple'):
                        reporter.print_info("\nOr as a single command:")
                        reporter.print_debug(recs['command_simple'])
                
                if recs.get('auth_profile'):
                    reporter.print_info(f"\nSuggested auth profile: {recs['auth_profile']}")
                    
                    # Generate auth profile if needed
                    if recs.get('auth_profile') == 'token_auth':
                        profile = discoverer.generate_auth_profile()
                        if profile:
                            reporter.print_info("\nGenerated auth profile (add to config/auth.yaml):")
                            import yaml
                            profile_yaml = yaml.dump({'profiles': {'auto_discovered': profile}}, default_flow_style=False)
                            reporter.print_debug(profile_yaml)
            
            # If --show-discovery, exit here
            if args.show_discovery:
                return 0
            
            # Apply discoveries to args if URL not provided
            if not args.url and results.get('url'):
                args.url = results['url']
                reporter.print_info(f"Using discovered URL: {args.url}")
            
            # Apply auth profile if credentials found
            if not args.auth_profile and results.get('recommendations', {}).get('auth_profile'):
                args.auth_profile = results['recommendations']['auth_profile']
                reporter.print_info(f"Using discovered auth profile: {args.auth_profile}")
                
                # Set auth vars
                if not args.auth_vars:
                    args.auth_vars = []
                for var_str in results['recommendations'].get('auth_vars', []):
                    if var_str not in args.auth_vars:
                        args.auth_vars.append(var_str)
            
            # Apply headers if found
            if results.get('headers'):
                if not args.headers:
                    args.headers = []
                for key, value in results['headers'].items():
                    header_str = f"{key}: {value}"
                    if header_str not in args.headers:
                        args.headers.append(header_str)
            
            reporter.print_separator()
            
        except Exception as e:
            reporter.print_error(f"Auto-discovery failed: {e}")
            if args.verbose:
                import traceback
                reporter.print_debug(traceback.format_exc())
            return 1
    
    # Handle request import
    imported_requests = []
    if args.import_file:
        try:
            reporter.print_info(f"Importing requests from: {args.import_file}")
            imported = RequestImporter.auto_detect_and_import(args.import_file)
            if isinstance(imported, list):
                imported_requests = imported
                reporter.print_success(f"Imported {len(imported_requests)} requests from Postman collection")
            else:
                imported_requests = [imported]
                reporter.print_success("Imported request from file")
        except Exception as e:
            reporter.print_error(f"Failed to import requests: {e}")
            if args.verbose:
                import traceback
                reporter.print_debug(traceback.format_exc())
            return 1
    
    if args.import_curl:
        try:
            reporter.print_info("Importing request from cURL command")
            imported_requests = [RequestImporter.from_curl_command(args.import_curl)]
            reporter.print_success("Imported request from cURL")
        except Exception as e:
            reporter.print_error(f"Failed to import cURL command: {e}")
            return 1
    
    if args.import_raw_http:
        try:
            reporter.print_info("Importing request from raw HTTP")
            imported_requests = [RequestImporter.from_raw_http(args.import_raw_http)]
            reporter.print_success("Imported request from raw HTTP")
        except Exception as e:
            reporter.print_error(f"Failed to import raw HTTP: {e}")
            return 1
    
    # List imported requests and exit
    if args.list_imported:
        if not imported_requests:
            reporter.print_error("No requests imported. Use --import to import requests first.")
            return 1
        
        reporter.print_separator()
        reporter.print_section_header("Imported Requests")
        for i, req in enumerate(imported_requests, 1):
            folder = f" ({req.get('folder')})" if req.get('folder') else ""
            reporter.print_info(f"{i}. {req.get('name', 'Unnamed')}{folder}")
            reporter.print_info(f"   URL: {req.get('url', 'N/A')}")
            reporter.print_info(f"   Method: {req.get('method', 'POST')}")
            if req.get('operation_name'):
                reporter.print_info(f"   Operation: {req.get('operation_name')}")
            reporter.print_separator()
        return 0
    
    # Use imported request if no URL provided
    if imported_requests and not args.url:
        if len(imported_requests) == 1:
            req = imported_requests[0]
            args.url = req.get('url')
            # Merge headers
            if not args.headers:
                args.headers = []
            for key, value in req.get('headers', {}).items():
                args.headers.append(f"{key}: {value}")
            # Set query for auth validation if provided
            if req.get('query') and not args.auth_test_query:
                args.auth_test_query = req.get('query')
                if req.get('variables'):
                    args.auth_test_variables = json.dumps(req.get('variables'))
            reporter.print_info(f"Using imported request: {req.get('name', 'Unnamed')}")
        else:
            reporter.print_error(f"Multiple requests imported ({len(imported_requests)}). Please specify URL with -u or use --list-imported to see available requests.")
            return 1

    if not args.url:
        reporter.print_error("Missing required argument: -u/--url")
        reporter.print_info("Run: python graphql-hunter.py --help")
        reporter.print_info("Or use: python graphql-hunter.py --auth-wizard")
        return 1
    
    # Parse custom headers
    custom_headers = {}
    if args.headers:
        for header in args.headers:
            if ':' in header:
                key, value = header.split(':', 1)
                custom_headers[key.strip()] = value.strip()

    # Initialize auth manager (maps -t/-H when no profile is specified)
    auth_manager = AuthManager.from_cli_args(args, reporter=reporter)
    auth_manager.select_provider(token=args.token, headers=custom_headers)
    
    # Initialize GraphQL client
    try:
        client = GraphQLClient(
            url=args.url,
            headers=custom_headers,
            proxy=args.proxy,
            delay=args.delay,
            verbose=args.verbose,
            auth_manager=auth_manager
        )
        reporter.print_info(f"Target: {args.url}")
        reporter.print_info(f"Profile: {args.profile}")
        if args.safe_mode:
            reporter.print_info("Safe mode: ENABLED (DoS tests will be limited)")
        
        # Validate authentication if requested
        if args.validate_auth:
            reporter.print_separator()
            reporter.print_section_header("Authentication Validation")
            try:
                test_query = args.auth_test_query
                test_variables = None
                if args.auth_test_variables:
                    try:
                        test_variables = json.loads(args.auth_test_variables)
                    except json.JSONDecodeError:
                        reporter.print_error(f"Invalid JSON in --auth-test-variables: {args.auth_test_variables}")
                        test_variables = None
                
                validation_result = client.validate_auth(test_query=test_query, test_variables=test_variables)
                
                reporter.print_info("Testing authentication...")
                reporter.print_info(f"  Status with auth: {validation_result['status_with_auth']}")
                reporter.print_info(f"  Status without auth: {validation_result['status_without_auth']}")
                reporter.print_separator()
                
                if validation_result['auth_working']:
                    reporter.print_success("[OK] Authentication is WORKING")
                elif validation_result['auth_required']:
                    reporter.print_error("[FAIL] Authentication is REQUIRED but may not be working correctly")
                else:
                    reporter.print_warning("[WARN] Authentication may NOT be required for this endpoint")
                
                reporter.print_info(f"Analysis: {validation_result['analysis']}")
                
                if args.verbose:
                    reporter.print_info("\nResponse with auth:")
                    reporter.print_debug(json.dumps(validation_result['response_with_auth'], indent=2))
                    reporter.print_info("\nResponse without auth:")
                    reporter.print_debug(json.dumps(validation_result['response_without_auth'], indent=2))
                
                reporter.print_separator()
            except Exception as e:
                reporter.print_error(f"Auth validation failed: {e}")
                if args.verbose:
                    import traceback
                    reporter.print_debug(traceback.format_exc())
        
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
    
    if not args.skip_xss:
        scanners.append(('Cross-Site Scripting (XSS)', XSSScanner(client, reporter, profile_config)))
    
    if not args.skip_jwt:
        scanners.append(('JWT Security', JWTScanner(client, reporter, profile_config)))
    
    # Execute scanners
    for scanner_name, scanner in scanners:
        reporter.print_section_header(scanner_name)
        try:
            findings = scanner.scan()
            # Sanitize findings to avoid leaking secrets in output/report files
            safe_findings = []
            if findings:
                for f in findings:
                    try:
                        safe_findings.append(auth_manager.sanitize_finding(f))
                    except Exception:
                        safe_findings.append(f)
            all_findings.extend(safe_findings)
            
            if safe_findings:
                for finding in safe_findings:
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
            reporter.print_success(f"JSON report saved to {args.output}")
        except Exception as e:
            reporter.print_error(f"Failed to save JSON: {e}")
    
    # Save to HTML if requested
    if args.html:
        try:
            output_data = {
                'metadata': scan_metadata,
                'findings': all_findings,
                'summary': reporter.get_summary_stats(all_findings)
            }
            HTMLReporter.generate(
                output_data['metadata'],
                output_data['findings'],
                output_data['summary'],
                args.html
            )
            reporter.print_success(f"HTML report saved to {args.html}")
        except Exception as e:
            reporter.print_error(f"Failed to save HTML: {e}")
    
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

