#!/usr/bin/env python3
"""
GraphQL Hunter - A comprehensive GraphQL security testing tool
"""

import argparse
import sys
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).parent
LIB_DIR = ROOT / "lib"
SCANNERS_DIR = ROOT / "scanners"

# Add lib/scanner directories to path lazily-friendly before runtime imports.
sys.path.insert(0, str(LIB_DIR))
sys.path.insert(0, str(SCANNERS_DIR))

DEFAULT_PROFILE_CONFIGS = {
    'quick': {
        'depth_limit': 3,
        'field_limit': 10,
        'enable_dos': False,
        'enable_deep_injection': False,
        'enable_rate_limit_testing': False,
        'enable_csrf_testing': True,
        'enable_file_upload_testing': True,
        'batch_size': 5,
        'brute_force_attempts': 10,
        'rate_limit_concurrency': 25,
        'rate_limit_requests': 50,
        'max_xss_tests': 10,
        'timeout': 10,
    },
    'standard': {
        'depth_limit': 5,
        'field_limit': 20,
        'enable_dos': True,
        'enable_deep_injection': True,
        'enable_rate_limit_testing': True,
        'enable_csrf_testing': True,
        'enable_file_upload_testing': True,
        'batch_size': 10,
        'brute_force_attempts': 20,
        'rate_limit_concurrency': 50,
        'rate_limit_requests': 100,
        'max_xss_tests': 20,
        'timeout': 30,
    },
    'deep': {
        'depth_limit': 10,
        'field_limit': 50,
        'enable_dos': True,
        'enable_deep_injection': True,
        'enable_rate_limit_testing': True,
        'enable_csrf_testing': True,
        'enable_file_upload_testing': True,
        'batch_size': 20,
        'brute_force_attempts': 30,
        'rate_limit_concurrency': 75,
        'rate_limit_requests': 150,
        'max_xss_tests': 30,
        'timeout': 60,
    },
    'stealth': {
        'depth_limit': 3,
        'field_limit': 10,
        'enable_dos': False,
        'enable_deep_injection': False,
        'enable_rate_limit_testing': False,
        'enable_csrf_testing': True,
        'enable_file_upload_testing': True,
        'batch_size': 3,
        'brute_force_attempts': 5,
        'rate_limit_concurrency': 10,
        'rate_limit_requests': 20,
        'max_xss_tests': 5,
        'timeout': 30,
        'delay': 1.0,
    },
}


def _print_dependency_error(exc: Exception) -> None:
    missing = getattr(exc, "name", None) or str(exc)
    print(f"[!] Missing runtime dependency: {missing}")
    print("[!] Install dependencies with: python3 -m pip install -r requirements.txt")


def _build_reporter(args):
    """Build reporter lazily so --help can work without optional deps."""
    try:
        from reporter import Reporter
        return Reporter(use_colors=not args.no_color, verbose=args.verbose), None
    except ModuleNotFoundError as exc:
        return None, exc


def _import_wizard():
    from auth.wizard import run_auth_wizard
    return run_auth_wizard


def _import_runtime_components():
    from graphql_client import GraphQLClient
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
    from rate_limiting_scanner import RateLimitingScanner
    from csrf_scanner import CSRFScanner
    from file_upload_scanner import FileUploadScanner
    from auth.manager import AuthManager
    from request_importer import RequestImporter
    from auto_discover import AutoDiscover

    return {
        'GraphQLClient': GraphQLClient,
        'HTMLReporter': HTMLReporter,
        'IntrospectionScanner': IntrospectionScanner,
        'InfoDisclosureScanner': InfoDisclosureScanner,
        'AuthBypassScanner': AuthBypassScanner,
        'InjectionScanner': InjectionScanner,
        'DoSScanner': DoSScanner,
        'BatchingScanner': BatchingScanner,
        'AliasingScanner': AliasingScanner,
        'CircularQueryScanner': CircularQueryScanner,
        'MutationFuzzer': MutationFuzzer,
        'XSSScanner': XSSScanner,
        'JWTScanner': JWTScanner,
        'RateLimitingScanner': RateLimitingScanner,
        'CSRFScanner': CSRFScanner,
        'FileUploadScanner': FileUploadScanner,
        'AuthManager': AuthManager,
        'RequestImporter': RequestImporter,
        'AutoDiscover': AutoDiscover,
    }


def _parse_headers(headers_list):
    """Parse repeated header args into a dictionary."""
    custom_headers = {}
    for header in headers_list or []:
        if ':' not in header:
            continue
        key, value = header.split(':', 1)
        custom_headers[key.strip()] = value.strip()
    return custom_headers


def _merge_headers(base_headers, new_headers):
    """Merge headers while preserving existing explicit values."""
    for key, value in (new_headers or {}).items():
        base_headers.setdefault(key, value)
    return base_headers


def determine_exit_code(summary: Dict[str, Any]) -> int:
    """Return exit code based on confirmed severities only."""
    confirmed_counts = (summary or {}).get('confirmed_by_severity', {})
    if confirmed_counts.get('CRITICAL', 0) > 0:
        return 2
    if confirmed_counts.get('HIGH', 0) > 0:
        return 1
    return 0

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='GraphQL Hunter - Comprehensive GraphQL Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  gqlh -u https://api.example.com/graphql

  # Scan with authentication
  gqlh -u https://api.example.com/graphql -H "Authorization: Bearer TOKEN"

  # Deep scan with output file
  gqlh -u https://api.example.com/graphql -p deep -o results.json

  # Safe mode (skip DoS tests)
  gqlh -u https://api.example.com/graphql --safe-mode

  # Stealth mode with delays
  gqlh -u https://api.example.com/graphql -p stealth --delay 2
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
    parser.add_argument('--delay', type=float, default=None,
                        help='Delay between requests in seconds (defaults to profile setting)')
    
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
    parser.add_argument('--skip-rate-limit', action='store_true',
                        help='Skip rate limiting tests')
    parser.add_argument('--skip-csrf', action='store_true',
                        help='Skip CSRF tests')
    parser.add_argument('--skip-file-upload', action='store_true',
                        help='Skip file upload tests')
    parser.add_argument('--brute-force-attempts', type=int, default=None,
                        help='Number of brute-force attempts for login testing (defaults to profile setting)')
    parser.add_argument('--rate-limit-concurrency', type=int, default=None,
                        help='Number of concurrent workers for rate limit testing (defaults to profile setting)')
    parser.add_argument('--rate-limit-requests', type=int, default=None,
                        help='Total number of requests to send during rate limit testing (defaults to profile setting)')
    
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
    reporter, reporter_import_error = _build_reporter(args)
    if reporter:
        reporter.print_banner()

    # Wizard mode: run before requiring the full runtime stack.
    if getattr(args, "auth_wizard", False):
        try:
            run_auth_wizard = _import_wizard()
            return run_auth_wizard(args, reporter=reporter)
        except ModuleNotFoundError as exc:
            _print_dependency_error(exc)
            return 1

    if reporter_import_error:
        _print_dependency_error(reporter_import_error)
        return 1

    try:
        runtime = _import_runtime_components()
    except ModuleNotFoundError as exc:
        _print_dependency_error(exc)
        return 1

    GraphQLClient = runtime['GraphQLClient']
    HTMLReporter = runtime['HTMLReporter']
    IntrospectionScanner = runtime['IntrospectionScanner']
    InfoDisclosureScanner = runtime['InfoDisclosureScanner']
    AuthBypassScanner = runtime['AuthBypassScanner']
    InjectionScanner = runtime['InjectionScanner']
    DoSScanner = runtime['DoSScanner']
    BatchingScanner = runtime['BatchingScanner']
    AliasingScanner = runtime['AliasingScanner']
    CircularQueryScanner = runtime['CircularQueryScanner']
    MutationFuzzer = runtime['MutationFuzzer']
    XSSScanner = runtime['XSSScanner']
    JWTScanner = runtime['JWTScanner']
    RateLimitingScanner = runtime['RateLimitingScanner']
    CSRFScanner = runtime['CSRFScanner']
    FileUploadScanner = runtime['FileUploadScanner']
    AuthManager = runtime['AuthManager']
    RequestImporter = runtime['RequestImporter']
    AutoDiscover = runtime['AutoDiscover']

    profile_config = get_profile_config(args.profile)
    if args.delay is None:
        args.delay = profile_config.get('delay', 0)
    if args.brute_force_attempts is None:
        args.brute_force_attempts = profile_config.get('brute_force_attempts', 20)
    if args.rate_limit_concurrency is None:
        args.rate_limit_concurrency = profile_config.get('rate_limit_concurrency', 50)
    if args.rate_limit_requests is None:
        args.rate_limit_requests = profile_config.get('rate_limit_requests', 100)

    custom_headers = _parse_headers(args.headers)

    # Auto-discovery mode
    if args.auto_discover or args.discover_notes:
        reporter.print_separator()
        reporter.print_section_header("Auto-Discovery")

        sources = list(args.auto_discover or [])
        if args.discover_notes:
            sources.append(args.discover_notes)

        try:
            discoverer = AutoDiscover()
            results = discoverer.auto_discover(sources)

            reporter.print_info("Analyzing provided sources...")
            reporter.print_separator()

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
                for key, token in results['tokens'].items():
                    reporter.print_info(f"  {key}: {str(token)[:30]}...")

            if results.get('headers'):
                reporter.print_info("Discovered Headers:")
                for key, value in results['headers'].items():
                    if 'token' in key.lower() or 'auth' in key.lower():
                        reporter.print_info(f"  {key}: {str(value)[:30]}...")
                    else:
                        reporter.print_info(f"  {key}: {value}")

            if results.get('queries'):
                reporter.print_info(f"Discovered {len(results['queries'])} queries")

            if results.get('mutations'):
                reporter.print_info(f"Discovered {len(results['mutations'])} mutations")

            if results.get('recommendations'):
                recs = results['recommendations']
                reporter.print_separator()
                reporter.print_section_header("Recommendations")

                if recs.get('command'):
                    reporter.print_info("Ready-to-run command:")
                    for i, line in enumerate(recs['command'].split(' \\\n  ')):
                        reporter.print_plain(line if i == 0 else f"  {line}")

                    if recs.get('command_simple'):
                        reporter.print_info("\nOr as a single command:")
                        reporter.print_plain(recs['command_simple'])

                if recs.get('auth_profile'):
                    reporter.print_info(f"\nSuggested auth profile: {recs['auth_profile']}")
                    if recs.get('auth_profile') == 'token_auth':
                        profile = discoverer.generate_auth_profile()
                        if profile:
                            import yaml
                            reporter.print_info("\nGenerated auth profile (add to config/auth.yaml):")
                            reporter.print_plain(
                                yaml.dump({'profiles': {'auto_discovered': profile}}, default_flow_style=False)
                            )

            if args.show_discovery:
                return 0

            if not args.url and results.get('url'):
                args.url = results['url']
                reporter.print_info(f"Using discovered URL: {args.url}")

            if not args.auth_profile and results.get('recommendations', {}).get('auth_profile'):
                args.auth_profile = results['recommendations']['auth_profile']
                reporter.print_info(f"Using discovered auth profile: {args.auth_profile}")

                if not args.auth_vars:
                    args.auth_vars = []
                for var_str in results['recommendations'].get('auth_vars', []):
                    if var_str not in args.auth_vars:
                        args.auth_vars.append(var_str)

            _merge_headers(custom_headers, results.get('headers') or {})
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

    if imported_requests:
        if len(imported_requests) == 1:
            req = imported_requests[0]
            if not args.url:
                args.url = req.get('url')
            _merge_headers(custom_headers, req.get('headers', {}))
            if req.get('query') and not args.auth_test_query:
                args.auth_test_query = req.get('query')
                if req.get('variables') is not None:
                    args.auth_test_variables = json.dumps(req.get('variables'))
            reporter.print_info(f"Using imported request: {req.get('name', 'Unnamed')}")
        elif not args.url:
            reporter.print_error(f"Multiple requests imported ({len(imported_requests)}). Please specify URL with -u or use --list-imported to see available requests.")
            return 1

    if not args.url:
        reporter.print_error("Missing required argument: -u/--url")
        reporter.print_info("Run: gqlh --help")
        reporter.print_info("Or use: gqlh --auth-wizard")
        return 1

    auth_manager = AuthManager.from_cli_args(args, reporter=reporter)
    auth_manager.select_provider(token=args.token, headers=custom_headers)

    try:
        client = GraphQLClient(
            url=args.url,
            headers=custom_headers,
            proxy=args.proxy,
            delay=args.delay or 0,
            verbose=args.verbose,
            timeout=profile_config.get('timeout', 30),
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

    # Apply CLI/runtime arguments to config
    profile_config['profile_name'] = args.profile
    profile_config['safe_mode'] = args.safe_mode
    profile_config['delay'] = args.delay or 0
    profile_config['timeout'] = profile_config.get('timeout', 30)
    profile_config['brute_force_attempts'] = args.brute_force_attempts
    profile_config['rate_limit_concurrency'] = args.rate_limit_concurrency
    profile_config['rate_limit_requests'] = args.rate_limit_requests
    profile_config['max_xss_tests'] = profile_config.get('max_xss_tests', 20)
    
    # Apply safe mode
    if args.safe_mode:
        profile_config['enable_dos'] = False
        profile_config['enable_rate_limit_testing'] = False
        profile_config['brute_force_attempts'] = 5  # Reduce brute-force attempts in safe mode
    
    # Store all findings
    all_findings = []
    failed_scanners = []

    scan_plan = [
        ('introspection', 'Introspection', lambda: IntrospectionScanner(client, reporter, profile_config), not args.skip_introspection, 'disabled by --skip-introspection'),
        ('info_disclosure', 'Information Disclosure', lambda: InfoDisclosureScanner(client, reporter, profile_config), not args.skip_info_disclosure, 'disabled by --skip-info-disclosure'),
        ('auth', 'Authentication/Authorization', lambda: AuthBypassScanner(client, reporter, profile_config), not args.skip_auth, 'disabled by --skip-auth'),
        ('injection', 'Injection', lambda: InjectionScanner(client, reporter, profile_config), not args.skip_injection, 'disabled by --skip-injection'),
        ('dos', 'DoS Vectors', lambda: DoSScanner(client, reporter, profile_config), (not args.skip_dos and profile_config.get('enable_dos', True)), 'disabled by --skip-dos or profile'),
        ('batching', 'Batching Attacks', lambda: BatchingScanner(client, reporter, profile_config), not args.skip_batching, 'disabled by --skip-batching'),
        ('aliasing', 'Aliasing Abuse', lambda: AliasingScanner(client, reporter, profile_config), not args.skip_aliasing, 'disabled by --skip-aliasing'),
        ('circular', 'Circular Queries', lambda: CircularQueryScanner(client, reporter, profile_config), not args.skip_circular, 'disabled by --skip-circular'),
        ('mutation_fuzzing', 'Mutation Fuzzing', lambda: MutationFuzzer(client, reporter, profile_config), not args.skip_mutation_fuzzing, 'disabled by --skip-mutation-fuzzing'),
        ('xss', 'Cross-Site Scripting (XSS)', lambda: XSSScanner(client, reporter, profile_config), not args.skip_xss, 'disabled by --skip-xss'),
        ('jwt', 'JWT Security', lambda: JWTScanner(client, reporter, profile_config), not args.skip_jwt, 'disabled by --skip-jwt'),
        ('rate_limit', 'Rate Limiting', lambda: RateLimitingScanner(client, reporter, profile_config), (not args.skip_rate_limit and profile_config.get('enable_rate_limit_testing', True)), 'disabled by --skip-rate-limit or profile'),
        ('csrf', 'CSRF Protection', lambda: CSRFScanner(client, reporter, profile_config), (not args.skip_csrf and profile_config.get('enable_csrf_testing', True)), 'disabled by --skip-csrf or profile'),
        ('file_upload', 'File Upload', lambda: FileUploadScanner(client, reporter, profile_config), (not args.skip_file_upload and profile_config.get('enable_file_upload_testing', True)), 'disabled by --skip-file-upload or profile'),
    ]

    scanners = [(display_name, factory()) for _, display_name, factory, enabled, _ in scan_plan if enabled]
    executed_scanners = [display_name for _, display_name, _, enabled, _ in scan_plan if enabled]
    skipped_scanners = [
        {'scanner': display_name, 'reason': reason}
        for _, display_name, _, enabled, reason in scan_plan if not enabled
    ]

    scan_metadata = {
        'target': args.url,
        'profile': args.profile,
        'safe_mode': args.safe_mode,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'status': 'running',
        'executed_scanners': executed_scanners,
        'skipped_scanners': skipped_scanners,
    }
    
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
            failed_scanners.append({'scanner': scanner_name, 'error': str(e)})
            if args.verbose:
                import traceback
                reporter.print_debug(traceback.format_exc())
        
        reporter.print_separator()
    
    # Print summary
    scan_metadata['status'] = 'partial' if failed_scanners else 'completed'
    scan_metadata['failed_scanners'] = failed_scanners
    summary = reporter.get_summary_stats(all_findings)
    reporter.print_summary(all_findings, scan_info=scan_metadata)
    
    # Save to JSON if requested
    if args.output:
        try:
            output_data = {
                'metadata': scan_metadata,
                'scan': {
                    'status': scan_metadata['status'],
                    'executed_scanners': executed_scanners,
                    'skipped_scanners': skipped_scanners,
                    'failed_scanners': failed_scanners,
                },
                'findings': all_findings,
                'summary': summary,
                'errors': failed_scanners,
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
                'scan': {
                    'status': scan_metadata['status'],
                    'executed_scanners': executed_scanners,
                    'skipped_scanners': skipped_scanners,
                    'failed_scanners': failed_scanners,
                },
                'findings': all_findings,
                'summary': summary,
                'errors': failed_scanners,
            }
            HTMLReporter.generate(
                output_data['metadata'],
                output_data['findings'],
                output_data['summary'],
                args.html,
                scan_info=output_data['scan']
            )
            reporter.print_success(f"HTML report saved to {args.html}")
        except Exception as e:
            reporter.print_error(f"Failed to save HTML: {e}")
    
    return determine_exit_code(summary)


def get_profile_config(profile):
    """Get configuration for scan profile, preferring config/payloads.yaml."""
    config_path = ROOT / "config" / "payloads.yaml"

    try:
        import yaml

        with open(config_path, 'r', encoding='utf-8') as handle:
            payload_config = yaml.safe_load(handle) or {}
        profiles = payload_config.get('profiles') or {}
        if isinstance(profiles.get(profile), dict):
            merged = dict(DEFAULT_PROFILE_CONFIGS.get('standard', {}))
            merged.update(profiles[profile])
            return merged
    except Exception:
        pass

    return dict(DEFAULT_PROFILE_CONFIGS.get(profile, DEFAULT_PROFILE_CONFIGS['standard']))


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        sys.exit(1)

