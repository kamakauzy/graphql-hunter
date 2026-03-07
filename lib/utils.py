#!/usr/bin/env python3
"""
Utility functions for GraphQL Hunter
"""

import json
import re
import shlex
from typing import Any, Dict, List, Optional


GRAPHQL_SCALARS = {'String', 'Int', 'Float', 'Boolean', 'ID'}


def extract_type_name(type_def: Dict) -> str:
    """
    Extract the actual type name from a type definition

    Args:
        type_def: Type definition from GraphQL schema

    Returns:
        Type name as string
    """
    if not type_def:
        return "Unknown"

    if type_def.get('name'):
        return type_def['name']

    if type_def.get('ofType'):
        return extract_type_name(type_def['ofType'])

    return "Unknown"


def type_signature(type_def: Dict) -> str:
    """Preserve GraphQL list/non-null wrappers when rendering a type."""
    if not type_def:
        return "String"

    kind = type_def.get('kind')
    name = type_def.get('name')
    nested = type_def.get('ofType')

    if kind == 'NON_NULL':
        return f"{type_signature(nested)}!"
    if kind == 'LIST':
        return f"[{type_signature(nested)}]"
    if name:
        return name
    if nested:
        return type_signature(nested)
    return "String"


def is_scalar_type(type_name: str) -> bool:
    """Check if type is a scalar type."""
    return type_name in GRAPHQL_SCALARS


def build_query_for_field(field: Dict, depth: int = 1, max_depth: int = 3) -> str:
    """
    Build a simple query for a field.

    This helper remains for backward compatibility; newer code should prefer
    schema-aware builders in `lib.introspection`.
    """
    if depth > max_depth:
        return ""

    field_name = field.get('name', '')
    args = field.get('args', [])

    arg_strings = []
    for arg in args:
        arg_name = arg.get('name')
        arg_type = extract_type_name(arg.get('type', {}))

        if arg_type in ('String', 'ID'):
            arg_strings.append(f'{arg_name}: "test"')
        elif arg_type == 'Int':
            arg_strings.append(f'{arg_name}: 1')
        elif arg_type == 'Float':
            arg_strings.append(f'{arg_name}: 1.0')
        elif arg_type == 'Boolean':
            arg_strings.append(f'{arg_name}: true')

    arg_part = f'({", ".join(arg_strings)})' if arg_strings else ''
    return f'{field_name}{arg_part}'


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file creation."""
    return re.sub(r'[<>:"/\\|?*]', '_', filename)


def truncate_string(s: str, max_length: int = 100) -> str:
    """Truncate string with ellipsis."""
    if len(s) <= max_length:
        return s
    return s[:max_length - 3] + '...'


def parse_error_message(error: Dict) -> str:
    """Extract error message from GraphQL error object."""
    if isinstance(error, dict):
        return error.get('message', str(error))
    return str(error)


def extract_error_messages(result: Dict[str, Any]) -> List[str]:
    """Normalize GraphQL error payloads into a flat string list."""
    messages = []
    for error in result.get('errors') or []:
        messages.append(parse_error_message(error))
    return messages


def response_status(result: Dict[str, Any]) -> int:
    """Get the HTTP-style status code associated with a response."""
    return int(result.get('_status_code', 0) or 0)


def is_successful_execution(result: Dict[str, Any]) -> bool:
    """True when a request executed successfully without GraphQL errors."""
    return result.get('data') is not None and not result.get('errors')


def is_validation_error(result: Dict[str, Any]) -> bool:
    """Best-effort detection of schema/validation errors."""
    validation_needles = [
        'cannot query field',
        'unknown argument',
        'validation',
        'expected type',
        'field',
        'argument',
        'selection',
        'required type',
    ]

    messages = " | ".join(extract_error_messages(result)).lower()
    return any(needle in messages for needle in validation_needles)


def payload_reflected_in_data(result: Dict[str, Any], payload: str) -> bool:
    """Check whether a payload is reflected in successful response data."""
    data = result.get('data')
    if data is None:
        return False
    serialized = json.dumps(data, sort_keys=True)
    encoded_payload = payload.replace('<', '\\u003c').replace('>', '\\u003e')
    return payload in serialized or encoded_payload in serialized


def payload_reflected_only_in_errors(result: Dict[str, Any], payload: str) -> bool:
    """Check whether a payload is reflected in errors but not in data."""
    serialized_errors = json.dumps(result.get('errors') or [], sort_keys=True)
    if payload not in serialized_errors:
        return False
    return not payload_reflected_in_data(result, payload)


def detect_sql_error(text: str) -> bool:
    """Detect SQL error patterns in text."""
    sql_patterns = [
        r'SQL syntax',
        r'mysql_fetch',
        r'mysqli',
        r'ORA-\d{5}',
        r'PostgreSQL.*ERROR',
        r'Warning.*pg_',
        r'SQLite.*error',
        r'SQLSTATE',
        r'syntax error at or near',
        r'unterminated quoted string',
    ]

    for pattern in sql_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def detect_nosql_error(text: str) -> bool:
    """Detect NoSQL error patterns in text."""
    nosql_patterns = [
        r'MongoError',
        r'mongodb',
        r'CouchDB',
        r'Redis.*error',
        r'Cassandra',
    ]

    for pattern in nosql_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def detect_stack_trace(text: str) -> bool:
    """Detect stack trace patterns in text."""
    stack_patterns = [
        r'at\s+\w+\.\w+\(',
        r'File ".*", line \d+',
        r'Traceback \(most recent call last\)',
        r'^\s+at\s.*\(.*:\d+:\d+\)',
        r'\.java:\d+\)',
        r'Exception in thread',
    ]

    for pattern in stack_patterns:
        if re.search(pattern, text, re.MULTILINE | re.IGNORECASE):
            return True
    return False


def get_field_count_in_query(query: str) -> int:
    """Count number of fields in a query (approximate)."""
    words = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', query)
    keywords = {'query', 'mutation', 'subscription', 'fragment', 'on', 'true', 'false', 'null'}
    fields = [w for w in words if w not in keywords]
    return len(fields)


def estimate_query_complexity(query: str) -> int:
    """Estimate query complexity based on depth and field count."""
    depth = query.count('{')
    field_count = get_field_count_in_query(query)
    return depth * field_count


def build_request_payload(
    query: Optional[str] = None,
    variables: Optional[Dict[str, Any]] = None,
    operation_name: Optional[str] = None,
    body: Optional[Any] = None,
    method: str = "POST",
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Build a structured request payload used for reproduction artifacts."""
    payload = {
        'method': method,
        'headers': headers or {},
    }

    if body is not None:
        payload['body'] = body
    else:
        request_body: Dict[str, Any] = {}
        if query is not None:
            request_body['query'] = query
        if variables is not None:
            request_body['variables'] = variables
        if operation_name:
            request_body['operationName'] = operation_name
        payload['body'] = request_body

    if query is not None:
        payload['query'] = query
    if variables is not None:
        payload['variables'] = variables
    if operation_name:
        payload['operation_name'] = operation_name

    return payload


def create_finding(title: str, severity: str, description: str,
                   impact: str, remediation: str, evidence: Optional[Dict] = None,
                   poc: Optional[str] = None, cwe: Optional[str] = None,
                   url: Optional[str] = None, classification: Optional[Dict[str, Any]] = None,
                   confidence: Optional[Dict[str, Any]] = None,
                   validation: Optional[Dict[str, Any]] = None,
                   scanner: Optional[str] = None,
                   request: Optional[Dict[str, Any]] = None,
                   location: Optional[Dict[str, Any]] = None,
                   manual_verification_required: Optional[bool] = None,
                   status: Optional[str] = None) -> Dict:
    """
    Create a standardized finding dictionary with actionable exploit formats.
    """
    finding = {
        'title': title,
        'severity': severity,
        'description': description,
        'impact': impact,
        'remediation': remediation,
    }

    if evidence:
        finding['evidence'] = evidence
    if classification:
        finding['classification'] = classification
    if confidence:
        finding['confidence'] = confidence
    if validation:
        finding['validation'] = validation
    if scanner:
        finding['scanner'] = scanner
    if location:
        finding['location'] = location
    if manual_verification_required is not None:
        finding['manual_verification_required'] = manual_verification_required
    if status:
        finding['status'] = status

    if poc:
        finding['poc'] = poc
    if cwe:
        finding['cwe'] = cwe

    if request is None and poc:
        request = build_request_payload(query=poc)

    if request:
        finding['request'] = request

    if url and request:
        curl_cmd = generate_curl_command(url, request)
        if curl_cmd:
            finding['curl_command'] = curl_cmd

        burp_request = generate_burp_request(url, request)
        if burp_request:
            finding['burp_request'] = burp_request
    elif url and poc:
        curl_cmd = generate_curl_command(url, poc)
        if curl_cmd:
            finding['curl_command'] = curl_cmd

        burp_request = generate_burp_request(url, poc)
        if burp_request:
            finding['burp_request'] = burp_request

    if 'status' not in finding:
        if finding.get('manual_verification_required'):
            finding['status'] = 'manual_review'
        elif (finding.get('confidence') or {}).get('level') == 'confirmed':
            finding['status'] = 'confirmed'
        else:
            finding['status'] = 'potential'

    return finding


def _normalize_request_for_replay(request_or_query: Any) -> Dict[str, Any]:
    """Normalize a query string or request dict into a replayable request object."""
    if isinstance(request_or_query, dict):
        normalized = dict(request_or_query)
        normalized.setdefault('method', 'POST')
        headers = dict(normalized.get('headers') or {})
        if normalized.get('body') is None:
            normalized['body'] = build_request_payload(
                query=normalized.get('query'),
                variables=normalized.get('variables'),
                operation_name=normalized.get('operation_name') or normalized.get('operationName'),
                method=normalized.get('method', 'POST'),
                headers=headers,
            )['body']
        normalized['headers'] = headers
        return normalized

    return build_request_payload(query=str(request_or_query))


def generate_curl_command(url: str, request_or_query: Any) -> str:
    """
    Generate a curl command for executing a GraphQL request.
    """
    request = _normalize_request_for_replay(request_or_query)
    method = request.get('method', 'POST').upper()
    headers = dict(request.get('headers') or {})
    headers.setdefault('Content-Type', 'application/json')
    body = request.get('body', {})
    body_text = json.dumps(body)

    header_lines = [f'  -H {shlex.quote(f"{key}: {value}")} \\' for key, value in headers.items()]
    header_block = "\n".join(header_lines)
    return f"""curl -X {method} {shlex.quote(url)} \\
{header_block}
  -d {shlex.quote(body_text)}"""


def generate_burp_request(url: str, request_or_query: Any) -> str:
    """
    Generate a Burp Suite HTTP request for a GraphQL query or request payload.
    """
    from urllib.parse import urlparse

    request = _normalize_request_for_replay(request_or_query)
    parsed = urlparse(url)
    host = parsed.netloc
    path = parsed.path or '/graphql'
    if parsed.query:
        path = f"{path}?{parsed.query}"

    method = request.get('method', 'POST').upper()
    headers = dict(request.get('headers') or {})
    headers.setdefault('Host', host)
    headers.setdefault('Content-Type', 'application/json')
    body = json.dumps(request.get('body', {}))
    headers['Content-Length'] = str(len(body))

    header_lines = [f"{key}: {value}" for key, value in headers.items()]
    return f"""{method} {path} HTTP/1.1
{chr(10).join(header_lines)}

{body}"""

