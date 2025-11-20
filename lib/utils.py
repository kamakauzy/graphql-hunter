#!/usr/bin/env python3
"""
Utility functions for GraphQL Hunter
"""

import re
from typing import Dict, List, Any, Optional


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
    
    # Handle wrapped types (NON_NULL, LIST)
    if type_def.get('ofType'):
        return extract_type_name(type_def['ofType'])
    
    return "Unknown"


def is_scalar_type(type_name: str) -> bool:
    """Check if type is a scalar type"""
    scalar_types = {'String', 'Int', 'Float', 'Boolean', 'ID'}
    return type_name in scalar_types


def build_query_for_field(field: Dict, depth: int = 1, max_depth: int = 3) -> str:
    """
    Build a simple query for a field
    
    Args:
        field: Field definition
        depth: Current depth
        max_depth: Maximum recursion depth
        
    Returns:
        Query string
    """
    if depth > max_depth:
        return ""
    
    field_name = field.get('name', '')
    args = field.get('args', [])
    
    # Build arguments with dummy values
    arg_strings = []
    for arg in args:
        arg_name = arg.get('name')
        arg_type = extract_type_name(arg.get('type', {}))
        
        # Provide dummy values based on type
        if arg_type == 'String' or arg_type == 'ID':
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
    """Sanitize filename for safe file creation"""
    return re.sub(r'[<>:"/\\|?*]', '_', filename)


def truncate_string(s: str, max_length: int = 100) -> str:
    """Truncate string with ellipsis"""
    if len(s) <= max_length:
        return s
    return s[:max_length-3] + '...'


def parse_error_message(error: Dict) -> str:
    """Extract error message from GraphQL error object"""
    if isinstance(error, dict):
        return error.get('message', str(error))
    return str(error)


def detect_sql_error(text: str) -> bool:
    """Detect SQL error patterns in text"""
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
    """Detect NoSQL error patterns in text"""
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
    """Detect stack trace patterns in text"""
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
    """Count number of fields in a query (approximate)"""
    # Simple heuristic - count words that are likely field names
    words = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', query)
    # Filter out keywords
    keywords = {'query', 'mutation', 'subscription', 'fragment', 'on', 'true', 'false', 'null'}
    fields = [w for w in words if w not in keywords]
    return len(fields)


def estimate_query_complexity(query: str) -> int:
    """Estimate query complexity based on depth and field count"""
    depth = query.count('{')
    field_count = get_field_count_in_query(query)
    return depth * field_count


def create_finding(title: str, severity: str, description: str,
                   impact: str, remediation: str, evidence: Optional[Dict] = None,
                   poc: Optional[str] = None, cwe: Optional[str] = None, 
                   url: Optional[str] = None) -> Dict:
    """
    Create a standardized finding dictionary with actionable exploit formats
    
    Args:
        title: Finding title
        severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
        description: Detailed description
        impact: Impact description
        remediation: Remediation advice
        evidence: Supporting evidence (request/response)
        poc: Proof of concept
        cwe: CWE identifier
        url: Target URL for generating curl/burp commands
        
    Returns:
        Finding dictionary with curl and Burp Suite formats
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
    if poc:
        finding['poc'] = poc
        
        # Generate curl command if URL and POC are provided
        if url and poc:
            curl_cmd = generate_curl_command(url, poc)
            if curl_cmd:
                finding['curl_command'] = curl_cmd
            
            burp_request = generate_burp_request(url, poc)
            if burp_request:
                finding['burp_request'] = burp_request
    if cwe:
        finding['cwe'] = cwe
    
    return finding


def generate_curl_command(url: str, query: str) -> str:
    """
    Generate a curl command for executing a GraphQL query
    
    Args:
        url: GraphQL endpoint URL
        query: GraphQL query string
    
    Returns:
        Formatted curl command
    """
    # Escape quotes and newlines in query
    escaped_query = query.replace('"', '\\"').replace('\n', ' ').replace('\r', '').strip()
    
    # Truncate very long queries for readability
    if len(escaped_query) > 500:
        escaped_query = escaped_query[:500] + '...'
    
    # Build curl command
    curl_cmd = f"""curl -X POST {url} \\
  -H "Content-Type: application/json" \\
  -d '{{"query":"{escaped_query}"}}'"""
    
    return curl_cmd


def generate_burp_request(url: str, query: str) -> str:
    """
    Generate a Burp Suite HTTP request for a GraphQL query
    
    Args:
        url: GraphQL endpoint URL
        query: GraphQL query string
    
    Returns:
        Formatted HTTP request for Burp Suite
    """
    from urllib.parse import urlparse
    import json
    
    parsed = urlparse(url)
    host = parsed.netloc
    path = parsed.path or '/graphql'
    scheme = parsed.scheme
    
    # Escape query for JSON
    body = json.dumps({"query": query})
    content_length = len(body)
    
    burp_request = f'''POST {path} HTTP/1.1
Host: {host}
Content-Type: application/json
Content-Length: {content_length}

{body}'''
    
    return burp_request

