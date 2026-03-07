#!/usr/bin/env python3
"""
Request Importer - Import requests from various formats (Postman, cURL, JSON, YAML)
"""

import json
import re
import shlex
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse


class RequestImporter:
    """Import GraphQL requests from various formats"""

    @staticmethod
    def _extract_operation_name(query: Optional[str]) -> Optional[str]:
        """Extract operation name from query if present."""
        if not query or not isinstance(query, str):
            return None

        op_match = re.search(r'(?:query|mutation|subscription)\s+(\w+)', query)
        if op_match:
            return op_match.group(1)
        return None

    @staticmethod
    def _normalize_variables(variables: Any) -> Any:
        """Normalize variables to a dict when possible."""
        if variables is None:
            return None
        if isinstance(variables, dict):
            return variables
        if isinstance(variables, str):
            stripped = variables.strip()
            if not stripped:
                return None
            try:
                parsed = json.loads(stripped)
                return parsed
            except Exception:
                return variables
        return variables

    @staticmethod
    def _extract_postman_requests(collection: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract requests from a Postman collection dictionary."""
        requests = []

        def extract_requests(item: Dict, folder_path: str = ""):
            """Recursively extract requests from collection items."""
            if item.get('request'):
                req = item['request']
                url_obj = req.get('url', {})

                # Build URL
                if isinstance(url_obj, str):
                    url = url_obj
                else:
                    protocol = url_obj.get('protocol', 'https')
                    host = url_obj.get('host', [])
                    path = url_obj.get('path', [])

                    if isinstance(host, list):
                        host = '.'.join(host)
                    if isinstance(path, list):
                        path = '/'.join(path)

                    url = f"{protocol}://{host}/{path}".replace('//', '/').replace(':/', '://')

                # Extract headers
                headers = {}
                for header in req.get('header', []):
                    if not header.get('disabled', False):
                        headers[header.get('key', '')] = header.get('value', '')

                # Extract body
                body = req.get('body', {})
                variables = None
                query = None

                if body.get('mode') == 'raw':
                    body_text = body.get('raw', '')
                    try:
                        body_json = json.loads(body_text)
                        query = body_json.get('query', '')
                        variables = RequestImporter._normalize_variables(body_json.get('variables'))
                    except Exception:
                        query = body_text
                elif body.get('mode') == 'graphql':
                    graphql = body.get('graphql', {})
                    query = graphql.get('query', '')
                    variables = RequestImporter._normalize_variables(graphql.get('variables'))

                request_data = {
                    'name': item.get('name', 'Unnamed Request'),
                    'url': url,
                    'method': req.get('method', 'POST'),
                    'headers': headers,
                    'query': query,
                    'variables': variables,
                    'operation_name': RequestImporter._extract_operation_name(query),
                    'folder': folder_path
                }

                requests.append(request_data)

            # Recursively process items
            if 'item' in item:
                current_folder = folder_path
                if item.get('name'):
                    current_folder = f"{folder_path}/{item['name']}" if folder_path else item['name']

                for sub_item in item['item']:
                    extract_requests(sub_item, current_folder)

        if 'item' in collection:
            for item in collection['item']:
                extract_requests(item)

        return requests
    
    @staticmethod
    def from_postman_collection(file_path: str) -> List[Dict[str, Any]]:
        """
        Import requests from Postman Collection v2.1 format
        
        Args:
            file_path: Path to Postman collection JSON file
            
        Returns:
            List of request dictionaries with url, headers, body, etc.
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            collection = json.load(f)
        return RequestImporter._extract_postman_requests(collection)

    @staticmethod
    def from_postman_collection_data(collection: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Import requests from an already-loaded Postman collection."""
        if not isinstance(collection, dict):
            raise ValueError("Postman collection data must be a dictionary")
        return RequestImporter._extract_postman_requests(collection)
    
    @staticmethod
    def from_curl_command(curl_cmd: str) -> Dict[str, Any]:
        """
        Parse a cURL command and extract request details
        
        Args:
            curl_cmd: cURL command string
            
        Returns:
            Request dictionary with url, headers, body, etc.
        """
        tokens = shlex.split(curl_cmd)
        if tokens and tokens[0] == 'curl':
            tokens = tokens[1:]

        method = None
        url = ""
        headers = {}
        body_text = ""

        i = 0
        while i < len(tokens):
            token = tokens[i]

            if token in ('-X', '--request') and i + 1 < len(tokens):
                method = tokens[i + 1].upper()
                i += 2
                continue

            if token in ('-H', '--header') and i + 1 < len(tokens):
                header = tokens[i + 1]
                if ':' in header:
                    key, value = header.split(':', 1)
                    headers[key.strip()] = value.strip()
                i += 2
                continue

            if token in ('-d', '--data', '--data-raw', '--data-binary', '--data-ascii') and i + 1 < len(tokens):
                if body_text:
                    body_text += tokens[i + 1]
                else:
                    body_text = tokens[i + 1]
                i += 2
                continue

            if token == '--get':
                method = 'GET'
                i += 1
                continue

            if token.startswith('http://') or token.startswith('https://'):
                url = token
                i += 1
                continue

            i += 1

        query = None
        variables = None

        if body_text:
            try:
                body_json = json.loads(body_text)
                query = body_json.get('query', '')
                variables = RequestImporter._normalize_variables(body_json.get('variables'))
            except Exception:
                query = body_text

        if not method:
            method = 'POST' if body_text else 'GET'

        return {
            'name': 'Imported from cURL',
            'url': url,
            'method': method,
            'headers': headers,
            'query': query,
            'variables': variables,
            'operation_name': RequestImporter._extract_operation_name(query)
        }
    
    @staticmethod
    def from_json(file_path: str) -> Dict[str, Any]:
        """
        Import request from JSON file
        
        Expected format:
        {
            "url": "https://api.example.com/graphql",
            "headers": {"Authorization": "Bearer token"},
            "query": "mutation { ... }",
            "variables": {...},
            "operation_name": "MyMutation"
        }
        
        Args:
            file_path: Path to JSON file
            
        Returns:
            Request dictionary
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        if not isinstance(data, dict):
            raise ValueError("JSON request file must contain an object at the root")
        
        return {
            'name': data.get('name', 'Imported from JSON'),
            'url': data.get('url', ''),
            'method': data.get('method', 'POST'),
            'headers': data.get('headers', {}),
            'query': data.get('query', ''),
            'variables': RequestImporter._normalize_variables(data.get('variables')),
            'operation_name': data.get('operation_name')
        }
    
    @staticmethod
    def from_yaml(file_path: str) -> Dict[str, Any]:
        """
        Import request from YAML file
        
        Expected format:
        url: https://api.example.com/graphql
        headers:
          Authorization: Bearer token
        query: |
          mutation { ... }
        variables:
          key: value
        
        Args:
            file_path: Path to YAML file
            
        Returns:
            Request dictionary
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            raise ValueError("YAML request file must contain an object at the root")
        
        return {
            'name': data.get('name', 'Imported from YAML'),
            'url': data.get('url', ''),
            'method': data.get('method', 'POST'),
            'headers': data.get('headers', {}),
            'query': data.get('query', ''),
            'variables': RequestImporter._normalize_variables(data.get('variables')),
            'operation_name': data.get('operation_name')
        }
    
    @staticmethod
    def from_raw_http(raw_request: str) -> Dict[str, Any]:
        """
        Parse raw HTTP request string
        
        Args:
            raw_request: Raw HTTP request string
            
        Returns:
            Request dictionary
        """
        normalized = raw_request.replace('\r\n', '\n').replace('\r', '\n').strip()
        lines = normalized.split('\n')
        
        # Parse request line
        request_line = lines[0]
        method_match = re.match(r'(\w+)\s+([^\s]+)', request_line)
        method = method_match.group(1) if method_match else 'POST'
        path = method_match.group(2) if method_match else '/'
        
        # Extract Host header to build full URL
        host = None
        headers = {}
        body_start = 0
        
        for i, line in enumerate(lines[1:], 1):
            if not line.strip():
                body_start = i + 1
                break
            
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
                if key.strip().lower() == 'host':
                    host = value.strip()
        
        # Build URL
        protocol = 'https' if '443' in str(host) else 'http'
        if host and ':' in host:
            host, port = host.split(':')
            if port not in ['80', '443']:
                url = f"{protocol}://{host}:{port}{path}"
            else:
                url = f"{protocol}://{host}{path}"
        elif host:
            url = f"{protocol}://{host}{path}"
        else:
            url = path
        
        # Extract body
        body_text = '\n'.join(lines[body_start:]) if body_start < len(lines) else ""
        
        query = None
        variables = None
        
        if body_text:
            try:
                body_json = json.loads(body_text)
                query = body_json.get('query', '')
                variables = RequestImporter._normalize_variables(body_json.get('variables'))
            except Exception:
                query = body_text
        
        return {
            'name': 'Imported from raw HTTP',
            'url': url,
            'method': method,
            'headers': headers,
            'query': query,
            'variables': variables,
            'operation_name': RequestImporter._extract_operation_name(query)
        }
    
    @staticmethod
    def auto_detect_and_import(file_path: str) -> Any:
        """
        Auto-detect file format and import
        
        Args:
            file_path: Path to file
            
        Returns:
            Imported request(s) - list for Postman collections, dict for others
        """
        path = Path(file_path)
        suffix = path.suffix.lower()
        
        if suffix == '.json':
            # Try Postman collection first
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if 'info' in data and 'schema' in data.get('info', {}):
                        # Looks like Postman collection
                        return RequestImporter.from_postman_collection(file_path)
            except:
                pass
            
            # Fall back to simple JSON
            return RequestImporter.from_json(file_path)
        
        elif suffix in ['.yaml', '.yml']:
            return RequestImporter.from_yaml(file_path)
        elif suffix in ['.txt', '.http', '.req', '.curl']:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
            if content.startswith('curl '):
                return RequestImporter.from_curl_command(content)
            if re.match(r'^[A-Z]+\s+\S+\s+HTTP/\d\.\d$', content.splitlines()[0]):
                return RequestImporter.from_raw_http(content)
            raise ValueError(f"Unsupported text request format in file: {file_path}")
        
        else:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
            if content.startswith('curl '):
                return RequestImporter.from_curl_command(content)
            if content and re.match(r'^[A-Z]+\s+\S+\s+HTTP/\d\.\d$', content.splitlines()[0]):
                return RequestImporter.from_raw_http(content)
            raise ValueError(f"Unsupported file format: {suffix}")
