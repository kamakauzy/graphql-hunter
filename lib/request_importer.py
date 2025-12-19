#!/usr/bin/env python3
"""
Request Importer - Import requests from various formats (Postman, cURL, JSON, YAML)
"""

import json
import re
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse


class RequestImporter:
    """Import GraphQL requests from various formats"""
    
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
        
        requests = []
        
        def extract_requests(item: Dict, folder_path: str = ""):
            """Recursively extract requests from collection items"""
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
                body_text = ""
                variables = None
                query = None
                
                if body.get('mode') == 'raw':
                    body_text = body.get('raw', '')
                    # Try to parse as JSON
                    try:
                        body_json = json.loads(body_text)
                        query = body_json.get('query', '')
                        variables = body_json.get('variables')
                    except:
                        query = body_text
                elif body.get('mode') == 'graphql':
                    query = body.get('graphql', {}).get('query', '')
                    variables = body.get('graphql', {}).get('variables')
                
                # Extract operation name from query if present
                operation_name = None
                if query:
                    op_match = re.search(r'(?:query|mutation|subscription)\s+(\w+)', query)
                    if op_match:
                        operation_name = op_match.group(1)
                
                request_data = {
                    'name': item.get('name', 'Unnamed Request'),
                    'url': url,
                    'method': req.get('method', 'POST'),
                    'headers': headers,
                    'query': query,
                    'variables': variables,
                    'operation_name': operation_name,
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
        
        # Process collection
        if 'item' in collection:
            for item in collection['item']:
                extract_requests(item)
        
        return requests
    
    @staticmethod
    def from_curl_command(curl_cmd: str) -> Dict[str, Any]:
        """
        Parse a cURL command and extract request details
        
        Args:
            curl_cmd: cURL command string
            
        Returns:
            Request dictionary with url, headers, body, etc.
        """
        # Extract URL
        url_match = re.search(r'curl\s+(?:-[^\s]+\s+)*["\']?([^"\'\s]+)["\']?', curl_cmd)
        url = url_match.group(1) if url_match else ""
        
        # Extract headers
        headers = {}
        header_matches = re.findall(r'-H\s+["\']([^"\']+)["\']', curl_cmd)
        for header in header_matches:
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
        
        # Extract data/body
        data_match = re.search(r'--data(?:-raw)?\s+["\']([^"\']+)["\']', curl_cmd, re.DOTALL)
        body_text = data_match.group(1) if data_match else ""
        
        query = None
        variables = None
        
        if body_text:
            try:
                body_json = json.loads(body_text)
                query = body_json.get('query', '')
                variables = body_json.get('variables')
            except:
                query = body_text
        
        # Extract operation name
        operation_name = None
        if query:
            op_match = re.search(r'(?:query|mutation|subscription)\s+(\w+)', query)
            if op_match:
                operation_name = op_match.group(1)
        
        return {
            'name': 'Imported from cURL',
            'url': url,
            'method': 'POST',
            'headers': headers,
            'query': query,
            'variables': variables,
            'operation_name': operation_name
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
        
        return {
            'name': data.get('name', 'Imported from JSON'),
            'url': data.get('url', ''),
            'method': data.get('method', 'POST'),
            'headers': data.get('headers', {}),
            'query': data.get('query', ''),
            'variables': data.get('variables'),
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
        
        return {
            'name': data.get('name', 'Imported from YAML'),
            'url': data.get('url', ''),
            'method': data.get('method', 'POST'),
            'headers': data.get('headers', {}),
            'query': data.get('query', ''),
            'variables': data.get('variables'),
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
        lines = raw_request.strip().split('\n')
        
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
                variables = body_json.get('variables')
            except:
                query = body_text
        
        # Extract operation name
        operation_name = None
        if query:
            op_match = re.search(r'(?:query|mutation|subscription)\s+(\w+)', query)
            if op_match:
                operation_name = op_match.group(1)
        
        return {
            'name': 'Imported from raw HTTP',
            'url': url,
            'method': method,
            'headers': headers,
            'query': query,
            'variables': variables,
            'operation_name': operation_name
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
        
        else:
            raise ValueError(f"Unsupported file format: {suffix}")
