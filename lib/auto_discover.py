#!/usr/bin/env python3
"""
Auto-Discovery - Automatically figure out authentication and configuration from notes, files, etc.
"""

import json
import re
import shlex
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse


class AutoDiscover:
    """Automatically discover authentication and configuration from various sources"""
    
    def __init__(self):
        self.discovered = self._empty_discovery()

    def _empty_discovery(self) -> Dict[str, Any]:
        return {
            'url': None,
            'auth_method': None,
            'credentials': {},
            'headers': {},
            'queries': [],
            'mutations': [],
            'tokens': {},
            'notes': []
        }
    
    def analyze_notes(self, notes_text: str) -> Dict[str, Any]:
        """
        Analyze text notes to extract URLs, credentials, tokens, etc.
        
        Args:
            notes_text: Plain text notes containing credentials, URLs, etc.
            
        Returns:
            Dictionary of discovered information
        """
        # Extract URLs
        url_patterns = [
            r'https?://[^\s]+',
            r'url[:\s]+([^\s\n]+)',
            r'endpoint[:\s]+([^\s\n]+)',
            r'graphql[:\s]+([^\s\n]+)',
        ]
        for pattern in url_patterns:
            matches = re.findall(pattern, notes_text, re.IGNORECASE)
            for match in matches:
                url = match if match.startswith('http') else f"https://{match}"
                if 'graphql' in url.lower() or '/graphql' in url:
                    self.discovered['url'] = url
                    break
        
        # Extract email
        email_pattern = r'email[:\s]+([^\s\n@]+@[^\s\n]+)'
        email_match = re.search(email_pattern, notes_text, re.IGNORECASE)
        if email_match:
            self.discovered['credentials']['email'] = email_match.group(1)
        
        # Extract password
        password_patterns = [
            r'password[:\s]+([^\s\n]+)',
            r'pwd[:\s]+([^\s\n]+)',
            r'pass[:\s]+([^\s\n]+)',
        ]
        for pattern in password_patterns:
            match = re.search(pattern, notes_text, re.IGNORECASE)
            if match:
                self.discovered['credentials']['password'] = match.group(1)
                break
        
        # Extract tokens (JWT format)
        jwt_pattern = r'eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'
        jwt_matches = re.findall(jwt_pattern, notes_text)
        if jwt_matches:
            # Check for token labels
            for match in jwt_matches:
                # Look for context around the token
                context_start = max(0, notes_text.find(match) - 50)
                context_end = min(len(notes_text), notes_text.find(match) + len(match) + 50)
                context = notes_text[context_start:context_end].lower()
                
                if 'token' in context or 'apikey' in context or 'jwt' in context:
                    if 'refresh' in context:
                        self.discovered['tokens']['refresh_token'] = match
                    else:
                        self.discovered['tokens']['access_token'] = match
        
        # Extract refresh tokens (hex format)
        refresh_pattern = r'(?:refresh[_\s]?token|refreshToken)[:\s]+([a-f0-9]{32,})'
        refresh_match = re.search(refresh_pattern, notes_text, re.IGNORECASE)
        if refresh_match:
            self.discovered['tokens']['refresh_token'] = refresh_match.group(1)
        
        # Extract UIDs
        uid_patterns = {
            'pdt_uid': r'(?:pdt[_\s]?uid|pdtUid)[:\s]+([A-Za-z0-9]+)',
            'patient_uid': r'(?:patient[_\s]?uid|patientUid)[:\s]+([A-Za-z0-9]+)',
            'careteams_uid': r'(?:careteams[_\s]?uid|careteamsUid)[:\s]+([A-Za-z0-9]+)',
        }
        for key, pattern in uid_patterns.items():
            match = re.search(pattern, notes_text, re.IGNORECASE)
            if match:
                self.discovered['credentials'][key] = match.group(1)
        
        # Extract access codes
        access_code_pattern = r'(?:access[_\s]?code|accessCode)[:\s]+([^\s\n]+)'
        access_match = re.search(access_code_pattern, notes_text, re.IGNORECASE)
        if access_match:
            self.discovered['credentials']['access_code'] = access_match.group(1)
        
        # Extract headers (Token:, Authorization:, etc.)
        # Look for header patterns in context
        header_patterns = [
            r'(Token|Authorization|X-API-Key|apikey)[:\s]+([^\n]+)',
        ]
        for pattern in header_patterns:
            matches = re.findall(pattern, notes_text, re.IGNORECASE)
            for header_name, header_value in matches:
                normalized_header_name = 'X-API-Key' if header_name.lower() == 'apikey' else header_name
                self.discovered['headers'][normalized_header_name] = header_value.strip()
        
        # Detect auth method
        if 'tokenAuth' in notes_text or 'token_auth' in notes_text.lower():
            self.discovered['auth_method'] = 'tokenAuth'
        elif self.discovered['credentials'].get('email') and self.discovered['credentials'].get('password'):
            # If we have email/password, likely tokenAuth mutation
            self.discovered['auth_method'] = 'tokenAuth'
        elif self.discovered['tokens'].get('access_token'):
            self.discovered['auth_method'] = 'token_header'
        
        return self.discovered
    
    def analyze_json_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze JSON file to extract configuration
        
        Args:
            file_path: Path to JSON file
            
        Returns:
            Dictionary of discovered information
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Check if it's a Postman collection
        if 'info' in data and 'schema' in data.get('info', {}):
            return self._analyze_postman_collection(data)
        
        # Check if it's a request file
        if 'url' in data or 'query' in data:
            return self._analyze_request_file(data)
        
        # Generic JSON - look for common patterns
        return self._analyze_generic_json(data)
    
    def _analyze_postman_collection(self, collection: Dict) -> Dict[str, Any]:
        """Analyze Postman collection"""
        from request_importer import RequestImporter
        
        requests = RequestImporter.from_postman_collection_data(collection)
        
        # Extract common URLs
        urls = [r.get('url') for r in requests if r.get('url')]
        if urls:
            # Use most common URL
            from collections import Counter
            url_counts = Counter(urls)
            self.discovered['url'] = url_counts.most_common(1)[0][0]
        
        # Extract common headers
        all_headers = {}
        for req in requests:
            for key, value in req.get('headers', {}).items():
                if key.lower() in ['token', 'authorization', 'x-api-key']:
                    if key not in all_headers:
                        all_headers[key] = value
        
        if all_headers:
            self.discovered['headers'].update(all_headers)
        
        # Extract queries/mutations
        for req in requests:
            if req.get('query'):
                if 'mutation' in req['query'].lower():
                    self.discovered['mutations'].append(req)
                else:
                    self.discovered['queries'].append(req)
        
        return self.discovered
    
    def _analyze_request_file(self, data: Dict) -> Dict[str, Any]:
        """Analyze request file format"""
        if 'url' in data:
            self.discovered['url'] = data['url']
        
        if 'headers' in data:
            self.discovered['headers'].update(data['headers'])
        
        if 'query' in data and isinstance(data.get('query'), str):
            if 'mutation' in data['query'].lower():
                self.discovered['mutations'].append(data)
            else:
                self.discovered['queries'].append(data)
        
        return self.discovered
    
    def _analyze_generic_json(self, data: Dict) -> Dict[str, Any]:
        """Analyze generic JSON for common patterns"""
        def extract_from_dict(d, path=""):
            """Recursively extract values"""
            if isinstance(d, dict):
                for key, value in d.items():
                    key_lower = key.lower()
                    current_path = f"{path}.{key}" if path else key
                    
                    # Look for URLs
                    if key_lower in ['url', 'endpoint', 'graphql_url', 'api_url']:
                        if isinstance(value, str) and value.startswith('http'):
                            self.discovered['url'] = value
                    
                    # Look for credentials
                    if key_lower in ['email', 'username', 'user']:
                        if isinstance(value, str) and '@' in value:
                            self.discovered['credentials']['email'] = value
                    
                    if key_lower in ['password', 'pwd', 'pass']:
                        if isinstance(value, str):
                            self.discovered['credentials']['password'] = value
                    
                    # Look for tokens
                    if 'token' in key_lower:
                        if isinstance(value, str):
                            if value.startswith('eyJ'):  # JWT
                                if 'refresh' in key_lower:
                                    self.discovered['tokens']['refresh_token'] = value
                                else:
                                    self.discovered['tokens']['access_token'] = value
                            else:
                                if 'refresh' in key_lower:
                                    self.discovered['tokens']['refresh_token'] = value
                    
                    # Look for headers
                    if key_lower in ['headers', 'header']:
                        if isinstance(value, dict):
                            self.discovered['headers'].update(value)
                    
                    extract_from_dict(value, current_path)
            
            elif isinstance(d, list):
                for item in d:
                    extract_from_dict(item, path)
        
        extract_from_dict(data)
        return self.discovered
    
    def analyze_yaml_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze YAML file"""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        return self._analyze_generic_json(data)
    
    def analyze_text_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze plain text file"""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return self.analyze_notes(content)
    
    def auto_discover(self, sources: List[str]) -> Dict[str, Any]:
        """
        Auto-discover from multiple sources
        
        Args:
            sources: List of file paths or text strings
            
        Returns:
            Complete discovery results with recommendations
        """
        self.discovered = self._empty_discovery()

        for source in sources:
            path = Path(source)
            
            if path.exists():
                # It's a file
                suffix = path.suffix.lower()
                
                if suffix == '.json':
                    self.analyze_json_file(str(path))
                elif suffix in ['.yaml', '.yml']:
                    self.analyze_yaml_file(str(path))
                elif suffix in ['.txt', '.md', '.notes']:
                    self.analyze_text_file(str(path))
                else:
                    # Try as text
                    try:
                        self.analyze_text_file(str(path))
                    except:
                        pass
            else:
                # It's text content
                self.analyze_notes(source)
        
        # Generate recommendations
        recommendations = self._generate_recommendations()
        self.discovered['recommendations'] = recommendations
        
        return self.discovered
    
    def _generate_recommendations(self) -> Dict[str, Any]:
        """Generate recommendations based on discovered information"""
        recs = {
            'auth_profile': None,
            'command': None,
            'auth_vars': [],
            'headers': []
        }
        
        discovered_headers = self.discovered.get('headers') or {}

        # Determine auth profile / headers
        if self.discovered['auth_method'] == 'tokenAuth' or \
           (self.discovered['credentials'].get('email') and
            self.discovered['credentials'].get('password')):
            recs['auth_profile'] = 'token_auth'
            recs['auth_vars'] = [
                f"email={self.discovered['credentials'].get('email')}",
                f"password={self.discovered['credentials'].get('password')}"
            ]
        elif discovered_headers:
            recs['headers'] = [f"{key}: {value}" for key, value in discovered_headers.items()]
        elif self.discovered['tokens'].get('access_token'):
            token = self.discovered['tokens']['access_token']
            recs['headers'] = [f"Authorization: Bearer {token}"]
        
        # Build command
        if self.discovered['url']:
            cmd_parts = [
                'gqlh',
                f"-u {shlex.quote(self.discovered['url'])}"
            ]
            
            if recs['auth_profile']:
                cmd_parts.append(f"--auth-profile {recs['auth_profile']}")
                for var in recs['auth_vars']:
                    cmd_parts.append(f"--auth-var {shlex.quote(var)}")
            elif recs['headers']:
                for header in recs['headers']:
                    cmd_parts.append(f"-H {shlex.quote(header)}")
            
            cmd_parts.append('--validate-auth')
            recs['command'] = ' \\\n  '.join(cmd_parts)
            recs['command_simple'] = ' '.join(cmd_parts)  # Single line version
        
        return recs
    
    def generate_auth_profile(self) -> Optional[Dict[str, Any]]:
        """Generate an auth profile YAML based on discoveries"""
        if not self.discovered.get('auth_method'):
            return None
        
        if self.discovered['auth_method'] == 'tokenAuth':
            profile = {
                'type': 'scripted',
                'acquire_steps': [
                    {
                        'type': 'graphql',
                        'query': """mutation TokenAuth($email: String!, $password: String!) {
  tokenAuth(email: $email, password: $password) {
    token
    refreshToken
    user {
      uid
      email
    }
  }
}""",
                        'variables': {
                            'email': '{{email}}',
                            'password': '{{password}}'
                        },
                        'extract': [
                            {
                                'var': 'access_token',
                                'from': 'json',
                                'path': 'data.tokenAuth.token'
                            },
                            {
                                'var': 'refresh_token',
                                'from': 'json',
                                'path': 'data.tokenAuth.refreshToken'
                            }
                        ]
                    }
                ],
                'inject_headers': {
                    'Token': '{{access_token}}'
                },
                'sensitive_headers': ['Token']
            }
            return profile
        
        return None
