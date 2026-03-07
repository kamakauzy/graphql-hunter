#!/usr/bin/env python3
"""
GraphQL Client - Handles all GraphQL requests and introspection
"""

import requests
import json
import time
import copy
from typing import Dict, List, Optional, Any, Mapping

try:
    # Optional dependency (auth engine). GraphQLClient works without it.
    from auth.manager import AuthManager  # noqa: F401
except Exception:  # pragma: no cover
    AuthManager = Any  # type: ignore

try:
    from auth.redact import redact_obj as _redact_obj, redact_text as _redact_text  # noqa: F401
except Exception:  # pragma: no cover
    _redact_obj = None  # type: ignore
    _redact_text = None  # type: ignore


class GraphQLClient:
    """Client for interacting with GraphQL endpoints"""
    
    def __init__(self, url: str, headers: Optional[Dict] = None, 
                 proxy: Optional[str] = None, delay: float = 0, 
                 verbose: bool = False, timeout: int = 30,
                 verify: bool = True,
                 auth_manager: Optional[Any] = None,
                 test_connection: bool = True):
        """
        Initialize GraphQL client
        
        Args:
            url: GraphQL endpoint URL
            headers: Custom HTTP headers
            proxy: Proxy URL (e.g., http://127.0.0.1:8080)
            delay: Delay between requests in seconds
            verbose: Enable verbose output
            timeout: Request timeout in seconds
        """
        self.url = url
        self.headers = headers or {}
        self.delay = delay
        self.verbose = verbose
        self.timeout = timeout
        self.verify = verify
        self.auth_manager = auth_manager
        self.schema = None
        self.introspection_enabled = None

        # Maintain cookies for session-based auth flows
        self.session = requests.Session()
        
        # Set default headers
        if 'Content-Type' not in self.headers:
            self.headers['Content-Type'] = 'application/json'
        
        # Configure proxy
        self.proxies = {}
        if proxy:
            self.proxies = {
                'http': proxy,
                'https': proxy
            }
        
        # Test connection
        if test_connection:
            self.test_connection()
    
    def test_connection(self):
        """Test connection to GraphQL endpoint"""
        result = self.query('{__typename}')
        status = int(result.get('_status_code', 0) or 0)
        if status not in [200, 400]:
            raise Exception(f"Unexpected status code: {status}")

    def _build_request_headers(
        self,
        extra_headers: Optional[Mapping[str, str]] = None,
        bypass_auth: bool = False,
        multipart: bool = False,
    ) -> Dict[str, str]:
        """Build request headers for a request."""
        req_headers = dict(self.headers)
        if (not bypass_auth) and self.auth_manager and hasattr(self.auth_manager, "get_request_headers"):
            req_headers.update(self.auth_manager.get_request_headers())
        if extra_headers:
            req_headers.update({k: str(v) for k, v in extra_headers.items()})

        if multipart:
            req_headers = {
                k: v for k, v in req_headers.items()
                if str(k).lower() != 'content-type'
            }
        return req_headers

    def _normalize_uploads(self, uploads: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Normalize upload specifications into a stable mapping."""
        normalized = {}
        for path, spec in (uploads or {}).items():
            if isinstance(spec, tuple):
                filename, content, content_type = (list(spec) + [None, None, None])[:3]
                spec = {'filename': filename, 'content': content, 'content_type': content_type}
            spec = dict(spec or {})
            content = spec.get('content', b'')
            if isinstance(content, str):
                content = content.encode('utf-8')
            normalized[path] = {
                'filename': spec.get('filename') or 'upload.bin',
                'content': content,
                'content_type': spec.get('content_type') or 'application/octet-stream',
            }
        return normalized

    def _set_value_at_path(self, target: Dict[str, Any], path: str, value: Any) -> None:
        """Set nested values using paths like variables.input.file or variables.files.0."""
        tokens = path.split('.')
        cursor: Any = target
        for token in tokens[:-1]:
            if token.isdigit():
                cursor = cursor[int(token)]
            else:
                cursor = cursor[token]
        final = tokens[-1]
        if final.isdigit():
            cursor[int(final)] = value
        else:
            cursor[final] = value

    def _build_multipart_request(
        self,
        payload: Dict[str, Any],
        uploads: Dict[str, Dict[str, Any]],
    ) -> tuple[Dict[str, str], Dict[str, tuple]]:
        """Build GraphQL multipart request components."""
        operations = copy.deepcopy(payload)
        file_map = {}
        files = {}

        for index, (path, spec) in enumerate(uploads.items()):
            file_key = str(index)
            self._set_value_at_path(operations, path, None)
            file_map[file_key] = [path]
            files[file_key] = (
                spec['filename'],
                spec['content'],
                spec['content_type'],
            )

        data = {
            'operations': json.dumps(operations),
            'map': json.dumps(file_map),
        }
        return data, files

    def _post_graphql(
        self,
        payload: Dict[str, Any],
        *,
        extra_headers: Optional[Mapping[str, str]] = None,
        bypass_auth: bool = False,
        uploads: Optional[Dict[str, Any]] = None,
    ) -> tuple[requests.Response, float]:
        """POST a GraphQL request as JSON or multipart."""
        multipart = bool(uploads)
        req_headers = self._build_request_headers(extra_headers=extra_headers, bypass_auth=bypass_auth, multipart=multipart)

        started = time.perf_counter()
        if multipart:
            normalized_uploads = self._normalize_uploads(uploads)
            data, files = self._build_multipart_request(payload, normalized_uploads)
            response = self.session.post(
                self.url,
                headers=req_headers,
                data=data,
                files=files,
                proxies=self.proxies,
                timeout=self.timeout,
                verify=self.verify
            )
        else:
            response = self.session.post(
                self.url,
                headers=req_headers,
                json=payload,
                proxies=self.proxies,
                timeout=self.timeout,
                verify=self.verify
            )
        elapsed = time.perf_counter() - started
        return response, elapsed

    def _parse_response(self, response: requests.Response, elapsed_seconds: float) -> Dict[str, Any]:
        """Parse an HTTP response into a GraphQL-style result dict."""
        if self.verbose:
            print(f"[DEBUG] Response Status: {response.status_code}")
            body = response.text[:1000]
            if _redact_text:
                body = _redact_text(body)
            print(f"[DEBUG] Response Body: {body}")

        try:
            result = response.json()
        except json.JSONDecodeError:
            result = {
                'errors': [{'message': f'Non-JSON response: {response.text[:200]}'}],
                'status_code': response.status_code,
                'raw_response': response.text
            }

        result['_status_code'] = response.status_code
        result['_headers'] = dict(response.headers)
        result['_elapsed_seconds'] = elapsed_seconds
        return result
    
    def query(self, query: str, variables: Optional[Dict] = None, 
              operation_name: Optional[str] = None,
              extra_headers: Optional[Mapping[str, str]] = None,
              bypass_auth: bool = False,
              uploads: Optional[Dict[str, Any]] = None) -> Dict:
        """
        Execute a GraphQL query
        
        Args:
            query: GraphQL query string
            variables: Query variables
            operation_name: Operation name
            
        Returns:
            Response dictionary with 'data', 'errors', etc.
        """
        # Apply delay if configured
        if self.delay > 0:
            time.sleep(self.delay)
        
        payload = {'query': query}
        if variables:
            payload['variables'] = variables
        if operation_name:
            payload['operationName'] = operation_name
        
        if self.verbose:
            print(f"\n[DEBUG] Request to {self.url}")
            debug_headers = dict(self.headers)
            if (not bypass_auth) and self.auth_manager and hasattr(self.auth_manager, "get_request_headers"):
                try:
                    debug_headers.update(self.auth_manager.get_request_headers())
                except Exception:
                    pass
            if extra_headers:
                debug_headers.update({k: str(v) for k, v in extra_headers.items()})
            if self.auth_manager and hasattr(self.auth_manager, "redact_headers"):
                debug_headers = self.auth_manager.redact_headers(debug_headers)
            if uploads:
                debug_headers = {
                    k: v for k, v in debug_headers.items()
                    if str(k).lower() != 'content-type'
                }
            print(f"[DEBUG] Headers: {json.dumps(debug_headers, indent=2)}")
            payload_for_debug = payload
            if _redact_obj:
                payload_for_debug = _redact_obj(payload_for_debug)
            print(f"[DEBUG] Payload: {json.dumps(payload_for_debug, indent=2)}")
            if uploads:
                upload_debug = {
                    path: {
                        'filename': spec.get('filename') if isinstance(spec, dict) else spec[0],
                        'content_type': spec.get('content_type') if isinstance(spec, dict) else (spec[2] if len(spec) > 2 else None),
                    }
                    for path, spec in uploads.items()
                }
                print(f"[DEBUG] Uploads: {json.dumps(upload_debug, indent=2)}")
        
        try:
            if (not bypass_auth) and self.auth_manager and hasattr(self.auth_manager, "ensure_prepared"):
                self.auth_manager.ensure_prepared(self)
            response, elapsed = self._post_graphql(
                payload,
                extra_headers=extra_headers,
                bypass_auth=bypass_auth,
                uploads=uploads,
            )
            result = self._parse_response(response, elapsed)

            # Refresh + retry once on auth failures
            if (not bypass_auth) and self.auth_manager and hasattr(self.auth_manager, "maybe_refresh_and_retry"):
                try:
                    should_retry = self.auth_manager.maybe_refresh_and_retry(self, response.status_code, result)
                except Exception:
                    should_retry = False

                if should_retry:
                    response, elapsed = self._post_graphql(
                        payload,
                        extra_headers=extra_headers,
                        bypass_auth=bypass_auth,
                        uploads=uploads,
                    )
                    result = self._parse_response(response, elapsed)

            return result
            
        except requests.exceptions.Timeout:
            return {
                'errors': [{'message': 'Request timeout'}],
                '_status_code': 0,
                '_timeout': True
            }
        except requests.exceptions.RequestException as e:
            return {
                'errors': [{'message': f'Request failed: {str(e)}'}],
                '_status_code': 0,
                '_error': str(e)
            }
    
    def introspect(self, force: bool = False) -> Optional[Dict]:
        """
        Perform introspection query to retrieve schema
        
        Args:
            force: Force re-introspection even if cached
            
        Returns:
            Schema dictionary or None if introspection is disabled
        """
        if self.schema and not force:
            return self.schema
        
        introspection_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
            directives {
              name
              description
              locations
              args {
                ...InputValue
              }
            }
          }
        }
        
        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              ...InputValue
            }
            type {
              ...TypeRef
            }
            isDeprecated
            deprecationReason
          }
          inputFields {
            ...InputValue
          }
          interfaces {
            ...TypeRef
          }
          enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
          }
          possibleTypes {
            ...TypeRef
          }
        }
        
        fragment InputValue on __InputValue {
          name
          description
          type { ...TypeRef }
          defaultValue
        }
        
        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """
        
        result = self.query(introspection_query)
        
        if result.get('data') and result['data'].get('__schema'):
            self.schema = result['data']['__schema']
            self.introspection_enabled = True
            return self.schema
        else:
            self.introspection_enabled = False
            return None
    
    def get_queries(self) -> List[Dict]:
        """Get all available queries from schema"""
        if not self.schema:
            self.introspect()
        
        if not self.schema:
            return []
        
        query_type_name = self.schema.get('queryType', {})
        if not query_type_name or not isinstance(query_type_name, dict):
            return []
        
        query_type_name = query_type_name.get('name')
        if not query_type_name:
            return []
        
        for type_def in self.schema.get('types', []):
            if type_def and type_def.get('name') == query_type_name:
                return type_def.get('fields', []) or []
        
        return []
    
    def get_mutations(self) -> List[Dict]:
        """Get all available mutations from schema"""
        if not self.schema:
            self.introspect()
        
        if not self.schema:
            return []
        
        mutation_type_name = self.schema.get('mutationType', {})
        if not mutation_type_name or not isinstance(mutation_type_name, dict):
            return []
        
        mutation_type_name = mutation_type_name.get('name')
        if not mutation_type_name:
            return []
        
        for type_def in self.schema.get('types', []):
            if type_def and type_def.get('name') == mutation_type_name:
                return type_def.get('fields', []) or []
        
        return []
    
    def get_types(self) -> List[Dict]:
        """Get all types from schema"""
        if not self.schema:
            self.introspect()
        
        if not self.schema:
            return []
        
        return self.schema.get('types', [])
    
    def get_type_by_name(self, name: str) -> Optional[Dict]:
        """Get specific type by name"""
        types = self.get_types()
        for type_def in types:
            if type_def.get('name') == name:
                return type_def
        return None
    
    def batch_query(self, queries: List[Dict]) -> List[Dict]:
        """
        Execute multiple queries in a single batch request
        
        Args:
            queries: List of query dictionaries with 'query', 'variables', 'operationName'
            
        Returns:
            List of response dictionaries
        """
        if self.delay > 0:
            time.sleep(self.delay)
        
        if self.verbose:
            print(f"\n[DEBUG] Batch Request to {self.url}")
            print(f"[DEBUG] Number of queries: {len(queries)}")
        
        try:
            if self.auth_manager and hasattr(self.auth_manager, "ensure_prepared"):
                self.auth_manager.ensure_prepared(self)

            req_headers = dict(self.headers)
            if self.auth_manager and hasattr(self.auth_manager, "get_request_headers"):
                req_headers.update(self.auth_manager.get_request_headers())

            response = self.session.post(
                self.url,
                headers=req_headers,
                json=queries,
                proxies=self.proxies,
                timeout=self.timeout,
                verify=self.verify
            )
            
            if self.verbose:
                print(f"[DEBUG] Response Status: {response.status_code}")
            
            try:
                results = response.json()
                if not isinstance(results, list):
                    results = [results]
            except json.JSONDecodeError:
                results = [{
                    'errors': [{'message': 'Non-JSON response'}],
                    'raw_response': response.text
                }]
            
            # Add metadata to each result
            for result in results:
                result['_status_code'] = response.status_code
            
            return results
            
        except requests.exceptions.RequestException as e:
            return [{
                'errors': [{'message': f'Batch request failed: {str(e)}'}],
                '_status_code': 0
            }]
    
    def is_introspection_enabled(self) -> bool:
        """Check if introspection is enabled"""
        if self.introspection_enabled is None:
            self.introspect()
        return self.introspection_enabled or False
    
    def validate_auth(self, test_query: Optional[str] = None, test_variables: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Validate authentication by comparing responses with and without auth headers
        
        Args:
            test_query: Optional GraphQL query/mutation to test (default: simple __typename query)
            test_variables: Optional variables for the test query
            
        Returns:
            Dictionary with validation results:
            {
                'auth_working': bool,
                'auth_required': bool,
                'status_with_auth': int,
                'status_without_auth': int,
                'response_with_auth': Dict,
                'response_without_auth': Dict,
                'analysis': str
            }
        """
        if test_query is None:
            test_query = '{ __typename }'
        
        # Test with current auth headers
        result_with_auth = self.query(test_query, variables=test_variables)
        status_with_auth = result_with_auth.get('_status_code', 0)
        
        # Test without auth (create a minimal client)
        unauth_headers = {'Content-Type': 'application/json'}
        unauth_client = GraphQLClient(
            url=self.url,
            headers=unauth_headers,
            proxy=self.proxies.get('http') if self.proxies else None,
            delay=0,
            verbose=False,
            timeout=self.timeout,
            verify=self.verify,
            test_connection=False
        )
        result_without_auth = unauth_client.query(test_query, variables=test_variables, bypass_auth=True)
        status_without_auth = result_without_auth.get('_status_code', 0)
        
        # Analyze results
        auth_working = False
        auth_required = False
        analysis = ""
        
        # Check for explicit auth errors
        errors_with_auth = result_with_auth.get('errors', [])
        errors_without_auth = result_without_auth.get('errors', [])
        
        error_msgs_with_auth = [e.get('message', '').lower() for e in errors_with_auth]
        error_msgs_without_auth = [e.get('message', '').lower() for e in errors_without_auth]
        
        # If we get 401/403 without auth but 200 with auth, auth is working
        if status_without_auth in [401, 403] and status_with_auth == 200:
            auth_working = True
            auth_required = True
            analysis = "Authentication is WORKING - requests without auth are rejected (401/403), requests with auth succeed (200)"
        # If we get auth errors without auth but not with auth
        elif any('unauthorized' in m or 'authentication' in m or 'forbidden' in m 
                 for m in error_msgs_without_auth) and not any('unauthorized' in m or 'authentication' in m or 'forbidden' in m 
                 for m in error_msgs_with_auth):
            auth_working = True
            auth_required = True
            analysis = "Authentication is WORKING - error messages indicate auth is required and working"
        # If both return same status and errors, check if it's a permission error
        elif status_with_auth == status_without_auth and error_msgs_with_auth == error_msgs_without_auth:
            # Permission errors indicate auth is working but authorization failed
            if any('permission' in m or 'authorization' in m for m in error_msgs_with_auth):
                # Permission errors with same response suggest either:
                # 1. Auth is working but token doesn't have permission (token may be expired/invalid)
                # 2. Auth is not required and permission check happens anyway
                # We'll mark as working since permission errors indicate the server is checking auth
                auth_working = True
                auth_required = True
                analysis = "Authentication appears to be WORKING - permission errors indicate auth is being checked. Same error with/without auth suggests: (1) Token may be expired/invalid, (2) Token not required for this endpoint, or (3) Permission check happens regardless of auth"
            else:
                auth_required = False
                analysis = "Authentication may NOT be required - identical responses with and without auth headers"
        # If both succeed, auth may not be required OR mutation/query doesn't need auth
        elif status_with_auth == 200 and status_without_auth == 200:
            if result_with_auth.get('data') and result_without_auth.get('data'):
                # Both have data - check if they're different
                if result_with_auth.get('data') != result_without_auth.get('data'):
                    auth_working = True
                    auth_required = True
                    analysis = "Authentication is WORKING - different data returned with vs without auth"
                else:
                    auth_required = False
                    analysis = "Authentication may NOT be required - identical data returned with and without auth"
            else:
                # Both have errors - check if they're permission errors
                if error_msgs_with_auth == error_msgs_without_auth:
                    # Same errors - check if permission-related
                    if any('permission' in m or 'authorization' in m for m in error_msgs_with_auth):
                        auth_working = True
                        auth_required = True
                        analysis = "Authentication appears to be WORKING - permission errors indicate auth is checked. Same error with/without auth suggests token may be expired/invalid or not required"
                    else:
                        auth_required = False
                        analysis = "Authentication may NOT be required - same errors with and without auth (likely validation/business logic error)"
                else:
                    auth_working = True
                    auth_required = True
                    analysis = "Authentication appears to be WORKING - different errors with vs without auth"
        # If with auth succeeds but without fails
        elif status_with_auth == 200 and status_without_auth != 200:
            auth_working = True
            auth_required = True
            analysis = f"Authentication is WORKING - request with auth succeeds (200), without auth fails ({status_without_auth})"
        else:
            # Ambiguous case
            analysis = f"Unable to determine auth status - with auth: {status_with_auth}, without auth: {status_without_auth}"
        
        return {
            'auth_working': auth_working,
            'auth_required': auth_required,
            'status_with_auth': status_with_auth,
            'status_without_auth': status_without_auth,
            'response_with_auth': result_with_auth,
            'response_without_auth': result_without_auth,
            'analysis': analysis
        }

