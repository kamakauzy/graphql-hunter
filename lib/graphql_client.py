#!/usr/bin/env python3
"""
GraphQL Client - Handles all GraphQL requests and introspection
"""

import requests
import json
import time
from typing import Dict, List, Optional, Any


class GraphQLClient:
    """Client for interacting with GraphQL endpoints"""
    
    def __init__(self, url: str, headers: Optional[Dict] = None, 
                 proxy: Optional[str] = None, delay: float = 0, 
                 verbose: bool = False, timeout: int = 30):
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
        self.schema = None
        self.introspection_enabled = None
        
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
        self._test_connection()
    
    def _test_connection(self):
        """Test connection to GraphQL endpoint"""
        try:
            response = requests.post(
                self.url,
                headers=self.headers,
                json={'query': '{__typename}'},
                proxies=self.proxies,
                timeout=self.timeout,
                verify=True
            )
            if response.status_code not in [200, 400]:
                raise Exception(f"Unexpected status code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            raise Exception(f"Connection failed: {e}")
    
    def query(self, query: str, variables: Optional[Dict] = None, 
              operation_name: Optional[str] = None) -> Dict:
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
            print(f"[DEBUG] Headers: {json.dumps(self.headers, indent=2)}")
            print(f"[DEBUG] Payload: {json.dumps(payload, indent=2)}")
        
        try:
            response = requests.post(
                self.url,
                headers=self.headers,
                json=payload,
                proxies=self.proxies,
                timeout=self.timeout,
                verify=True
            )
            
            if self.verbose:
                print(f"[DEBUG] Response Status: {response.status_code}")
                print(f"[DEBUG] Response Body: {response.text[:1000]}")
            
            # Try to parse JSON
            try:
                result = response.json()
            except json.JSONDecodeError:
                result = {
                    'errors': [{'message': f'Non-JSON response: {response.text[:200]}'}],
                    'status_code': response.status_code,
                    'raw_response': response.text
                }
            
            # Add metadata
            result['_status_code'] = response.status_code
            result['_headers'] = dict(response.headers)
            
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
        
        query_type_name = self.schema.get('queryType', {}).get('name')
        if not query_type_name:
            return []
        
        for type_def in self.schema.get('types', []):
            if type_def.get('name') == query_type_name:
                return type_def.get('fields', [])
        
        return []
    
    def get_mutations(self) -> List[Dict]:
        """Get all available mutations from schema"""
        if not self.schema:
            self.introspect()
        
        if not self.schema:
            return []
        
        mutation_type_name = self.schema.get('mutationType', {}).get('name')
        if not mutation_type_name:
            return []
        
        for type_def in self.schema.get('types', []):
            if type_def.get('name') == mutation_type_name:
                return type_def.get('fields', [])
        
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
            response = requests.post(
                self.url,
                headers=self.headers,
                json=queries,
                proxies=self.proxies,
                timeout=self.timeout,
                verify=True
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

