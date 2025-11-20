#!/usr/bin/env python3
"""
Schema introspection utilities
"""

from typing import Dict, List, Optional


class SchemaParser:
    """Parse and analyze GraphQL schema"""
    
    def __init__(self, schema: Dict):
        """
        Initialize schema parser
        
        Args:
            schema: Introspection schema result
        """
        self.schema = schema
        self.types = {}
        
        # Safely parse types
        if schema and isinstance(schema, dict):
            types_list = schema.get('types', [])
            if types_list:
                self.types = {t['name']: t for t in types_list if t and 'name' in t}
        
        self.query_type = schema.get('queryType', {}).get('name') if schema else None
        self.mutation_type = schema.get('mutationType', {}).get('name') if schema and schema.get('mutationType') else None
        self.subscription_type = schema.get('subscriptionType', {}).get('name') if schema and schema.get('subscriptionType') else None
    
    def get_queries(self) -> List[Dict]:
        """Get all query fields"""
        if not self.query_type:
            return []
        query_type = self.types.get(self.query_type)
        if not query_type:
            return []
        return query_type.get('fields', [])
    
    def get_mutations(self) -> List[Dict]:
        """Get all mutation fields"""
        if not self.mutation_type:
            return []
        mutation_type = self.types.get(self.mutation_type)
        if not mutation_type:
            return []
        return mutation_type.get('fields', [])
    
    def get_subscriptions(self) -> List[Dict]:
        """Get all subscription fields"""
        if not self.subscription_type:
            return []
        subscription_type = self.types.get(self.subscription_type)
        if not subscription_type:
            return []
        return subscription_type.get('fields', [])
    
    def get_custom_types(self) -> List[Dict]:
        """Get custom (non-builtin) types"""
        builtin_prefixes = ('__', )
        builtin_types = {'String', 'Int', 'Float', 'Boolean', 'ID'}
        
        custom = []
        for type_def in self.schema.get('types', []):
            name = type_def.get('name', '')
            if name.startswith(builtin_prefixes) or name in builtin_types:
                continue
            if type_def.get('kind') == 'OBJECT':
                custom.append(type_def)
        
        return custom
    
    def find_fields_with_args(self) -> List[Dict]:
        """Find all fields that accept arguments"""
        fields_with_args = []
        
        for type_def in self.schema.get('types', []):
            if type_def.get('kind') != 'OBJECT':
                continue
            
            for field in type_def.get('fields', []):
                if field.get('args'):
                    fields_with_args.append({
                        'type': type_def.get('name'),
                        'field': field.get('name'),
                        'args': field.get('args')
                    })
        
        return fields_with_args
    
    def find_deprecated_fields(self) -> List[Dict]:
        """Find deprecated fields"""
        deprecated = []
        
        for type_def in self.schema.get('types', []):
            if type_def.get('kind') != 'OBJECT':
                continue
            
            for field in type_def.get('fields', []):
                if field.get('isDeprecated'):
                    deprecated.append({
                        'type': type_def.get('name'),
                        'field': field.get('name'),
                        'reason': field.get('deprecationReason', 'No reason provided')
                    })
        
        return deprecated
    
    def find_sensitive_field_names(self) -> List[Dict]:
        """Find fields with potentially sensitive names"""
        sensitive_keywords = [
            'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey',
            'private', 'credential', 'auth', 'ssn', 'credit_card', 'cvv',
            'pin', 'admin', 'internal', 'debug'
        ]
        
        sensitive_fields = []
        
        for type_def in self.schema.get('types', []):
            if type_def.get('kind') != 'OBJECT':
                continue
            
            for field in type_def.get('fields', []):
                field_name = field.get('name', '').lower()
                for keyword in sensitive_keywords:
                    if keyword in field_name:
                        sensitive_fields.append({
                            'type': type_def.get('name'),
                            'field': field.get('name'),
                            'keyword': keyword
                        })
                        break
        
        return sensitive_fields
    
    def analyze_complexity(self) -> Dict:
        """Analyze schema complexity"""
        total_types = len([t for t in self.schema.get('types', []) 
                          if not t.get('name', '').startswith('__')])
        total_queries = len(self.get_queries())
        total_mutations = len(self.get_mutations())
        total_subscriptions = len(self.get_subscriptions())
        
        return {
            'total_types': total_types,
            'total_queries': total_queries,
            'total_mutations': total_mutations,
            'total_subscriptions': total_subscriptions,
            'has_mutations': total_mutations > 0,
            'has_subscriptions': total_subscriptions > 0
        }

