#!/usr/bin/env python3
"""
Schema introspection utilities
"""

from typing import Any, Dict, List, Optional, Set

from utils import extract_type_name, type_signature as render_type_signature


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
            if type_def.get('name', '').startswith('__'):
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
            if type_def.get('name', '').startswith('__'):
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
            if type_def.get('name', '').startswith('__'):
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
    
    def find_upload_mutations(self) -> List[Dict]:
        """Find mutations that accept Upload type arguments"""
        upload_mutations = []
        
        mutations = self.get_mutations()
        for mutation in mutations:
            args = mutation.get('args', [])
            for arg in args:
                arg_type = self._extract_type_name(arg.get('type', {}))
                if arg_type == 'Upload' or 'Upload' in str(arg_type):
                    upload_mutations.append(mutation)
                    break
        
        return upload_mutations

    def type_signature(self, type_def: Dict) -> str:
        """Render a GraphQL type while preserving wrappers."""
        return render_type_signature(type_def)

    def resolve_type(self, type_def: Dict) -> Optional[Dict]:
        """Resolve a nested type reference to its schema definition."""
        type_name = self._extract_type_name(type_def)
        if type_name == "Unknown":
            return None
        return self.types.get(type_name)

    def is_leaf_type(self, type_def: Dict) -> bool:
        """Return True for scalars and enums."""
        resolved = self.resolve_type(type_def)
        if resolved:
            return resolved.get('kind') in {'SCALAR', 'ENUM'}
        return self._extract_type_name(type_def) in {'String', 'Int', 'Float', 'Boolean', 'ID'}

    def is_input_object(self, type_def: Dict) -> bool:
        """Return True for GraphQL input object types."""
        resolved = self.resolve_type(type_def)
        return bool(resolved and resolved.get('kind') == 'INPUT_OBJECT')

    def default_value_for_type(self, type_def: Dict, max_depth: int = 2, visited: Optional[Set[str]] = None) -> Any:
        """Build a minimal JSON-serializable value for the given GraphQL type."""
        visited = visited or set()
        if not type_def:
            return "test"

        kind = type_def.get('kind')
        if kind == 'NON_NULL':
            return self.default_value_for_type(type_def.get('ofType', {}), max_depth=max_depth, visited=visited)
        if kind == 'LIST':
            return [self.default_value_for_type(type_def.get('ofType', {}), max_depth=max_depth - 1, visited=visited)]

        type_name = self._extract_type_name(type_def)
        if type_name in {'String', 'ID', 'Upload'}:
            return "test"
        if type_name == 'Int':
            return 1
        if type_name == 'Float':
            return 1.0
        if type_name == 'Boolean':
            return True

        resolved = self.types.get(type_name)
        if not resolved:
            return "test"

        if resolved.get('kind') == 'ENUM':
            enum_values = resolved.get('enumValues') or []
            return enum_values[0].get('name') if enum_values else None

        if resolved.get('kind') == 'INPUT_OBJECT':
            if max_depth <= 0 or type_name in visited:
                return None
            visited.add(type_name)
            value = {}
            for field in resolved.get('inputFields', []):
                field_value = self.default_value_for_type(field.get('type', {}), max_depth=max_depth - 1, visited=visited)
                if field_value is not None:
                    value[field.get('name')] = field_value
            visited.discard(type_name)
            return value

        return None

    def minimal_selection_set(self, type_def: Dict, max_depth: int = 2, visited: Optional[Set[str]] = None) -> str:
        """Build a minimal but valid selection set for an output type."""
        visited = visited or set()
        if self.is_leaf_type(type_def):
            return ""

        resolved = self.resolve_type(type_def)
        if not resolved:
            return "{ __typename }"

        type_name = resolved.get('name')
        if max_depth <= 0 or type_name in visited:
            return "{ __typename }"

        fields = resolved.get('fields') or []
        if not fields:
            return "{ __typename }"

        visited.add(type_name)
        preferred_fields = ['id', 'uid', 'name', 'title', 'email', 'success', 'message']
        selections: List[str] = []

        for preferred in preferred_fields:
            for field in fields:
                if field.get('name') == preferred and not field.get('args') and self.is_leaf_type(field.get('type', {})):
                    selections.append(preferred)
                    break

        if not selections:
            for field in fields:
                if field.get('args'):
                    continue
                if self.is_leaf_type(field.get('type', {})):
                    selections.append(field.get('name'))
                else:
                    nested = self.minimal_selection_set(field.get('type', {}), max_depth=max_depth - 1, visited=visited)
                    if nested:
                        selections.append(f"{field.get('name')} {nested}")
                if len(selections) >= 3:
                    break

        visited.discard(type_name)
        if not selections:
            return "{ __typename }"
        return "{ " + " ".join(selections[:3]) + " }"

    def build_operation(
        self,
        field: Dict,
        operation_kind: str,
        overrides: Optional[Dict[str, Any]] = None,
        max_depth: int = 2,
    ) -> Dict[str, Any]:
        """Build a schema-valid operation for a query or mutation field."""
        overrides = overrides or {}
        field_name = field.get('name')
        args = field.get('args', [])
        variables = {}
        var_defs = []
        arg_uses = []

        for arg in args:
            arg_name = arg.get('name')
            arg_type = arg.get('type', {})
            value = overrides.get(arg_name, self.default_value_for_type(arg_type, max_depth=max_depth))
            if value is None:
                return {
                    'testable': False,
                    'skip_reason': f"Unable to generate value for argument '{arg_name}'",
                    'query': None,
                    'variables': None,
                    'operation_name': None,
                }

            variables[arg_name] = value
            var_defs.append(f"${arg_name}: {self.type_signature(arg_type)}")
            arg_uses.append(f"{arg_name}: ${arg_name}")

        selection = self.minimal_selection_set(field.get('type', {}), max_depth=max_depth)
        operation_name = f"Auto{operation_kind.title()}{field_name[0].upper()}{field_name[1:]}" if field_name else "AutoGeneratedOperation"
        var_defs_part = f"({', '.join(var_defs)})" if var_defs else ""
        arg_uses_part = f"({', '.join(arg_uses)})" if arg_uses else ""
        selection_part = f" {selection}" if selection else ""
        query = f"{operation_kind} {operation_name}{var_defs_part} {{ {field_name}{arg_uses_part}{selection_part} }}"

        return {
            'testable': True,
            'skip_reason': None,
            'query': query,
            'variables': variables,
            'operation_name': operation_name,
        }
    
    def _extract_type_name(self, type_def: Dict) -> str:
        """Extract type name from type definition"""
        if not type_def:
            return "Unknown"
        
        if type_def.get('name'):
            return type_def['name']
        
        if type_def.get('ofType'):
            return self._extract_type_name(type_def['ofType'])
        
        return "Unknown"

