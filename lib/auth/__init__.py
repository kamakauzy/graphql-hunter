"""
Authentication workflow engine for GraphQL Hunter.

This package provides:
- AuthManager: selection, preparation, refresh/retry, and redaction orchestration
- Providers: concrete auth implementations (API key, bearer, OAuth2, cookie session, scripted)
- Flow runner: multi-step acquisition workflows (HTTP + GraphQL steps) with value extraction
"""

from .manager import AuthManager, AuthConfigError, AuthRuntimeError


