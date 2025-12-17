"""
AuthManager: provider selection, config loading, retry/refresh policy, and redaction.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

import yaml

from .providers import (
    APIKeyProvider,
    AuthProvider,
    BearerTokenProvider,
    CookieSessionProvider,
    OAuth2Provider,
    ProviderError,
    ScriptedProvider,
    StaticHeadersProvider,
)
from .redact import redact_headers as _redact_headers, sanitize_finding


class AuthConfigError(Exception):
    pass


class AuthRuntimeError(Exception):
    pass


def _parse_kv_list(items: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for item in items or []:
        if "=" not in item:
            continue
        k, v = item.split("=", 1)
        out[k.strip()] = v
    return out


def _env_vars(prefix: str = "GQLH_") -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in os.environ.items():
        if k.startswith(prefix):
            out[k[len(prefix) :].lower()] = v
    return out


def _normalize_profile_name(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    return str(s).strip()


@dataclass
class AuthSelection:
    provider: Optional[AuthProvider]
    profile_name: Optional[str] = None
    profile_type: Optional[str] = None


class AuthManager:
    def __init__(
        self,
        *,
        reporter=None,
        auth_config_path: Optional[str] = None,
        auth_profile: Optional[str] = None,
        detect: bool = True,
        auth_vars: Optional[Dict[str, str]] = None,
        extra_sensitive_headers: Optional[List[str]] = None,
    ):
        self.reporter = reporter
        self.detect = detect
        self.auth_config_path = auth_config_path
        self.auth_profile = _normalize_profile_name(auth_profile)

        merged_vars: Dict[str, str] = {}
        merged_vars.update(_env_vars())
        if auth_vars:
            merged_vars.update(auth_vars)
        self.vars = merged_vars

        self.extra_sensitive_headers = extra_sensitive_headers or []

        self._selection: AuthSelection = AuthSelection(provider=None)
        self._prepared = False

    @staticmethod
    def from_cli_args(args, reporter=None) -> "AuthManager":
        auth_vars = _parse_kv_list(getattr(args, "auth_vars", None) or [])
        extra_sensitive = []
        return AuthManager(
            reporter=reporter,
            auth_config_path=getattr(args, "auth_config", None),
            auth_profile=getattr(args, "auth_profile", None),
            detect=getattr(args, "auth_detect", True),
            auth_vars=auth_vars,
            extra_sensitive_headers=extra_sensitive,
        )

    def select_provider(self, *, token: Optional[str], headers: Dict[str, str]) -> AuthSelection:
        # Explicit profile wins.
        if self.auth_profile:
            prof = self._load_profile(self.auth_profile)
            provider = self._provider_from_profile(prof)
            self._selection = AuthSelection(provider=provider, profile_name=self.auth_profile, profile_type=prof.get("type"))
            return self._selection

        # Derive from existing CLI flags: -t/-H
        if token or headers:
            h = dict(headers or {})
            if token:
                h["Authorization"] = f"Bearer {token}"
            provider = StaticHeadersProvider(profile={"headers": h}, variables=self.vars, reporter=self.reporter)
            self._selection = AuthSelection(provider=provider, profile_name=None, profile_type="static_headers")
            return self._selection

        # No auth configured.
        self._selection = AuthSelection(provider=None)
        return self._selection

    def ensure_prepared(self, client) -> None:
        if self._prepared:
            return
        if self._selection.provider:
            self._selection.provider.prepare(client)
        self._prepared = True

    def get_request_headers(self) -> Dict[str, str]:
        if not self._selection.provider:
            return {}
        return self._selection.provider.headers_for_request()

    def maybe_refresh_and_retry(self, client, status_code: int, result: Dict[str, Any]) -> bool:
        """
        Decide whether to refresh and retry once.
        Returns True if caller should retry the request.
        """
        provider = self._selection.provider
        if not provider:
            if self.detect and self._looks_like_auth_failure(status_code, result):
                self._diagnose_auth_failure(status_code, result)
            return False

        if provider.is_auth_failure(status_code, result) and provider.can_refresh():
            if self.reporter and hasattr(self.reporter, "print_info"):
                self.reporter.print_info("Auth failure detected; attempting refresh and retry once...")
            ok = provider.refresh(client)
            return bool(ok)

        if self.detect and provider.is_auth_failure(status_code, result):
            self._diagnose_auth_failure(status_code, result)
        return False

    def redact_headers(self, headers: Mapping[str, Any]) -> Dict[str, Any]:
        provider = self._selection.provider
        sensitive = set(self.extra_sensitive_headers or [])
        if provider:
            sensitive |= set(provider.sensitive_header_names() or [])
        return _redact_headers(headers, sensitive_header_names=sensitive)

    def sanitize_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        provider = self._selection.provider
        sensitive = set(self.extra_sensitive_headers or [])
        if provider:
            sensitive |= set(provider.sensitive_header_names() or [])
        return sanitize_finding(finding, extra_sensitive_headers=sensitive)

    def _load_profile(self, profile_name: str) -> Dict[str, Any]:
        path = self.auth_config_path
        if not path:
            raise AuthConfigError("auth_profile specified but no auth_config_path provided")
        if not os.path.exists(path):
            raise AuthConfigError(f"Auth config not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        profiles = cfg.get("profiles") or {}
        if profile_name not in profiles:
            raise AuthConfigError(f"Auth profile not found: {profile_name}")
        prof = profiles[profile_name] or {}
        if "type" not in prof:
            raise AuthConfigError(f"Auth profile '{profile_name}' missing type")
        return prof

    def _provider_from_profile(self, prof: Dict[str, Any]) -> AuthProvider:
        ptype = prof.get("type")
        if ptype == "api_key":
            return APIKeyProvider(prof, self.vars, reporter=self.reporter)
        if ptype == "bearer":
            return BearerTokenProvider(prof, self.vars, reporter=self.reporter)
        if ptype in ("oauth2_client_credentials", "oauth2_refresh_token", "oauth2_auth_code", "oauth2_device_code"):
            return OAuth2Provider(prof, self.vars, reporter=self.reporter)
        if ptype == "cookie_session":
            return CookieSessionProvider(prof, self.vars, reporter=self.reporter)
        if ptype == "scripted":
            return ScriptedProvider(prof, self.vars, reporter=self.reporter)
        raise AuthConfigError(f"Unknown auth profile type: {ptype}")

    def _looks_like_auth_failure(self, status_code: int, result: Dict[str, Any]) -> bool:
        # basic heuristic, provider-specific logic lives in provider
        if status_code in (401, 403):
            return True
        msg = ""
        try:
            errs = result.get("errors") or []
            msg = " | ".join([str(e.get("message", e)) for e in errs if e]).lower()
        except Exception:
            msg = str(result.get("errors", "")).lower()
        needles = ["unauthorized", "forbidden", "unauthenticated", "not authenticated", "invalid token", "csrf"]
        return any(n in msg for n in needles)

    def _diagnose_auth_failure(self, status_code: int, result: Dict[str, Any]) -> None:
        if not self.reporter:
            return
        msg = ""
        try:
            errs = result.get("errors") or []
            msg = " | ".join([str(e.get("message", e)) for e in errs if e])[:300]
        except Exception:
            msg = str(result.get("errors", ""))[:300]

        if hasattr(self.reporter, "print_warning"):
            self.reporter.print_warning(f"Possible auth/CSRF issue (status={status_code}). {msg}")
            self.reporter.print_warning("If this endpoint requires auth, supply -t/--token, -H headers, or --auth-profile with --auth-config.")


