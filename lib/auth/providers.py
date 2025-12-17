"""
Auth providers for GraphQL Hunter.

Each provider can:
- prepare(): acquire credentials (optional)
- headers_for_request(): inject request headers (Authorization, x-api-key, CSRF, etc.)
- is_auth_failure(): detect failures (HTTP status or GraphQL error patterns)
- refresh(): refresh credentials (optional)
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import urlencode

from .flows import FlowRunner, FlowError, render_template


class ProviderError(Exception):
    pass


def _now() -> float:
    return time.time()


def _b64_basic(user: str, pw: str) -> str:
    raw = f"{user}:{pw}".encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _graphqLError_messages(result: Dict[str, Any]) -> str:
    errs = result.get("errors") or []
    try:
        return " | ".join([str(e.get("message", e)) for e in errs if e])
    except Exception:
        return str(errs)


def _looks_like_auth_failure(status_code: int, result: Dict[str, Any]) -> bool:
    if status_code in (401, 403):
        return True
    msg = _graphqLError_messages(result).lower()
    needles = [
        "unauthorized",
        "forbidden",
        "not authenticated",
        "unauthenticated",
        "authentication",
        "invalid token",
        "missing token",
        "jwt",
        "token expired",
        "access denied",
        "csrf",
    ]
    return any(n in msg for n in needles)


@dataclass
class Token:
    access_token: str
    token_type: str = "Bearer"
    expires_at: Optional[float] = None

    def is_expired(self, skew_seconds: int = 30) -> bool:
        if self.expires_at is None:
            return False
        return _now() >= (self.expires_at - skew_seconds)


class AuthProvider:
    def __init__(self, profile: Dict[str, Any], variables: Dict[str, str], reporter=None):
        self.profile = profile or {}
        self.vars = variables
        self.reporter = reporter

    def prepare(self, client) -> None:
        return None

    def headers_for_request(self) -> Dict[str, str]:
        return {}

    def is_auth_failure(self, status_code: int, result: Dict[str, Any]) -> bool:
        return _looks_like_auth_failure(status_code, result)

    def can_refresh(self) -> bool:
        return False

    def refresh(self, client) -> bool:
        return False

    def sensitive_header_names(self) -> List[str]:
        # allow per-provider augmentation
        return []


class StaticHeadersProvider(AuthProvider):
    """Just injects static headers (useful for -H and/or -t mapping)."""

    def headers_for_request(self) -> Dict[str, str]:
        headers = self.profile.get("headers") or {}
        return {k: str(v) for k, v in headers.items()}

    def sensitive_header_names(self) -> List[str]:
        return list((self.profile.get("sensitive_headers") or []))


class APIKeyProvider(AuthProvider):
    def headers_for_request(self) -> Dict[str, str]:
        header_name = self.profile.get("header_name") or "x-api-key"
        value = self.vars.get(self.profile.get("var") or "api_key") or self.profile.get("value")
        if not value:
            raise ProviderError(f"API key missing. Provide via --auth-var {(self.profile.get('var') or 'api_key')}=...")
        prefix = self.profile.get("prefix") or ""
        v = f"{prefix}{value}" if prefix else str(value)
        return {header_name: v}

    def sensitive_header_names(self) -> List[str]:
        return [str(self.profile.get("header_name") or "x-api-key")]


class BearerTokenProvider(AuthProvider):
    def headers_for_request(self) -> Dict[str, str]:
        header_name = self.profile.get("header_name") or "Authorization"
        token = self.vars.get(self.profile.get("var") or "access_token") or self.profile.get("token")
        if not token:
            raise ProviderError(f"Bearer token missing. Provide via --auth-var {(self.profile.get('var') or 'access_token')}=... or -t/--token")
        prefix = self.profile.get("prefix") or "Bearer "
        if prefix and not prefix.endswith(" "):
            prefix = prefix + " "
        return {header_name: f"{prefix}{token}"}

    def sensitive_header_names(self) -> List[str]:
        return [str(self.profile.get("header_name") or "Authorization")]


class OAuth2Provider(AuthProvider):
    """
    OAuth2/OIDC provider variants.

    Supported profile.type values:
    - oauth2_client_credentials
    - oauth2_refresh_token
    - oauth2_auth_code  (semi-manual: user provides code via --auth-var oauth_code=...)
    - oauth2_device_code (semi-manual: tool prints user_code/verification_uri and polls)
    """

    def __init__(self, profile: Dict[str, Any], variables: Dict[str, str], reporter=None):
        super().__init__(profile, variables, reporter)
        self.token: Optional[Token] = None

    def prepare(self, client) -> None:
        if self.token and not self.token.is_expired():
            return
        self._acquire_token(client)

    def can_refresh(self) -> bool:
        return True

    def refresh(self, client) -> bool:
        try:
            self._acquire_token(client, force=True)
            return True
        except Exception:
            return False

    def headers_for_request(self) -> Dict[str, str]:
        if not self.token or self.token.is_expired():
            raise ProviderError("OAuth token not available or expired; did acquire fail?")
        return {"Authorization": f"{self.token.token_type} {self.token.access_token}"}

    def sensitive_header_names(self) -> List[str]:
        return ["Authorization"]

    def _token_request(
        self,
        client,
        *,
        token_url: str,
        data: Dict[str, str],
        client_id: Optional[str],
        client_secret: Optional[str],
        auth_method: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        sess = getattr(client, "session", None)
        proxies = getattr(client, "proxies", None)
        timeout = getattr(client, "timeout", 30)
        verify = getattr(client, "verify", True)
        if sess is None:
            raise ProviderError("GraphQLClient does not expose a requests.Session() as 'session'")

        req_headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if headers:
            req_headers.update(headers)

        if auth_method == "basic":
            if not client_id or not client_secret:
                raise ProviderError("OAuth basic auth requires client_id and client_secret")
            req_headers["Authorization"] = f"Basic {_b64_basic(client_id, client_secret)}"
        elif auth_method == "body":
            if client_id:
                data["client_id"] = client_id
            if client_secret:
                data["client_secret"] = client_secret
        else:
            raise ProviderError(f"Unknown oauth auth_method: {auth_method}")

        resp = sess.post(
            token_url,
            headers=req_headers,
            data=urlencode(data),
            proxies=proxies,
            timeout=timeout,
            verify=verify,
        )
        try:
            j = resp.json()
        except Exception:
            raise ProviderError(f"OAuth token endpoint returned non-JSON (status {resp.status_code})")

        if resp.status_code >= 400 or "error" in j:
            raise ProviderError(f"OAuth token error: {j}")
        return j

    def _acquire_token(self, client, force: bool = False) -> None:
        profile_type = self.profile.get("type")
        token_url = self.profile.get("token_url")
        if not token_url:
            raise ProviderError("OAuth profile missing token_url")

        client_id = self.vars.get(self.profile.get("client_id_var") or "client_id") or self.profile.get("client_id")
        client_secret = self.vars.get(self.profile.get("client_secret_var") or "client_secret") or self.profile.get("client_secret")
        scope = self.vars.get(self.profile.get("scope_var") or "scope") or self.profile.get("scope")
        audience = self.vars.get(self.profile.get("audience_var") or "audience") or self.profile.get("audience")
        auth_method = self.profile.get("auth_method") or "body"  # body|basic

        data: Dict[str, str] = {}
        if scope:
            data["scope"] = str(scope)
        if audience:
            data["audience"] = str(audience)

        if profile_type == "oauth2_client_credentials":
            data["grant_type"] = "client_credentials"

        elif profile_type == "oauth2_refresh_token":
            data["grant_type"] = "refresh_token"
            refresh_token = self.vars.get(self.profile.get("refresh_token_var") or "refresh_token") or self.profile.get("refresh_token")
            if not refresh_token:
                raise ProviderError("Missing refresh_token for oauth2_refresh_token")
            data["refresh_token"] = str(refresh_token)

        elif profile_type == "oauth2_auth_code":
            data["grant_type"] = "authorization_code"
            redirect_uri = self.profile.get("redirect_uri") or self.vars.get("redirect_uri")
            if redirect_uri:
                data["redirect_uri"] = str(redirect_uri)
            code_var = self.profile.get("code_var") or "oauth_code"
            code = self.vars.get(code_var) or self.profile.get("code")
            if not code:
                authorize_url = self.profile.get("authorize_url")
                if authorize_url and client_id and redirect_uri:
                    params = {
                        "response_type": "code",
                        "client_id": client_id,
                        "redirect_uri": redirect_uri,
                    }
                    if scope:
                        params["scope"] = scope
                    url = authorize_url + ("&" if "?" in authorize_url else "?") + urlencode(params)
                    if self.reporter and hasattr(self.reporter, "print_info"):
                        self.reporter.print_info(f"OAuth auth-code: open this URL, then provide code via --auth-var {code_var}=...")
                        self.reporter.print_info(url)
                raise ProviderError(f"Missing auth code. Provide via --auth-var {code_var}=...")
            data["code"] = str(code)

        elif profile_type == "oauth2_device_code":
            # Device flow: request device_code then poll token endpoint
            device_url = self.profile.get("device_authorization_url")
            if not device_url:
                raise ProviderError("oauth2_device_code requires device_authorization_url")
            if not client_id:
                raise ProviderError("oauth2_device_code requires client_id")

            sess = getattr(client, "session", None)
            proxies = getattr(client, "proxies", None)
            timeout = getattr(client, "timeout", 30)
            verify = getattr(client, "verify", True)
            if sess is None:
                raise ProviderError("GraphQLClient does not expose a requests.Session() as 'session'")

            device_req = {"client_id": client_id}
            if scope:
                device_req["scope"] = str(scope)
            resp = sess.post(
                device_url,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data=urlencode(device_req),
                proxies=proxies,
                timeout=timeout,
                verify=verify,
            )
            j = resp.json()
            if resp.status_code >= 400 or "error" in j:
                raise ProviderError(f"OAuth device authorization error: {j}")

            user_code = j.get("user_code")
            verification_uri = j.get("verification_uri") or j.get("verification_uri_complete")
            device_code = j.get("device_code")
            interval = int(j.get("interval") or 5)
            expires_in = int(j.get("expires_in") or 600)

            if self.reporter and hasattr(self.reporter, "print_warning"):
                self.reporter.print_warning("OAuth device-code flow: complete verification in your browser")
                if verification_uri:
                    self.reporter.print_warning(f"Visit: {verification_uri}")
                if user_code:
                    self.reporter.print_warning(f"User code: {user_code}")

            if not device_code:
                raise ProviderError("Device flow did not return device_code")

            poll_deadline = _now() + expires_in
            while _now() < poll_deadline:
                poll_data = {
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                    "client_id": client_id,
                }
                try:
                    token_json = self._token_request(
                        client,
                        token_url=token_url,
                        data=poll_data,
                        client_id=None,
                        client_secret=None,
                        auth_method="body",
                    )
                    self._store_token(token_json)
                    return
                except ProviderError as e:
                    # Expected during polling: authorization_pending, slow_down
                    msg = str(e)
                    if "authorization_pending" in msg:
                        time.sleep(interval)
                        continue
                    if "slow_down" in msg:
                        interval += 5
                        time.sleep(interval)
                        continue
                    raise

            raise ProviderError("Device flow timed out waiting for user authorization")

        else:
            raise ProviderError(f"Unknown OAuth profile type: {profile_type}")

        token_json = self._token_request(
            client,
            token_url=token_url,
            data=data,
            client_id=client_id,
            client_secret=client_secret,
            auth_method=auth_method,
        )
        self._store_token(token_json)

    def _store_token(self, token_json: Dict[str, Any]) -> None:
        access_token = token_json.get("access_token")
        if not access_token:
            raise ProviderError("OAuth response missing access_token")
        token_type = token_json.get("token_type") or "Bearer"
        expires_in = token_json.get("expires_in")
        expires_at = None
        try:
            if expires_in is not None:
                expires_at = _now() + int(expires_in)
        except Exception:
            expires_at = None
        self.token = Token(access_token=str(access_token), token_type=str(token_type), expires_at=expires_at)
        # Export to variables for templating / scripted providers
        self.vars["access_token"] = str(access_token)


class CookieSessionProvider(AuthProvider):
    """
    Cookie-session auth.
    - Runs scripted login flow steps in prepare() to populate cookies and any vars (e.g., csrf_token)
    - Optionally injects CSRF header from a variable
    """

    def __init__(self, profile: Dict[str, Any], variables: Dict[str, str], reporter=None):
        super().__init__(profile, variables, reporter)
        self._prepared = False
        self._flow = FlowRunner(reporter=reporter, verbose=False)

    def prepare(self, client) -> None:
        if self._prepared:
            return
        steps = self.profile.get("login_steps") or []
        if steps:
            self._flow.run(client=client, steps=steps, variables=self.vars)
        self._prepared = True

    def headers_for_request(self) -> Dict[str, str]:
        csrf = self.profile.get("csrf") or {}
        if not csrf:
            return {}
        header_name = csrf.get("header_name")
        var = csrf.get("var") or "csrf_token"
        if not header_name:
            return {}
        value = self.vars.get(var)
        if not value:
            return {}
        return {str(header_name): str(value)}

    def sensitive_header_names(self) -> List[str]:
        csrf = self.profile.get("csrf") or {}
        header_name = csrf.get("header_name")
        return [str(header_name)] if header_name else []


class ScriptedProvider(AuthProvider):
    """
    Generic provider with:\n
    - acquire_steps: run once to populate variables/cookies\n
    - inject_headers: dict of header templates using {{var}}\n
    """

    def __init__(self, profile: Dict[str, Any], variables: Dict[str, str], reporter=None):
        super().__init__(profile, variables, reporter)
        self._prepared = False
        self._flow = FlowRunner(reporter=reporter, verbose=False)

    def prepare(self, client) -> None:
        if self._prepared:
            return
        steps = self.profile.get("acquire_steps") or []
        if steps:
            self._flow.run(client=client, steps=steps, variables=self.vars)
        self._prepared = True

    def headers_for_request(self) -> Dict[str, str]:
        headers = self.profile.get("inject_headers") or {}
        headers = render_template(headers, self.vars)
        return {k: str(v) for k, v in headers.items()}

    def sensitive_header_names(self) -> List[str]:
        return list((self.profile.get("sensitive_headers") or []))


