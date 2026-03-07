"""
Secret redaction helpers.

Goal: never leak credentials in verbose logs or reports.
We redact by header name and by common token patterns.
"""

from __future__ import annotations

import copy
import re
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Sequence, Set


DEFAULT_SENSITIVE_HEADERS: Set[str] = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "token",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "csrf-token",
    "xsrf-token",
    # Common credential fields (often appear in JSON bodies / variables / evidence)
    "password",
    "pass",
    "passwd",
    "client_secret",
    "refresh_token",
    "access_token",
    "id_token",
    "device_code",
    "code",
}


def _mask(value: str) -> str:
    if value is None:
        return value
    v = str(value)
    if len(v) <= 8:
        return "***REDACTED***"
    return v[:3] + "***REDACTED***" + v[-3:]


def redact_headers(headers: Mapping[str, Any], sensitive_header_names: Iterable[str] | None = None) -> Dict[str, Any]:
    """Return a redacted copy of headers."""
    if headers is None:
        return {}
    sensitive = {h.lower() for h in (sensitive_header_names or DEFAULT_SENSITIVE_HEADERS)}
    out: Dict[str, Any] = {}
    for k, v in headers.items():
        if k is None:
            continue
        if str(k).lower() in sensitive:
            out[k] = _mask(v)
        else:
            out[k] = v
    return out


_BEARER_RE = re.compile(r"\bBearer\s+([A-Za-z0-9\-\._~\+/]+=*)", re.IGNORECASE)
_JWT_RE = re.compile(r"\b(eyJ[A-Za-z0-9\-_]+)\.([A-Za-z0-9\-_]{5,})\.([A-Za-z0-9\-_]{5,})\b")


def redact_text(text: str) -> str:
    """Redact common token patterns from arbitrary text."""
    if not text:
        return text
    redacted = _BEARER_RE.sub("Bearer ***REDACTED***", text)
    # JWTs can appear without 'Bearer'
    redacted = _JWT_RE.sub("***REDACTED_JWT***", redacted)
    return redacted


def redact_obj(obj: Any, sensitive_keys: Iterable[str] | None = None) -> Any:
    """
    Deep-redact dict/list structures.
    - If a dict key is sensitive, its value is masked.
    - If a value is a string, we also apply token-pattern redaction.
    """
    sens = {k.lower() for k in (sensitive_keys or DEFAULT_SENSITIVE_HEADERS)}

    if isinstance(obj, Mapping):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            k_str = str(k)
            if k_str.lower() in sens:
                out[k_str] = _mask(v)
            else:
                out[k_str] = redact_obj(v, sens)
        return out

    if isinstance(obj, Sequence) and not isinstance(obj, (str, bytes, bytearray)):
        return [redact_obj(x, sens) for x in obj]

    if isinstance(obj, str):
        return redact_text(obj)

    return obj


def sanitize_finding(finding: Dict[str, Any], extra_sensitive_headers: Iterable[str] | None = None) -> Dict[str, Any]:
    """
    Return a redacted copy of a finding safe for printing/saving.

    This avoids leaking auth material inside evidence/poc/curl/burp strings.
    """
    if not finding:
        return finding
    sensitive = set(DEFAULT_SENSITIVE_HEADERS)
    if extra_sensitive_headers:
        sensitive |= {h.lower() for h in extra_sensitive_headers}

    safe = copy.deepcopy(finding)
    safe = redact_obj(safe, sensitive)
    return safe


