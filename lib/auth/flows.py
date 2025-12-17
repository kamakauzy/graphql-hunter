"""
Scripted auth flow runner.

Supports multi-step credential acquisition:
- HTTP steps (GET/POST) with json/form bodies
- GraphQL steps (query/mutation) executed via GraphQLClient
With extraction into variables:
- json path extraction
- header extraction
- regex extraction from text
- cookie extraction (from requests.Session cookie jar)
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import urlencode


class FlowError(Exception):
    pass


def render_template(value: Any, variables: Mapping[str, str]) -> Any:
    """Render a simple {{var}} template in strings; recurse through dict/list."""
    if value is None:
        return None
    if isinstance(value, str):
        def repl(match: re.Match) -> str:
            key = match.group(1).strip()
            return str(variables.get(key, ""))

        return re.sub(r"\{\{\s*([^}]+?)\s*\}\}", repl, value)
    if isinstance(value, dict):
        return {k: render_template(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [render_template(v, variables) for v in value]
    return value


def _tokenize_path(path: str) -> List[str]:
    # Supports dotted paths and simple [index] e.g. data.tokens[0].access_token
    if not path:
        return []
    tokens: List[str] = []
    buf = ""
    i = 0
    while i < len(path):
        c = path[i]
        if c == ".":
            if buf:
                tokens.append(buf)
                buf = ""
            i += 1
            continue
        if c == "[":
            if buf:
                tokens.append(buf)
                buf = ""
            j = path.find("]", i)
            if j == -1:
                raise FlowError(f"Invalid json path (missing ']'): {path}")
            tokens.append(path[i : j + 1])  # include brackets
            i = j + 1
            continue
        buf += c
        i += 1
    if buf:
        tokens.append(buf)
    return tokens


def extract_json_path(obj: Any, path: str) -> Any:
    cur = obj
    for tok in _tokenize_path(path):
        if tok.startswith("[") and tok.endswith("]"):
            idx_s = tok[1:-1].strip()
            try:
                idx = int(idx_s)
            except ValueError as e:
                raise FlowError(f"Invalid list index in path {path}: {idx_s}") from e
            if not isinstance(cur, list) or idx >= len(cur):
                return None
            cur = cur[idx]
        else:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(tok)
    return cur


@dataclass
class StepResult:
    status_code: int
    headers: Dict[str, str]
    text: str
    json: Optional[Any]


class FlowRunner:
    def __init__(self, reporter=None, verbose: bool = False):
        self.reporter = reporter
        self.verbose = verbose

    def _debug(self, msg: str):
        if self.reporter and hasattr(self.reporter, "print_debug"):
            self.reporter.print_debug(msg)
        elif self.verbose:
            print(f"[DEBUG] {msg}")

    def run(
        self,
        *,
        client,
        steps: List[Dict[str, Any]],
        variables: Dict[str, str],
        max_steps: int = 50,
    ) -> Dict[str, str]:
        if not steps:
            return variables
        if len(steps) > max_steps:
            raise FlowError(f"Too many flow steps ({len(steps)} > {max_steps})")

        for idx, step in enumerate(steps):
            if not isinstance(step, dict):
                raise FlowError(f"Invalid step at index {idx}: expected object")
            step_type = step.get("type", "http")

            step_rendered = render_template(step, variables)
            self._debug(f"Flow step {idx+1}/{len(steps)} type={step_type}")

            if step_type == "graphql":
                res = self._run_graphql_step(client, step_rendered)
            elif step_type == "http":
                res = self._run_http_step(client, step_rendered)
            else:
                raise FlowError(f"Unknown step type: {step_type}")

            self._apply_extractors(res, client, step_rendered.get("extract", []), variables)

        return variables

    def _run_graphql_step(self, client, step: Dict[str, Any]) -> StepResult:
        query = step.get("query")
        if not query:
            raise FlowError("GraphQL step missing 'query'")
        variables = step.get("variables")
        operation_name = step.get("operationName")
        headers = step.get("headers") or None
        # Avoid recursion: acquisition flows must bypass the auth manager's prepare() hook.
        result = client.query(
            query,
            variables=variables,
            operation_name=operation_name,
            extra_headers=headers,
            bypass_auth=True,
        )
        text = json.dumps(result)
        return StepResult(
            status_code=int(result.get("_status_code", 0) or 0),
            headers={k: str(v) for k, v in (result.get("_headers") or {}).items()},
            text=text,
            json=result,
        )

    def _run_http_step(self, client, step: Dict[str, Any]) -> StepResult:
        method = (step.get("method") or "POST").upper()
        url = step.get("url")
        if not url:
            raise FlowError("HTTP step missing 'url'")
        headers = step.get("headers") or {}
        params = step.get("params") or {}
        json_body = step.get("json")
        form_body = step.get("form")
        data_body = step.get("data")

        if params:
            url = url + ("&" if "?" in url else "?") + urlencode(params, doseq=True)

        # Use the same session/proxy settings as GraphQLClient.
        sess = getattr(client, "session", None)
        proxies = getattr(client, "proxies", None)
        timeout = getattr(client, "timeout", 30)
        verify = getattr(client, "verify", True)

        if sess is None:
            raise FlowError("GraphQLClient does not expose a requests.Session() as 'session'")

        if getattr(client, "delay", 0) and client.delay > 0:
            time.sleep(client.delay)

        resp = sess.request(
            method,
            url,
            headers=headers,
            params=None,
            json=json_body,
            data=form_body if form_body is not None else data_body,
            proxies=proxies,
            timeout=timeout,
            verify=verify,
        )
        text = resp.text or ""
        try:
            j = resp.json()
        except Exception:
            j = None
        return StepResult(
            status_code=int(resp.status_code),
            headers={k: str(v) for k, v in resp.headers.items()},
            text=text,
            json=j,
        )

    def _apply_extractors(
        self,
        res: StepResult,
        client,
        extractors: Any,
        variables: Dict[str, str],
    ):
        if not extractors:
            return
        if not isinstance(extractors, list):
            raise FlowError("'extract' must be a list")

        for ex in extractors:
            if not isinstance(ex, dict):
                continue
            var_name = ex.get("var")
            if not var_name:
                continue

            src = ex.get("from", "json")
            value: Any = None

            if src == "json":
                if res.json is None:
                    value = None
                else:
                    value = extract_json_path(res.json, ex.get("path", ""))
            elif src == "header":
                header_name = ex.get("name")
                if header_name:
                    # Case-insensitive lookup
                    for k, v in res.headers.items():
                        if k.lower() == str(header_name).lower():
                            value = v
                            break
                regex = ex.get("regex")
                if value is not None and regex:
                    m = re.search(regex, str(value))
                    if m:
                        value = m.group(1) if m.groups() else m.group(0)
            elif src == "text":
                regex = ex.get("regex")
                if regex:
                    m = re.search(regex, res.text or "")
                    if m:
                        value = m.group(1) if m.groups() else m.group(0)
            elif src == "cookie":
                cookie_name = ex.get("name")
                if cookie_name:
                    sess = getattr(client, "session", None)
                    if sess is not None:
                        jar = sess.cookies
                        value = jar.get(cookie_name)
            else:
                raise FlowError(f"Unknown extractor source: {src}")

            if value is None:
                continue
            variables[var_name] = str(value)
            self._debug(f"Extracted var {var_name}=<set>")


