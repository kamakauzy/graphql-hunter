"""
Interactive auth wizard for GraphQL Hunter.

Design goals:
- Help users configure auth quickly without printing secrets
- Prefer environment variables (GQLH_*) for secrets
- Output an exact scan command the user can run
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


def _prompt(prompt: str, default: Optional[str] = None) -> str:
    suffix = f" [{default}]" if default else ""
    val = input(f"{prompt}{suffix}: ").strip()
    return val if val else (default or "")


def _choose(prompt: str, options: Dict[str, str], default_key: str) -> str:
    # options: key -> label
    print(prompt)
    for k, label in options.items():
        d = " (default)" if k == default_key else ""
        print(f"  {k}) {label}{d}")
    while True:
        choice = input("> ").strip().lower()
        if not choice:
            return default_key
        if choice in options:
            return choice
        print("Invalid choice. Try again.")


def _ps_env_set_lines(kv: Dict[str, str]) -> str:
    # Print safe PowerShell env export lines with placeholders.
    lines = []
    for k, v in kv.items():
        # v should already be placeholder text (not real secret)
        lines.append(f'$env:{k} = "{v}"')
    return "\n".join(lines)


@dataclass
class WizardResult:
    url: str
    auth_profile: str
    env_vars: Dict[str, str]
    extra_args: str = ""


def run_auth_wizard(args, reporter=None) -> int:
    """
    Run an interactive wizard and print a ready-to-run command.

    Secrets are not echoed; we instruct users to set env vars instead.
    """
    if reporter and hasattr(reporter, "print_info"):
        reporter.print_info("Auth Wizard: this will print a runnable command without exposing secrets.")

    url = getattr(args, "url", None) or ""
    if not url:
        url = _prompt("GraphQL URL (e.g., https://api.example.com/graphql)")

    auth_type = _choose(
        "Select authentication type:",
        {
            "a": "API key (header-based)",
            "b": "Bearer token (JWT / access token)",
            "c": "OAuth2 client-credentials",
            "d": "OAuth2 refresh-token",
            "e": "OAuth2 auth-code (semi-manual paste code)",
            "f": "OAuth2 device-code (semi-manual browser verification)",
            "g": "Cookie session + CSRF (requires config/auth.yaml edits)",
        },
        default_key="b",
    )

    res = _build_result(url=url, auth_type=auth_type)

    # Print how to set env vars (PowerShell-friendly)
    if reporter and hasattr(reporter, "print_separator"):
        reporter.print_separator()
    print("### Set environment variables (PowerShell)")
    if res.env_vars:
        print(_ps_env_set_lines(res.env_vars))
    else:
        print("# (none)")

    print("\n### Run scan")
    cmd = f'python graphql-hunter.py -u "{res.url}" --auth-profile {res.auth_profile}{res.extra_args}'
    print(cmd)

    print("\nNotes:")
    print("- Secrets are read from env vars prefixed with GQLH_.")
    print("- You can also pass values with --auth-var KEY=VALUE, but that may expose secrets in shell history.")
    if auth_type == "g":
        print("- Cookie+CSRF requires you to customize the login URLs/steps in config/auth.yaml (profile: cookie_session_with_csrf).")

    return 0


def _build_result(*, url: str, auth_type: str) -> WizardResult:
    if auth_type == "a":
        return WizardResult(
            url=url,
            auth_profile="api_key",
            env_vars={"GQLH_API_KEY": "PASTE_API_KEY_HERE"},
        )

    if auth_type == "b":
        return WizardResult(
            url=url,
            auth_profile="bearer",
            env_vars={"GQLH_ACCESS_TOKEN": "PASTE_TOKEN_HERE"},
        )

    if auth_type == "c":
        return WizardResult(
            url=url,
            auth_profile="oauth2_client_credentials",
            env_vars={
                "GQLH_CLIENT_ID": "YOUR_CLIENT_ID",
                "GQLH_CLIENT_SECRET": "YOUR_CLIENT_SECRET",
                "GQLH_SCOPE": "OPTIONAL_SCOPE",
                "GQLH_AUDIENCE": "OPTIONAL_AUDIENCE",
            },
        )

    if auth_type == "d":
        return WizardResult(
            url=url,
            auth_profile="oauth2_refresh_token",
            env_vars={
                "GQLH_CLIENT_ID": "YOUR_CLIENT_ID",
                "GQLH_CLIENT_SECRET": "YOUR_CLIENT_SECRET",
                "GQLH_REFRESH_TOKEN": "YOUR_REFRESH_TOKEN",
                "GQLH_SCOPE": "OPTIONAL_SCOPE",
            },
        )

    if auth_type == "e":
        # Auth code is short-lived; allow passing via --auth-var.
        return WizardResult(
            url=url,
            auth_profile="oauth2_auth_code",
            env_vars={
                "GQLH_CLIENT_ID": "YOUR_CLIENT_ID",
                "GQLH_CLIENT_SECRET": "YOUR_CLIENT_SECRET",
                "GQLH_SCOPE": "OPTIONAL_SCOPE",
            },
            extra_args=" --auth-var oauth_code=PASTE_CODE_HERE",
        )

    if auth_type == "f":
        return WizardResult(
            url=url,
            auth_profile="oauth2_device_code",
            env_vars={
                "GQLH_CLIENT_ID": "YOUR_CLIENT_ID",
                "GQLH_SCOPE": "OPTIONAL_SCOPE",
            },
        )

    # cookie session
    return WizardResult(
        url=url,
        auth_profile="cookie_session_with_csrf",
        env_vars={
            "GQLH_USERNAME": "YOUR_USERNAME",
            "GQLH_PASSWORD": "YOUR_PASSWORD",
        },
    )


