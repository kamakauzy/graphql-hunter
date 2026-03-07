#!/usr/bin/env python3
"""
Simple CLI wrapper for GraphQL Hunter.

Supports:
- python gqlh.py ...
- editable-install console entrypoints that resolve `gqlh:main`
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_legacy_cli():
    current_path = Path(__file__).resolve()
    candidate_paths = [current_path.with_name("graphql-hunter.py")]
    candidate_paths.extend(parent / "graphql-hunter.py" for parent in current_path.parents)

    script_path = None
    for candidate in candidate_paths:
        if candidate.exists():
            script_path = candidate
            break

    if script_path is None:
        raise RuntimeError("Unable to locate graphql-hunter.py for delegated CLI execution")

    spec = importlib.util.spec_from_file_location("graphql_hunter_legacy_cli", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load CLI implementation from {script_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    module = _load_legacy_cli()
    return int(module.main())


if __name__ == "__main__":
    sys.exit(main())
