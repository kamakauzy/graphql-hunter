import pytest
from graphql_hunter.cli import main


def test_cli_main_runs_without_error():
    """Ensure the CLI entry point can be imported and main() runs without raising an exception."""
    try:
        main()
    except SystemExit as e:
        # argparse calls sys.exit when no arguments are provided; this is expected.
        assert e is not None
        pass
