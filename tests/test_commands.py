"""Test cases for the __main__ module."""
from typer.testing import CliRunner

from gwcert.__main__ import app


def test_gwcert_help_succeeds(runner: CliRunner) -> None:
    """Verify help commands exit with a status code of zero."""
    # gwcert
    result = runner.invoke(app)
    assert result.exit_code == 0
    result = runner.invoke(app, args=["--help"])
    assert result.exit_code == 0

    # gwcert ca
    result = runner.invoke(app, args=["ca"])
    assert result.exit_code == 0
    result = runner.invoke(app, args=["ca", "--help"])
    assert result.exit_code == 0

    # gwcert ca subcommands
    for subcommand in ["add-key", "clean", "create", "info"]:
        result = runner.invoke(app, args=["ca", subcommand, "--help"])
        assert result.exit_code == 0, f"{subcommand}  exit: {result.exit_code}"

    # gwcert ca info
    result = runner.invoke(app, args=["ca", "info"])
    assert result.exit_code == 0

    # gwcert key
    result = runner.invoke(app, args=["key"])
    assert result.exit_code == 0
    result = runner.invoke(app, args=["key", "--help"])
    assert result.exit_code == 0

    # gwcert key subcommands
    for subcommand in ["rsa", "csr", "certify", "add"]:
        result = runner.invoke(app, args=["key", subcommand, "--help"])
        assert result.exit_code == 0, f"{subcommand}  exit: {result.exit_code}"
