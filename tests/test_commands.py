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

    # gwcert csr
    result = runner.invoke(app, args=["csr"])
    assert result.exit_code == 0
    result = runner.invoke(app, args=["csr", "--help"])
    assert result.exit_code == 0
