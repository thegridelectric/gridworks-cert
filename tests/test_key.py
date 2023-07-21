"""Test cases for the __main__ module."""
from pathlib import Path

from typer.testing import CliRunner

from gwcert.__main__ import app


def test_gwcert_key_files(runner: CliRunner, tmp_path: Path) -> None:
    """Verify 'gwcert key' commands produce expected files."""
    ca_dir = tmp_path / "ca"
    certs_dir = ca_dir / "certs"
    key_name = "foo"

    # gwcert key rsa
    result = runner.invoke(
        app, args=["key", "rsa", "--certs-dir", str(certs_dir), key_name]
    )
    assert result.exit_code == 0, result.stdout
    for path in [
        certs_dir / key_name / (key_name + ".pem"),
        certs_dir / key_name / (key_name + ".pub"),
    ]:
        assert path.exists()

    # gwcert key csr
    result = runner.invoke(
        app, args=["key", "csr", "--certs-dir", str(certs_dir), key_name]
    )
    assert result.exit_code == 0, result.stdout
    for path in [
        certs_dir / key_name / (key_name + ".csr"),
    ]:
        assert path.exists()

    # gwcert key certify
    result = runner.invoke(
        app, args=["key", "certify", "--certs-dir", str(certs_dir), key_name]
    )
    assert result.exit_code == 0, result.stdout
    for path in [
        certs_dir / key_name / (key_name + ".crt"),
    ]:
        assert path.exists()

    # gwcert key add
    key_name = "bar"
    result = runner.invoke(
        app, args=["key", "add", "--certs-dir", str(certs_dir), key_name]
    )
    assert result.exit_code == 0, result.stdout
    for path in [
        certs_dir / key_name / (key_name + ".pem"),
        certs_dir / key_name / (key_name + ".pub"),
        certs_dir / key_name / (key_name + ".csr"),
        certs_dir / key_name / (key_name + ".crt"),
    ]:
        assert path.exists()
