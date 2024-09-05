"""Test cases for the __main__ module."""

from pathlib import Path

from typer.testing import CliRunner

from gwcert.__main__ import app


def test_gwcert_ca_files(runner: CliRunner, tmp_path: Path) -> None:
    """Verify 'gwcert ca' commands produce expected files."""
    ca_dir = tmp_path / "ca"
    result = runner.invoke(
        app, args=["ca", "create", "--ca-dir", str(ca_dir), "TestCA"]
    )
    assert result.exit_code == 0, result.stdout

    for path in [
        ca_dir / "ca_key.pub",
        ca_dir / "ca.crt",
        ca_dir / "ca.crl",
        ca_dir / "private" / "ca_key.pem",
    ]:
        assert path.exists()

    key_name = "foo"
    result = runner.invoke(
        app, args=["ca", "add-key", "--ca-dir", str(ca_dir), key_name]
    )
    assert result.exit_code == 0, result.stdout
    key_dir = ca_dir / "certs" / key_name
    for path in [
        key_dir / (key_name + ".pem"),
        key_dir / (key_name + ".pub"),
        key_dir / (key_name + ".csr"),
        key_dir / (key_name + ".crt"),
    ]:
        assert path.exists()
