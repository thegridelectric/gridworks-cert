"""Test cases for the __main__ module."""
from pathlib import Path

from typer.testing import CliRunner

from gwcert.__main__ import app


def test_gwcert_key_files(runner: CliRunner, tmp_path: Path) -> None:
    """Verify 'gwcert key' commands produce expected files."""
    certs_dir = tmp_path / "certs"
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

    # Generate the CA so we can certify
    ca_dir = tmp_path / "ca"
    result = runner.invoke(
        app, args=["ca", "create", "--ca-dir", str(ca_dir), "testca"]
    )
    assert result.exit_code == 0, result.stdout

    # gwcert key certify
    result = runner.invoke(
        app,
        args=[
            "key",
            "certify",
            "--certs-dir",
            str(certs_dir),
            "--ca-dir",
            str(ca_dir),
            key_name,
        ],
    )
    assert result.exit_code == 0, result.stdout
    for path in [
        certs_dir / key_name / (key_name + ".crt"),
    ]:
        assert path.exists()

    # gwcert key add
    key_name = "bar"
    result = runner.invoke(
        app,
        args=[
            "key",
            "add",
            "--certs-dir",
            str(certs_dir),
            "--ca-dir",
            str(ca_dir),
            key_name,
        ],
    )
    assert result.exit_code == 0, result.stdout
    for path in [
        certs_dir / key_name / (key_name + ".pem"),
        certs_dir / key_name / (key_name + ".pub"),
        certs_dir / key_name / (key_name + ".csr"),
        certs_dir / key_name / (key_name + ".crt"),
    ]:
        assert path.exists()

    # gwcert key info
    result = runner.invoke(
        app,
        args=[
            "key",
            "info",
            "--certs-dir",
            str(certs_dir),
            key_name,
        ],
    )
    assert result.exit_code == 0, result.stdout
    subject_line = f"Subject: CN = {key_name}"
    assert (
        subject_line in result.stdout
    ), f"ERROR. Subject line <{subject_line}> not in output\n{result.stdout}"
