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
        certs_dir / key_name / (key_name + ".pub"),
        certs_dir / key_name / "private" / (key_name + ".pem"),
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
        certs_dir / key_name / (key_name + ".pub"),
        certs_dir / key_name / "private" / (key_name + ".pem"),
        certs_dir / key_name / (key_name + ".csr"),
        certs_dir / key_name / (key_name + ".crt"),
        certs_dir / key_name / "ca.crt",
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
    subject_line1 = f"Subject: CN = {key_name}"
    subject_line2 = f"Subject: CN={key_name}"
    assert (
        subject_line1 in result.stdout or subject_line2 in result.stdout
    ), f"ERROR. Neither Subject line <{subject_line1}> nor <{subject_line2}> found in output\n{result.stdout}"


def test_certify_ca_copy(runner: CliRunner, tmp_path: Path) -> None:
    """Verify 'gwcert key certify' copys CA certificate or not as expected"""
    certs_dir = tmp_path / "certs"
    ca_dir = tmp_path / "ca"
    key_name = "foo"
    cert_path = certs_dir / key_name / (key_name + ".crt")
    ca_cert_copy_path = cert_path.parent / "ca.crt"

    ## Prep ###################################################################
    runner.invoke(app, args=["key", "rsa", "--certs-dir", str(certs_dir), key_name])
    runner.invoke(app, args=["key", "csr", "--certs-dir", str(certs_dir), key_name])
    runner.invoke(app, args=["ca", "create", "--ca-dir", str(ca_dir), "testca"])
    ca_cert_path = ca_dir / "ca.crt"
    for path in [
        certs_dir / key_name / (key_name + ".pub"),
        certs_dir / key_name / "private" / (key_name + ".pem"),
        certs_dir / key_name / (key_name + ".csr"),
        ca_cert_path,
    ]:
        assert path.exists()
    ## Prep ###################################################################

    # certify - no ca.crt copy (default)
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
    assert cert_path.exists()
    assert not ca_cert_copy_path.exists()

    # certify - copy ca.crt
    cert_path.unlink()
    assert not cert_path.exists()
    result = runner.invoke(
        app,
        args=[
            "key",
            "certify",
            "--certs-dir",
            str(certs_dir),
            "--ca-dir",
            str(ca_dir),
            "--copy-ca-cert",
            key_name,
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert cert_path.exists()
    assert ca_cert_copy_path.exists()

    # certify without copy - delete existing ca.crt, which could be ambiguous
    result = runner.invoke(
        app,
        args=[
            "key",
            "certify",
            "--certs-dir",
            str(certs_dir),
            "--ca-dir",
            str(ca_dir),
            "--force",
            key_name,
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert cert_path.exists()
    assert not ca_cert_copy_path.exists()
