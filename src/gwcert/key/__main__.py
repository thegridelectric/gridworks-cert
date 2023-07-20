"""Commands for gwcert.ca package."""
import datetime
import uuid
from pathlib import Path
from typing import Annotated
from typing import List
from typing import Optional

import typer
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from rich import print

from gwcert import DEFAULT_CA_DIR
from gwcert.paths import DEFAULT_CERTS_DIR


app = typer.Typer(
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    rich_markup_mode="rich",
    help="""
    Commands for generating keys, Certificate Signing Requests and Certificates.
    """,
)

_INVALID_PATHS = [Path("."), Path("..")]
CWD = Path(".")


def _get_output_path(
    name_or_output_path: str, output_suffix: str, certs_dir: Path = CWD
) -> Path:
    """
    Return an output of the form certs_dir/name_or_output_path/name_or_output_path.suffix, unless name_or_output_path
    contains parent directories, in which case the return value is Path(name_or_output_path).

    Output path construction, when performed, is:

        a           -> /certs/a/a.pem
        a.pem       -> /certs/a/a.pem
        a.b         -> /certs/a.b/a.b.pem
        a.b.pem     -> /certs/a.b/a.b.pem


    Args:
        name_or_output_path: 'name' of output file or an explicit output path.
        output_suffix: File suffix of output path. Ignored if name_or_output_path is an explicit path.
        certs_dir: Base directory for constructed output paths. Ignored if name_or_output_path is an explicit path.

    Returns:
        Output Path.

    Raises:
        ValueError: If name_as_path is '.' or '..'.

    """
    name_as_path = Path(name_or_output_path)
    if name_as_path in _INVALID_PATHS:
        raise ValueError(
            f"Parameter name_or_output_path ({name_or_output_path}) must not be one of {_INVALID_PATHS}"
        )
    if len(name_as_path.parts) == 1:
        # no parent directory specified; infer parent directory and possibly suffix.
        if name_as_path.suffix == output_suffix:
            output_path = certs_dir / name_as_path.stem / name_as_path
        else:
            output_path = (
                certs_dir / name_as_path / (name_or_output_path + output_suffix)
            )
    else:
        # explicit output path specified. Parameters output_suffix and certs_dir will be ignored.
        output_path = name_as_path
    return output_path


def _store_file(
    output_path: Path,
    data_bytes: bytes,
    permission: Optional[int] = None,
) -> None:
    parent_dir = output_path.parent
    if not parent_dir.exists():
        parent_dir.mkdir(parents=True)
    with output_path.open("w") as f:
        f.write(data_bytes.decode("utf-8"))
    if permission is not None:
        output_path.chmod(permission)


@app.command()
def gen_rsa(
    name: Annotated[
        str,
        typer.Argument(
            help="'name' of generated key, or explict path to generated key file."
        ),
    ],
    certs_dir: Annotated[
        Path, typer.Option(help="Base storage directory for named certs")
    ] = DEFAULT_CERTS_DIR,
    public_exponent: Annotated[
        int,
        typer.Option(
            help="The public exponent of the new key. Either 65537 or 3 (for legacy purposes). Almost everyone should use 65537."
        ),
    ] = 65537,
    key_size: Annotated[
        int,
        typer.Option(
            help="The length of the modulus in bits. It is strongly recommended to be at least 2048."
        ),
    ] = 2048,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="""Overwrites existing files.
    [yellow][bold]WARNING: [/yellow][/bold]--force will [red][bold]PERMANENTLY DELETE[/red][/bold]
    the public and private key for this key name""",
        ),
    ] = False,
) -> None:
    """
    Create public/private key pair using RSA.
    """
    private_key_path = _get_output_path(
        name_or_output_path=name, output_suffix=".pem", certs_dir=certs_dir
    )
    public_key_path = _get_output_path(
        name_or_output_path=name, output_suffix=".pub", certs_dir=certs_dir
    )
    if not force and (private_key_path.exists() or public_key_path.exists()):
        print(
            "One or more output files [yellow][bold]already exist. Doing nothing.[/yellow][/bold]"
        )
        print(
            f"  private key file  exists:{str(private_key_path.exists()):5s}  {private_key_path}"
        )
        print(
            f"  public key file   exists:{str(private_key_path.exists()):5s}  {private_key_path}"
        )
        print("\nUse --force to overwrite keys")
        return
    key = rsa.generate_private_key(public_exponent=public_exponent, key_size=key_size)
    print(f"Writing private key file: {private_key_path}")
    _store_file(
        private_key_path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        0o600,
    )
    print(f"Writing public key file:  {public_key_path}")
    _store_file(
        public_key_path,
        key.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH,
        ),
    )


@app.command()
def gen_csr(
    name: Annotated[
        str,
        typer.Argument(
            help="'name' of generated csr, or explict path to generated csr file."
        ),
    ],
    private_key_path: Annotated[
        Optional[Path],
        typer.Option(
            help=(
                "Optional explicit path to private key file. If absent, private key path is derived from "
                "csr output path."
            )
        ),
    ] = None,
    certs_dir: Annotated[
        Path, typer.Option(help="Base storage directory for named certs")
    ] = DEFAULT_CERTS_DIR,
    common_name: Annotated[
        str,
        typer.Option(
            help="Common Name used in certificate. If unspecified, key-name is used."
        ),
    ] = "",
    dns_names: Annotated[
        Optional[List[str]], typer.Option("--dns", help="DNS entries")
    ] = None,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="""Overwrites existing file.
                [yellow][bold]WARNING: [/yellow][/bold]--force will [red][bold]PERMANENTLY DELETE[/red][/bold]
                the csr file for this name""",
        ),
    ] = False,
) -> None:
    """
    Create Certificate Signing Request from a private key.
    """
    csr_path = _get_output_path(
        name_or_output_path=name, output_suffix=".csr", certs_dir=certs_dir
    )
    if not force and csr_path.exists():
        print(
            f"CSR file {csr_path} [yellow][bold]already exists. Doing nothing.[/yellow][/bold]"
        )
        print("\nUse --force to overwrite csr file")
        return
    if private_key_path is None:
        private_key_path = csr_path.with_suffix(".pem")

    if not private_key_path.exists():
        raise ValueError(f"Private key path {private_key_path} does not exist")

    with private_key_path.open("rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)

    if not dns_names:
        dns_names = [common_name]

    print(f"Writing CSR file:         {csr_path}")
    _store_file(
        csr_path,
        x509.CertificateSigningRequestBuilder()  # type: ignore
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))  # type: ignore
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(dns_name) for dns_name in dns_names]
            ),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=False
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
        .public_bytes(encoding=serialization.Encoding.PEM),
    )


@app.command()
def certify(
    name: Annotated[
        str,
        typer.Argument(
            help="'name' of generated certificate, or explict path to generated crt file."
        ),
    ],
    csr_path: Annotated[
        Optional[Path],
        typer.Option(
            help=(
                "Optional explicit path to Certificate Signing Request. If absent, CSR path is derived from the"
                "certificate output path."
            )
        ),
    ] = None,
    ca_certificate_path: Annotated[
        Optional[Path],
        typer.Option(
            help="Optional explicit path to CA certificate file. If absent, CA certificate path is derived from ca_dir."
        ),
    ] = None,
    ca_private_key_path: Annotated[
        Optional[Path],
        typer.Option(
            help="Optional explicit path to CA private key file. If absent, CA private key path is derived from ca_dir."
        ),
    ] = None,
    ca_dir: Annotated[
        Path, typer.Option(help="Certificate Authority directory")
    ] = DEFAULT_CA_DIR,
    certs_dir: Annotated[
        Path, typer.Option(help="Base storage directory for named certs")
    ] = DEFAULT_CERTS_DIR,
    valid_days: Annotated[
        int,
        typer.Option(
            help="Number of days issued certificates should be valid for",
            min=0,
            max=825,
        ),
    ] = 825,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="""Overwrites existing certificate file.
        [yellow][bold]WARNING: [/yellow][/bold]--force will [red][bold]PERMANENTLY DELETE[/red][/bold]
        the certificate file for this name""",
        ),
    ] = False,
) -> None:
    """
    Sign a CSR, producing a certificate.
    """
    certificate_path = _get_output_path(name, ".crt", certs_dir)
    if csr_path is None:
        csr_path = certificate_path.with_suffix(".csr")
    if ca_certificate_path is None:
        ca_certificate_path = ca_dir / "ca.crt"
    if ca_private_key_path is None:
        ca_private_key_path = ca_dir / "private" / "ca_key.pem"

    if not force and certificate_path.exists():
        print(
            f"Ceritifcate file {certificate_path} [yellow][bold]already exists. Doing nothing.[/yellow][/bold]"
        )
        print("\nUse --force to overwrite certificate file")
        return
    if not csr_path.exists():
        raise ValueError(f"CSR path {csr_path} does not exist")
    if not ca_certificate_path.exists():
        raise ValueError(f"CA certificate path {ca_certificate_path} does not exist")
    if not ca_private_key_path.exists():
        raise ValueError(f"CA private key path {ca_private_key_path} does not exist")

    with csr_path.open("rb") as f:
        csr = x509.load_pem_x509_csr(f.read())
    with ca_certificate_path.open("rb") as f:
        ca_certificate = x509.load_pem_x509_certificate(f.read())
    with ca_private_key_path.open("rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    certificate_builder = x509.CertificateBuilder().subject_name(csr.subject)
    for extension in csr.extensions:
        if extension.value.oid._name != "subjectAltName":  # noqa
            continue
        certificate_builder = certificate_builder.add_extension(
            extension.value, critical=extension.critical
        )

    print(f"Writing certificate file: {certificate_path}")
    _store_file(
        certificate_path,
        certificate_builder.issuer_name(ca_certificate.subject)
        .public_key(csr.public_key())
        .serial_number(uuid.uuid4().int)
        .not_valid_before(datetime.datetime.today() - datetime.timedelta(1, 0, 0))
        .not_valid_after(
            datetime.datetime.today() + (datetime.timedelta(1, 0, 0) * valid_days)
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=True,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
                key_cert_sign=False,
                crl_sign=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(
            private_key=ca_key,
            algorithm=hashes.SHA256(),
        )
        .public_bytes(encoding=serialization.Encoding.PEM),
    )


# For sphinx:
typer_click_object = typer.main.get_command(app)
