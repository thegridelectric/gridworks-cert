"""Commands for gwcert.ca package."""
import datetime
import subprocess
import uuid
from pathlib import Path
from typing import Annotated
from typing import List
from typing import Optional

import rich
import typer
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa
from cryptography.x509.oid import NameOID

from gwcert import DEFAULT_CA_DIR
from gwcert.paths import DEFAULT_CERTS_DIR


app = typer.Typer(
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    rich_markup_mode="rich",
    help="""
    Commands for generating named keys, Certificate Signing Requests and Certificates.

    By default certificates are generated in:

        $HOME/.local/share/gridworks/ca/certs/KEYNAME/

    By default CA files are:

        $HOME/.local/share/gridworks/ca/ca.crt
        $HOME/.local/share/gridworks/ca/private/ca_key.pem.

    Subcommands rsa, csr and certify may be called in order to produce key/certificate pairs usable with the
    specified CA. Subcommand 'add' calls all three of those in order.

    The I/O of these commands is approximately:

        rsa -> private key
        csr(private key) -> CSR
        certify(CSR, CA certificate, CA private key) -> certificate

    """,
)

_INVALID_PATHS = [Path("."), Path("..")]
CWD = Path(".")


def get_output_path(
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
def rsa(
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

    Writes public and private key files, by default named:

        $HOME/.local/share/gridworks/ca/certs/name/name.pub
        $HOME/.local/share/gridworks/ca/certs/name/name.pem

    Output files can be explicitly named by passing a path-like string for a ".pem" file to the name parameter.
    """
    private_key_path = get_output_path(
        name_or_output_path=name, output_suffix=".pem", certs_dir=certs_dir
    )
    public_key_path = private_key_path.with_suffix(".pub")
    if not force and (private_key_path.exists() or public_key_path.exists()):
        rich.print(
            "One or more output files [yellow][bold]already exist. Doing nothing.[/yellow][/bold]"
        )
        rich.print(
            f"  private key file  exists:{str(private_key_path.exists()):5s}  {private_key_path}"
        )
        rich.print(
            f"  public key file   exists:{str(private_key_path.exists()):5s}  {private_key_path}"
        )
        rich.print("\nUse --force to overwrite keys")
        return
    key = crypto_rsa.generate_private_key(
        public_exponent=public_exponent, key_size=key_size
    )
    rich.print(f"Writing private key file: {private_key_path}")
    _store_file(
        private_key_path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        0o600,
    )
    rich.print(f"Writing public key file:  {public_key_path}")
    _store_file(
        public_key_path,
        key.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH,
        ),
    )


@app.command()
def csr(
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

    Uses input files, by default named:

        $HOME/.local/share/gridworks/ca/certs/name/name.pub

    Writes a CSR file, by default named:

        $HOME/.local/share/gridworks/ca/certs/name/name.csr

    Input file can be explicitly named with the --private-key-path paramter.
    Output file can be explicitly named by passing a path-like string for a ".csr" file to the name parameter.

    """
    csr_path = get_output_path(
        name_or_output_path=name, output_suffix=".csr", certs_dir=certs_dir
    )
    if not force and csr_path.exists():
        rich.print(
            f"CSR file {csr_path} [yellow][bold]already exists. Doing nothing.[/yellow][/bold]"
        )
        rich.print("\nUse --force to overwrite csr file")
        return
    if private_key_path is None:
        private_key_path = csr_path.with_suffix(".pem")

    if not private_key_path.exists():
        raise ValueError(f"Private key path {private_key_path} does not exist")

    with private_key_path.open("rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)

    if not common_name:
        common_name = csr_path.stem

    if not dns_names:
        dns_names = [common_name]

    rich.print(f"Writing CSR file:         {csr_path}")
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
    Sign a CSR, producing a certificate .

    Uses input files, by default named:

        $HOME/.local/share/gridworks/ca/certs/name/name.csr

    Writes a certificate file, by default named:

        $HOME/.local/share/gridworks/ca/certs/name/name.crt

    Input file can be explicitly named with the --csr-path, --ca-certificate-path and --ca-private-key-path parameters.
    Output file can be explicitly named by passing a path-like string for a ".crt" file to the name parameter.
    """
    certificate_path = get_output_path(name, ".crt", certs_dir)
    if csr_path is None:
        csr_path = certificate_path.with_suffix(".csr")
    if ca_certificate_path is None:
        ca_certificate_path = ca_dir / "ca.crt"
    if ca_private_key_path is None:
        ca_private_key_path = ca_dir / "private" / "ca_key.pem"

    if not force and certificate_path.exists():
        rich.print(
            f"Ceritifcate file {certificate_path} [yellow][bold]already exists. Doing nothing.[/yellow][/bold]"
        )
        rich.print("\nUse --force to overwrite certificate file")
        return
    if not csr_path.exists():
        raise ValueError(f"CSR path {csr_path} does not exist")
    if not ca_certificate_path.exists():
        raise ValueError(f"CA certificate path {ca_certificate_path} does not exist")
    if not ca_private_key_path.exists():
        raise ValueError(f"CA private key path {ca_private_key_path} does not exist")

    with csr_path.open("rb") as f:
        csr_ = x509.load_pem_x509_csr(f.read())
    with ca_certificate_path.open("rb") as f:
        ca_certificate = x509.load_pem_x509_certificate(f.read())
    with ca_private_key_path.open("rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    certificate_builder: x509.CertificateBuilder = x509.CertificateBuilder().subject_name(csr_.subject)  # type: ignore
    for extension in csr_.extensions:
        if extension.value.oid._name != "subjectAltName":  # noqa
            continue
        certificate_builder = certificate_builder.add_extension(
            extension.value, critical=extension.critical
        )

    rich.print(f"Writing certificate file: {certificate_path}")
    _store_file(
        certificate_path,
        certificate_builder.issuer_name(ca_certificate.subject)
        .public_key(csr_.public_key())
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


@app.command()
def info(
    name: Annotated[
        str,
        typer.Argument(
            help="'name' of generated certificate, or explict path to generated crt file."
        ),
    ],
    certs_dir: Annotated[
        Path, typer.Option(help="Base storage directory for named certs")
    ] = DEFAULT_CERTS_DIR,
    show_files: Annotated[
        bool,
        typer.Option(
            "--files", help="Show paths of files in directory of certificate."
        ),
    ] = False,
) -> None:
    """Show information about a certificate using '[cyan]openssl x509 -in CERTIFICATE_PATH -text -noout[/cyan]'."""
    certificate_path = get_output_path(
        name_or_output_path=name, output_suffix=".crt", certs_dir=certs_dir
    )
    rich.print(f"Showing information for certificate {certificate_path}")
    if show_files:
        cert_dir = certificate_path.parent
        rich.print(f"Files for certificate {certificate_path.stem}")
        for path in cert_dir.iterdir():
            rich.print(f" {path}")
    cmd = [
        "openssl",
        "x509",
        "-in",
        str(certificate_path),
        "-text",
        "-noout",
    ]
    rich.print(f"Running command:\n\n\t{' '.join(cmd)}\n")
    result = subprocess.run(cmd, capture_output=True)
    print(result.stdout.decode("utf-8"))
    if result.returncode != 0:
        raise RuntimeError(
            f"ERROR. Command <{' '.join(cmd)}> failed with returncode:{result.returncode}"
        )


@app.command()
def add(
    ctx: typer.Context,
    name: Annotated[
        str,
        typer.Argument(
            help="'name' of generated identity, or explict path to generated private key file."
        ),
    ],
    csr_path: Annotated[
        Optional[Path],
        typer.Option(
            help=(
                "Optional explicit path to Certificate Signing Request. If absent, CSR path is derived from the"
                "private key output path."
            )
        ),
    ] = None,
    certificate_path: Annotated[
        Optional[Path],
        typer.Option(
            help=(
                "Optional explicit path to Certificate Signing Request. If absent, CSR path is derived from the"
                "private key output path."
            )
        ),
    ] = None,
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
    common_name: Annotated[
        str,
        typer.Option(
            help="Common Name used in certificate. If unspecified, key-name is used."
        ),
    ] = "",
    dns_names: Annotated[
        Optional[List[str]], typer.Option("--dns", help="DNS entries")
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
    valid_days: Annotated[
        int,
        typer.Option(
            help="Number of days issued certificates should be valid for",
            min=0,
            max=825,
        ),
    ] = 825,
) -> None:
    """Generate public/private RSA key pair, CSR and certificate for a named identity.

    Writes public/private key, CSR and certificate files, by default named:

        $HOME/.local/share/gridworks/ca/certs/name/name.pub
        $HOME/.local/share/gridworks/ca/certs/name/name.pem
        $HOME/.local/share/gridworks/ca/certs/name/name.csr
        $HOME/.local/share/gridworks/ca/certs/name/name.crt

    Input file can be explicitly named with the --ca-certificate-path and --ca-private-key-path parameters.
    Output file can be explicitly named by passing a path-like string for a ".pem" file to the name parameter and/or
    with --csr-path and --certificate-path parameters.
    """
    private_key_path = get_output_path(
        name_or_output_path=name, output_suffix=".pem", certs_dir=certs_dir
    )
    public_key_path = private_key_path.with_suffix(".pub")
    if csr_path is None:
        csr_path = private_key_path.with_suffix(".csr")
    if certificate_path is None:
        certificate_path = private_key_path.with_suffix(".crt")
    if not force and (
        private_key_path.exists()
        or public_key_path.exists()
        or csr_path.exists()
        or certificate_path.exists()
    ):
        rich.print(
            "One or more output files [yellow][bold]already exist. Doing nothing.[/yellow][/bold]"
        )
        rich.print(
            f"  private key file  exists:{str(private_key_path.exists()):5s}  {private_key_path}"
        )
        rich.print(
            f"  public key file   exists:{str(private_key_path.exists()):5s}  {private_key_path}"
        )
        rich.print(
            f"  CSR file          exists:{str(csr_path.exists()):5s}  {private_key_path}"
        )
        rich.print(
            f"  Certificate file  exists:{str(certificate_path.exists()):5s}  {private_key_path}"
        )
        rich.print("\nUse --force to overwrite keys")
        return
    ctx.invoke(
        rsa,
        name=name,
        certs_dir=certs_dir,
        public_exponent=public_exponent,
        key_size=key_size,
        force=force,
    )
    ctx.invoke(
        csr,
        name=csr_path,
        private_key_path=private_key_path,
        certs_dir=certs_dir,
        common_name=common_name,
        dns_names=dns_names,
        force=force,
    )
    ctx.invoke(
        certify,
        name=certificate_path,
        csr_path=csr_path,
        ca_certificate_path=ca_certificate_path,
        ca_private_key_path=ca_private_key_path,
        ca_dir=ca_dir,
        certs_dir=certs_dir,
        valid_days=valid_days,
        force=force,
    )


# For sphinx:
typer_click_object = typer.main.get_command(app)
