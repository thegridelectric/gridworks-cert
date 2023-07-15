"""Commands for gwcert.ca package."""

import shutil
from pathlib import Path
from typing import Annotated

import typer
import xdg
from ownca import CertificateAuthority
from ownca._constants import CA_CERT  # noqa
from ownca._constants import CA_CRL  # noqa
from ownca._constants import CA_CSR  # noqa
from ownca._constants import CA_KEY  # noqa
from ownca._constants import CA_PUBLIC_KEY  # noqa
from ownca.utils import ownca_directory
from rich import print


app = typer.Typer(
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    rich_markup_mode="rich",
    help="""
    Commands for creating and using a local Certificate Authority.
    """,
)

DEFAULT_CA_DIR = Path(xdg.xdg_data_home()) / "gridworks" / "ca"


@app.command()
def clean(
    ca_dir: Annotated[
        Path, typer.Option(help="CA storage directory.")
    ] = DEFAULT_CA_DIR,
    yes_really_forever: Annotated[
        bool,
        typer.Option(
            "--yes-really-forever",
            help="Required to actually clean the CA storage directory",
        ),
    ] = False,
) -> None:
    """Delete the CA storage directory and contents. [yellow][bold] WARNING: [red] PERMANENTLY DELETES CA CERTIFICATE AND KEY."""
    if not yes_really_forever:
        print(
            "[yellow][bold]WARNING: [/yellow][/bold]clean command does [cyan]nothing[/cyan] if --yes-really-forever is not specified."
        )
        print(
            "[yellow][bold]WARNING: [/yellow][/bold]--yes-really-forever will [red][bold]PERMANENTLY DELETE THE CA CERTIFICATE AND KEY"
        )
    else:
        ca_dir = Path(ca_dir)
        if ca_dir.exists():
            shutil.rmtree(ca_dir)


def print_ca_info(ca: CertificateAuthority) -> None:
    """Print informations about a CertificateAuthority object."""
    print(f"Created Certificate Authority with status: {ca.status}")
    print("Files:")
    ca_dir = Path(ca.ca_storage)
    for description, file_name in [
        ("CA Private Key", CA_KEY),
        ("CA Public Key", CA_PUBLIC_KEY),
        ("CA Certificate", CA_CERT),
        ("CA Certificate Signing Request", CA_CSR),
        ("CA Certitifate Revocation List", CA_CRL),
    ]:
        file_path = ca_dir / file_name
        print(
            f"  {description:30s}    Exists:{str(file_path.exists()):5s}  <{str(file_path)}>"
        )
    print(ca.cert)


@app.command()
def create(
    common_name: Annotated[
        str, typer.Argument(help="Certificate Authority Common Name when issuing cert.")
    ],
    ca_dir: Annotated[
        Path, typer.Option(help="CA storage directory.")
    ] = DEFAULT_CA_DIR,
    valid_days: Annotated[
        int, typer.Option(help="Number of days issued certificates should be valid for")
    ] = 825,
    public_exponent: Annotated[
        int,
        typer.Option(
            help="Passed to cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key()"
        ),
    ] = 65537,
    key_size: Annotated[
        int,
        typer.Option(
            help="Passed to cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key()"
        ),
    ] = 2048,
) -> None:
    """Create files necessary for a simple, self-signed Certificate Authority."""
    ca_dir = Path(ca_dir)
    ca_status = ownca_directory(str(ca_dir))
    if ca_status.certificate or ca_status.key or ca_status.public_key or ca_status.crl:
        print(
            f"[yellow][bold]WARNING: [/yellow][/bold] CA directory <{ca_dir}> is not empty. "
        )
        print("[yellow][bold]WARNING: [/yellow][/bold] NOT creating CA.")
    else:
        ca = CertificateAuthority(
            ca_storage=str(ca_dir),
            common_name=common_name,
            maximum_days=valid_days,
            public_exponent=public_exponent,
            key_size=key_size,
        )
        print_ca_info(ca)


@app.command(
    help="""
    Delete the CA storage directory and contents. [yellow][bold] WARNING: [red] PERMANENTLY DELETES CA CERTIFICATE AND KEY
    """
)
def certify(
    csr_path: Annotated[
        Path,
        typer.Argument(help="Path to the Certificate Signing Request file to sign"),
    ],
    ca_dir: Annotated[
        Path, typer.Option(help="CA storage directory.")
    ] = DEFAULT_CA_DIR,
) -> None:
    """Create a certificate for a Certificate Signing Request."""
    print("[yellow][bold]WARNING: Not implemented[/yellow][/bold]")
    print(f"csr_path: <{csr_path}>")
    print(f"ca_dir:   <{ca_dir}>")


@app.command()
def info(
    ca_dir: Annotated[
        Path, typer.Option(help="CA storage directory.")
    ] = DEFAULT_CA_DIR,
) -> None:
    """Show information about CA configured on disk."""
    ca_dir = Path(ca_dir)
    if not ca_dir.exists():
        print(f"CA directory <{ca_dir}> does not exist")
    else:
        print_ca_info(CertificateAuthority(str(ca_dir)))


# For sphinx:
typer_click_object = typer.main.get_command(app)
