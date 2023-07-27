"""Commands for gwcert.ca package."""

import shutil
from pathlib import Path
from typing import Annotated
from typing import List
from typing import Optional

import typer
from ownca import CertificateAuthority
from ownca._constants import CA_CERT  # noqa
from ownca._constants import CA_CERTS_DIR  # noqa
from ownca._constants import CA_CRL  # noqa
from ownca._constants import CA_CSR  # noqa
from ownca._constants import CA_KEY  # noqa
from ownca._constants import CA_PUBLIC_KEY  # noqa
from ownca.utils import ownca_directory
from rich import print

from gwcert.paths import DEFAULT_CA_DIR


app = typer.Typer(
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    rich_markup_mode="rich",
    help="""
    Commands for creating and using a local Certificate Authority.
    """,
)


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
    print(f"Certificate Authority in directory: <{ca.ca_storage}>:")
    print(" Files:")
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
            f"  {description:30s}    Exists:{str(file_path.exists()):5s}  {str(file_path)}"
        )
    named_keys = ca.certificates
    named_key_dir = ca_dir / CA_CERTS_DIR
    print(f" Named keys in {named_key_dir}: {len(named_keys)} ")
    for named_key in named_keys:
        print(f"  {named_key}")
        for path in (named_key_dir / named_key).iterdir():
            print(f"    {str(path)}")


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


@app.command()
def add_key(
    key_name: Annotated[str, typer.Argument(help="Name used for key files.")],
    ca_dir: Annotated[
        Path, typer.Option(help="CA storage directory.")
    ] = DEFAULT_CA_DIR,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="""Overwrites existing files.
            [yellow][bold]WARNING: [/yellow][/bold]--force will [red][bold]PERMANENTLY DELETE[/red][/bold]
            the files for this key name, including public and private key.""",
        ),
    ] = False,
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
    common_name: Annotated[
        str,
        typer.Option(
            help="Common Name used in certificate. If unspecified, key-name is used."
        ),
    ] = "",
    dns_names: Annotated[
        Optional[List[str]], typer.Option("--dns", help="DNS entries")
    ] = None,
    is_ca: Annotated[
        bool,
        typer.Option(
            "--is-ca",
            help="Whether certificate for this key can itself sign other certificates",
        ),
    ] = False,
) -> None:
    """
    Generate public/private key pair, CSR and signed certificate.
    """
    ca_dir = Path(ca_dir)
    if not ca_dir.exists():
        print(
            f"CA directory <{ca_dir}> does not exist. Use 'gwcert ca create' to create it before adding keys."
        )
        return
    key_dir = ca_dir / CA_CERTS_DIR / key_name
    if key_dir.exists():
        if not force:
            print(
                f"Key dir {key_dir} [yellow][bold]already exists. Doing nothing.[/yellow][/bold]"
            )
            print(f"Use --force to overwrite all key files for key name <{key_name}>")
            return
        else:
            print(
                f"[yellow][bold]DELETING existing key directory[/yellow][/bold] {key_dir}."
            )
            shutil.rmtree(key_dir)
    print(f"Creating keys at {key_dir}.")
    ca = CertificateAuthority(str(ca_dir))
    if not common_name:
        common_name = key_name
    ca.issue_certificate(
        key_name,
        maximum_days=valid_days,
        common_name=common_name,
        dns_names=dns_names,
        oids=None,
        public_exponent=public_exponent,
        key_size=key_size,
        ca=is_ca,
    )
    print("Created:")
    for path in key_dir.iterdir():
        print(f" {path}")


# For sphinx:
typer_click_object = typer.main.get_command(app)
