"""gwcert command-line interface."""

from importlib.metadata import version

import typer
from trogon import Trogon
from typer.main import get_group

from gwcert.ca import app as ca_app
from gwcert.key import app as key_app


__version__ = version("gridworks-cert")

app = typer.Typer(
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    rich_markup_mode="rich",
    help="GridWords TLS certificate tools.",
)
app.add_typer(ca_app, name="ca")
app.add_typer(key_app, name="key")


@app.command()
def tui(ctx: typer.Context) -> None:
    """Visual CLI command builder."""
    Trogon(get_group(app), click_context=ctx).run()


def _version_callback(value: bool) -> None:
    """Print version and exit"""
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(  # noqa
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Do any argument processing for base gwcert command."""
    return


# For sphinx:
typer_click_object = typer.main.get_command(app)

if __name__ == "__main__":
    app()
