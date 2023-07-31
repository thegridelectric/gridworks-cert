"""gwcert command-line interface."""
import typer
from trogon import Trogon
from typer.main import get_group

from gwcert.ca import app as ca_app
from gwcert.key import app as key_app


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


# For sphinx:
typer_click_object = typer.main.get_command(app)

if __name__ == "__main__":
    app()
