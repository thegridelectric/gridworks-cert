"""gwcert command-line interface."""
import typer

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


# For sphinx:
typer_click_object = typer.main.get_command(app)

if __name__ == "__main__":
    app()
