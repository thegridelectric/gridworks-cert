"""Commands for gwcert.csr package."""

import typer


app = typer.Typer(
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    rich_markup_mode="rich",
    help="""
    Commands for creating a Certificate Signing Request.
    """,
)


@app.command()
def create() -> None:
    """Create a Certificate Signing Request."""
    pass


# For sphinx:
typer_click_object = typer.main.get_command(app)
