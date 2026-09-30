"""PySuite entry point."""

from typing import Annotated

import typer

from pysuite import __version__
from pysuite.commands import files, logs, net, sec, system, web

app = typer.Typer(
    help="PySuite - cybersecurity and sysadmin toolkit for the terminal.",
    no_args_is_help=True,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)
app.add_typer(net.app, name="net", help="Network recon: port scan, ping sweep, DNS, WHOIS, subnets.")
app.add_typer(web.app, name="web", help="Web auditing: security headers, TLS certificates, uptime.")
app.add_typer(sec.app, name="sec", help="Security: hashing, passwords, encoding, JWT, IOC extraction.")
app.add_typer(system.app, name="sys", help="System: overview, processes, listening ports, users.")
app.add_typer(files.app, name="files", help="Files: large files, duplicates, integrity baselines, entropy, permissions.")
app.add_typer(logs.app, name="logs", help="Logs: SSH auth and web access log analysis.")


def show_version(value: bool) -> None:
    if value:
        typer.echo(f"pysuite {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[bool, typer.Option("--version", "-V", callback=show_version, is_eager=True)] = False,
):
    pass


if __name__ == "__main__":
    app()
