import httpx
from rich.table import Table
from rich.prompt import Prompt

from core.console import console
from core.utils import pause
from core.validators import is_valid_url

def inspect_url(url: str) -> dict:
    timeout = httpx.Timeout(10.0, connect=5.0)
    with httpx.Client(follow_redirects=True, timeout=timeout) as client:
        response = client.get(url)
        return {
            "Final URL": str(response.url),
            "Status Code": response.status_code,
            "HTTP Version": response.http_version,
            "Server": response.headers.get("server", "-"),
            "Content-Type": response.headers.get("content-type", "-"),
            "Content-Length": response.headers.get("content-length", "-"),
        }

def http_inspector_menu():
    console.print("\n[bold cyan]HTTP Inspector[/bold cyan]")
    url = Prompt.ask("Enter URL (include http:// or https://)").strip()

    if not is_valid_url(url):
        console.print("[bold red]Invalid URL.[/bold red]")
        pause()
        return

    try:
        result = inspect_url(url)
        table = Table(title="HTTP Inspection")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        for key, value in result.items():
            table.add_row(str(key), str(value))

        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")

    pause()