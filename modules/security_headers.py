import httpx
from rich.table import Table
from rich.prompt import Prompt

from core.console import console
from core.utils import pause
from core.validators import is_valid_url

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

def check_security_headers(url: str) -> dict:
    timeout = httpx.Timeout(10.0, connect=5.0)
    with httpx.Client(follow_redirects=True, timeout=timeout) as client:
        response = client.get(url)
        headers = response.headers
        return {header: headers.get(header, "Missing") for header in SECURITY_HEADERS}

def security_headers_menu():
    console.print("\n[bold cyan]Security Headers Check[/bold cyan]")
    url = Prompt.ask("Enter URL (include http:// or https://)").strip()

    if not is_valid_url(url):
        console.print("[bold red]Invalid URL.[/bold red]")
        pause()
        return

    try:
        results = check_security_headers(url)
        table = Table(title=f"Security Headers - {url}")
        table.add_column("Header", style="cyan")
        table.add_column("Value", style="white")

        for header, value in results.items():
            table.add_row(header, value)

        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")

    pause()