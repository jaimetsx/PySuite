import whois
from rich.table import Table
from rich.prompt import Prompt

from core.console import console
from core.utils import pause

def whois_lookup_menu():
    console.print("\n[bold cyan]Whois Lookup[/bold cyan]")
    domain = Prompt.ask("Enter domain").strip()

    try:
        result = whois.whois(domain)

        table = Table(title=f"Whois Results for {domain}")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        fields = [
            "domain_name",
            "registrar",
            "creation_date",
            "expiration_date",
            "updated_date",
            "name_servers",
            "emails",
        ]

        for field in fields:
            value = result.get(field, "-")
            table.add_row(field, str(value))

        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")

    pause()