import dns.resolver
import dns.reversename
from rich.table import Table
from rich.prompt import Prompt

from core.console import console
from core.utils import pause

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

def dns_lookup(domain: str) -> dict:
    results = {}
    resolver = dns.resolver.Resolver()

    for record_type in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, record_type)
            results[record_type] = [r.to_text() for r in answers]
        except Exception:
            results[record_type] = []

    return results

def reverse_dns_lookup(ip: str) -> list:
    try:
        reverse_name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(reverse_name, "PTR")
        return [r.to_text() for r in answers]
    except Exception:
        return []

def dns_lookup_menu():
    console.print("\n[bold cyan]DNS Lookup[/bold cyan]")
    console.print("1. Standard DNS lookup")
    console.print("2. Reverse DNS lookup")
    choice = Prompt.ask("Choose an option", default="1").strip()

    if choice == "1":
        domain = Prompt.ask("Enter domain").strip()
        try:
            results = dns_lookup(domain)
            table = Table(title=f"DNS Results for {domain}")
            table.add_column("Type", style="cyan")
            table.add_column("Values", style="white")

            for record_type, values in results.items():
                table.add_row(record_type, "\n".join(values) if values else "-")

            console.print(table)
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")

    elif choice == "2":
        ip = Prompt.ask("Enter IP address").strip()
        results = reverse_dns_lookup(ip)
        table = Table(title=f"Reverse DNS Results for {ip}")
        table.add_column("PTR", style="cyan")
        if results:
            for item in results:
                table.add_row(item)
        else:
            table.add_row("-")
        console.print(table)

    else:
        console.print("[bold red]Invalid option.[/bold red]")

    pause()