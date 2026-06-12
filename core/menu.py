from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt

from core.console import console
from core.utils import clear_screen, pause

from modules.hash_tools import hash_file_menu
from modules.dns_tools import dns_lookup_menu
from modules.http_tools import http_inspector_menu
from modules.security_headers import security_headers_menu
from modules.ip_tools import ip_tools_menu
from modules.port_tools import port_checker_menu
from modules.whois_tools import whois_lookup_menu
from modules.encoding_tools import encoding_tools_menu
from modules.file_tools import file_tools_menu

def show_banner():
    console.print(
        Panel.fit(
            "[bold cyan]PySuite[/bold cyan]\n[white]Terminal utilities for cybersecurity and sysadmin workflows[/white]",
            border_style="cyan"
        )
    )

def run_main_menu():
    while True:
        clear_screen()
        show_banner()

        table = Table(title="Main Menu", header_style="bold magenta")
        table.add_column("Option", style="cyan", justify="center")
        table.add_column("Category", style="white")

        table.add_row("1", "File Hash Checker")
        table.add_row("2", "DNS Lookup")
        table.add_row("3", "HTTP Inspector")
        table.add_row("4", "Security Headers Check")
        table.add_row("5", "IP / Subnet Tools")
        table.add_row("6", "Port Checker")
        table.add_row("7", "Whois Lookup")
        table.add_row("8", "Encoding / Decoding Tools")
        table.add_row("9", "File Inspector")
        table.add_row("0", "Exit")

        console.print(table)
        choice = Prompt.ask("Choose an option", default="0").strip()

        if choice == "1":
            hash_file_menu()
        elif choice == "2":
            dns_lookup_menu()
        elif choice == "3":
            http_inspector_menu()
        elif choice == "4":
            security_headers_menu()
        elif choice == "5":
            ip_tools_menu()
        elif choice == "6":
            port_checker_menu()
        elif choice == "7":
            whois_lookup_menu()
        elif choice == "8":
            encoding_tools_menu()
        elif choice == "9":
            file_tools_menu()
        elif choice == "0":
            console.print("\n[bold green]Goodbye.[/bold green]")
            break
        else:
            console.print("[bold red]Invalid option.[/bold red]")
            pause()