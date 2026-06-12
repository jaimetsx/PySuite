import socket
from rich.table import Table
from rich.prompt import Prompt

from core.console import console
from core.utils import pause

def check_port(host: str, port: int, timeout: float = 1.0) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0

def port_checker_menu():
    console.print("\n[bold cyan]Port Checker[/bold cyan]")
    host = Prompt.ask("Enter host or IP").strip()
    ports_input = Prompt.ask("Enter ports separated by commas (example: 22,80,443)").strip()

    try:
        ports = [int(p.strip()) for p in ports_input.split(",") if p.strip()]
        table = Table(title=f"Port Results for {host}")
        table.add_column("Port", style="cyan")
        table.add_column("Status", style="white")

        for port in ports:
            if port < 1 or port > 65535:
                table.add_row(str(port), "[bold red]Invalid range[/bold red]")
                continue

            status = "OPEN" if check_port(host, port) else "CLOSED"
            status_color = "bold green" if status == "OPEN" else "bold red"
            table.add_row(str(port), f"[{status_color}]{status}[/{status_color}]")

        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")

    pause()