import ipaddress
from rich.table import Table
from rich.prompt import Prompt

from core.console import console
from core.utils import pause
from core.validators import is_valid_ip, is_valid_network

def ip_tools_menu():
    console.print("\n[bold cyan]IP / Subnet Tools[/bold cyan]")
    console.print("1. Inspect IP address")
    console.print("2. Inspect subnet")
    choice = Prompt.ask("Choose an option", default="1").strip()

    if choice == "1":
        value = Prompt.ask("Enter IP address").strip()

        if not is_valid_ip(value):
            console.print("[bold red]Invalid IP address.[/bold red]")
            pause()
            return

        ip_obj = ipaddress.ip_address(value)
        table = Table(title="IP Details")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Version", str(ip_obj.version))
        table.add_row("Compressed", str(ip_obj.compressed))
        table.add_row("Is Private", str(ip_obj.is_private))
        table.add_row("Is Global", str(ip_obj.is_global))
        table.add_row("Is Loopback", str(ip_obj.is_loopback))
        table.add_row("Is Multicast", str(ip_obj.is_multicast))
        console.print(table)

    elif choice == "2":
        value = Prompt.ask("Enter subnet (example: 192.168.1.0/24)").strip()

        if not is_valid_network(value):
            console.print("[bold red]Invalid subnet.[/bold red]")
            pause()
            return

        net = ipaddress.ip_network(value, strict=False)
        table = Table(title="Subnet Details")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Network Address", str(net.network_address))
        table.add_row("Broadcast Address", str(net.broadcast_address))
        table.add_row("Netmask", str(net.netmask))
        table.add_row("Prefix Length", str(net.prefixlen))
        table.add_row("Total Addresses", str(net.num_addresses))
        console.print(table)

    else:
        console.print("[bold red]Invalid option.[/bold red]")

    pause()