import base64
from urllib.parse import quote, unquote
from rich.prompt import Prompt
from rich.table import Table

from core.console import console
from core.utils import pause

def encoding_tools_menu():
    console.print("\n[bold cyan]Encoding / Decoding Tools[/bold cyan]")
    console.print("1. Base64 encode")
    console.print("2. Base64 decode")
    console.print("3. URL encode")
    console.print("4. URL decode")

    choice = Prompt.ask("Choose an option", default="1").strip()
    text = Prompt.ask("Enter text").strip()

    try:
        result = ""

        if choice == "1":
            result = base64.b64encode(text.encode()).decode()
        elif choice == "2":
            result = base64.b64decode(text.encode()).decode(errors="replace")
        elif choice == "3":
            result = quote(text)
        elif choice == "4":
            result = unquote(text)
        else:
            console.print("[bold red]Invalid option.[/bold red]")
            pause()
            return

        table = Table(title="Result")
        table.add_column("Operation", style="cyan")
        table.add_column("Output", style="white")
        operations = {
            "1": "Base64 Encode",
            "2": "Base64 Decode",
            "3": "URL Encode",
            "4": "URL Decode",
        }
        table.add_row(operations[choice], result)
        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")

    pause()