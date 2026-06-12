import hashlib
from pathlib import Path
from rich.table import Table
from rich.prompt import Prompt

from core.console import console
from core.utils import pause
from core.validators import file_exists

def calculate_hashes(file_path: str) -> dict:
    hashes = {
        "MD5": hashlib.md5(),
        "SHA1": hashlib.sha1(),
        "SHA256": hashlib.sha256(),
        "SHA512": hashlib.sha512(),
    }

    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            for algo in hashes.values():
                algo.update(chunk)

    return {name: algo.hexdigest() for name, algo in hashes.items()}

def hash_file_menu():
    console.print("\n[bold cyan]File Hash Checker[/bold cyan]")
    file_path = Prompt.ask("Enter file path").strip()

    if not file_exists(file_path):
        console.print("[bold red]File not found.[/bold red]")
        pause()
        return

    try:
        results = calculate_hashes(file_path)
        table = Table(title=f"Hash Results - {Path(file_path).name}")
        table.add_column("Algorithm", style="cyan")
        table.add_column("Digest", style="white")

        for name, digest in results.items():
            table.add_row(name, digest)

        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")

    pause()