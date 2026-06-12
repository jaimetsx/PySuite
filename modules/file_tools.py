from pathlib import Path
from datetime import datetime
import mimetypes

from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.panel import Panel

from core.console import console
from core.utils import pause
from core.validators import file_exists

MAX_PREVIEW_CHARS = 8000
TEXT_EXTENSIONS = {
    ".txt", ".log", ".md", ".py", ".js", ".ts", ".json", ".yaml", ".yml",
    ".xml", ".html", ".css", ".sh", ".ini", ".conf", ".env", ".csv"
}

def inspect_file(path: str) -> dict:
    file_path = Path(path)
    stat = file_path.stat()
    mime_type, _ = mimetypes.guess_type(path)

    return {
        "Name": file_path.name,
        "Absolute Path": str(file_path.resolve()),
        "Size (bytes)": stat.st_size,
        "Created": datetime.fromtimestamp(stat.st_ctime),
        "Modified": datetime.fromtimestamp(stat.st_mtime),
        "Suffix": file_path.suffix or "-",
        "MIME Type": mime_type or "unknown",
        "Readable": file_path.is_file(),
    }

def is_probably_text_file(file_path: Path) -> bool:
    if file_path.suffix.lower() in TEXT_EXTENSIONS:
        return True

    mime_type, _ = mimetypes.guess_type(str(file_path))
    if mime_type and mime_type.startswith("text/"):
        return True

    return False

def read_text_preview(file_path: Path, max_chars: int = MAX_PREVIEW_CHARS) -> str:
    content = file_path.read_text(encoding="utf-8", errors="replace")
    if len(content) > max_chars:
        return content[:max_chars] + "\n\n[Output truncated...]"
    return content

def file_tools_menu():
    console.print("\n[bold cyan]File Inspector[/bold cyan]")
    path = Prompt.ask("Enter file path").strip()

    if not file_exists(path):
        console.print("[bold red]File not found.[/bold red]")
        pause()
        return

    try:
        file_path = Path(path)
        result = inspect_file(path)

        table = Table(title=f"File Details - {file_path.name}")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        for key, value in result.items():
            table.add_row(str(key), str(value))

        console.print(table)

        if Confirm.ask("Do you want to view the file content?", default=False):
            if not is_probably_text_file(file_path):
                console.print(
                    "[bold yellow]This file does not appear to be a text file. Content preview skipped.[/bold yellow]"
                )
                pause()
                return

            preview = read_text_preview(file_path)
            console.print(
                Panel(
                    preview if preview else "[empty file]",
                    title=f"Content Preview - {file_path.name}",
                    border_style="green"
                )
            )

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")

    pause()