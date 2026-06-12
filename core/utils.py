import subprocess
import platform
from pathlib import Path

def pause():
    input("\nPress Enter to continue...")

def clear_screen() -> None:
    command = ["cmd", "/c", "cls"] if platform.system() == "Windows" else ["clear"]
    subprocess.run(command, check=False)

def safe_read_text(path: str, max_bytes: int = 200000) -> str:
    file_path = Path(path)
    with open(file_path, "rb") as f:
        content = f.read(max_bytes)
    return content.decode("utf-8", errors="replace")