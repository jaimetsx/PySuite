"""Shared helpers: consoles, formatting and argument parsing."""

from __future__ import annotations

import json
import urllib.request
from typing import NoReturn

import typer
from rich.console import Console

from pysuite import __version__

console = Console()
err_console = Console(stderr=True)

USER_AGENT = f"PySuite/{__version__}"


def die(message: str, code: int = 1) -> NoReturn:
    err_console.print(f"[bold red]error:[/] {message}")
    raise typer.Exit(code)


def human_size(num_bytes: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num_bytes) < 1024:
            return f"{num_bytes:.0f} {unit}" if unit == "B" else f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} PB"


def parse_size(text: str) -> int:
    """Parse sizes like '500', '10K', '1.5M', '2G' into bytes."""
    text = text.strip().upper().removesuffix("B")
    multipliers = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
    if text and text[-1] in multipliers:
        return int(float(text[:-1]) * multipliers[text[-1]])
    return int(float(text))


def parse_ports(spec: str) -> list[int]:
    """Parse a port spec like '22,80,8000-8100' into a sorted list of ports."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = (int(p) for p in part.split("-", 1))
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    invalid = [p for p in ports if not 1 <= p <= 65535]
    if invalid:
        raise ValueError(f"ports out of range 1-65535: {invalid[:5]}")
    if not ports:
        raise ValueError("no ports given")
    return sorted(ports)


def http_get(url: str, timeout: float = 10.0) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def http_get_json(url: str, timeout: float = 10.0) -> dict:
    return json.loads(http_get(url, timeout))
