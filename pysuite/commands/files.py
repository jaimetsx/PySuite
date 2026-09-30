"""Filesystem auditing: space usage, duplicates, integrity and entropy."""

from __future__ import annotations

import hashlib
import heapq
import json
import math
import os
import stat
from collections import Counter, defaultdict
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

from pysuite.utils import console, die, human_size, parse_size

app = typer.Typer(no_args_is_help=True)


def walk_files(root: Path) -> Iterator[Path]:
    """Yield regular files under root, skipping symlinks and unreadable dirs."""
    for dirpath, _, filenames in os.walk(root, onerror=lambda e: None):
        for name in filenames:
            path = Path(dirpath, name)
            if not path.is_symlink() and path.is_file():
                yield path


def sha256_file(path: Path, limit: int | None = None) -> str:
    h = hashlib.sha256()
    remaining = limit
    with path.open("rb") as fh:
        while chunk := fh.read(1 << 20 if remaining is None else min(1 << 20, remaining)):
            h.update(chunk)
            if remaining is not None:
                remaining -= len(chunk)
                if remaining <= 0:
                    break
    return h.hexdigest()


def find_duplicates(root: Path, min_size: int = 1) -> list[list[Path]]:
    by_size: dict[int, list[Path]] = defaultdict(list)
    for path in walk_files(root):
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size >= min_size:
            by_size[size].append(path)

    groups = []
    for paths in by_size.values():
        if len(paths) < 2:
            continue
        # Cheap partial hash first, full hash only for files that still collide.
        by_partial: dict[str, list[Path]] = defaultdict(list)
        for p in paths:
            try:
                by_partial[sha256_file(p, 64 * 1024)].append(p)
            except OSError:
                continue
        for candidates in by_partial.values():
            if len(candidates) < 2:
                continue
            by_full: dict[str, list[Path]] = defaultdict(list)
            for p in candidates:
                try:
                    by_full[sha256_file(p)].append(p)
                except OSError:
                    continue
            groups.extend(sorted(g) for g in by_full.values() if len(g) > 1)
    return groups


def build_baseline(root: Path) -> dict:
    files = {}
    for path in walk_files(root):
        try:
            stat = path.stat()
            files[path.relative_to(root).as_posix()] = {"sha256": sha256_file(path), "size": stat.st_size}
        except OSError:
            continue
    return {"root": str(root.resolve()), "created": datetime.now(timezone.utc).isoformat(), "files": files}


def compare_baseline(old: dict[str, dict], new: dict[str, dict]) -> dict[str, list[str]]:
    return {
        "added": sorted(new.keys() - old.keys()),
        "removed": sorted(old.keys() - new.keys()),
        "modified": sorted(k for k in old.keys() & new.keys() if old[k]["sha256"] != new[k]["sha256"]),
    }


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    return -sum(c / total * math.log2(c / total) for c in Counter(data).values())


@app.command()
def large(
    path: Annotated[Path, typer.Argument(help="Directory to scan")] = Path("."),
    top: Annotated[int, typer.Option("--top", "-n")] = 20,
):
    """Find the largest files under a directory."""
    if not path.is_dir():
        die(f"not a directory: {path}")
    with console.status("Scanning..."):
        sized = []
        for p in walk_files(path):
            try:
                sized.append((p.stat().st_size, p))
            except OSError:
                continue
        biggest = heapq.nlargest(top, sized)
    table = Table(title=f"Largest files in {path.resolve()}")
    table.add_column("Size", justify="right")
    table.add_column("Path", overflow="fold")
    for size, p in biggest:
        table.add_row(human_size(size), str(p))
    console.print(table)
    console.print(f"Scanned {len(sized):,} files, {human_size(sum(s for s, _ in sized))} total")


@app.command()
def dupes(
    path: Annotated[Path, typer.Argument(help="Directory to scan")] = Path("."),
    min_size: Annotated[str, typer.Option("--min-size", help="Ignore files smaller than this, e.g. 1K, 5M")] = "1",
):
    """Find duplicate files by content (SHA-256)."""
    if not path.is_dir():
        die(f"not a directory: {path}")
    with console.status("Hashing candidates..."):
        groups = find_duplicates(path, parse_size(min_size))
    if not groups:
        console.print("[green]No duplicates found.[/]")
        return
    wasted = 0
    for i, group in enumerate(sorted(groups, key=lambda g: -g[0].stat().st_size), 1):
        size = group[0].stat().st_size
        wasted += size * (len(group) - 1)
        console.print(f"[bold]#{i}[/] {human_size(size)} x {len(group)}")
        for p in group:
            console.print(f"   {p}", markup=False, highlight=False)
    console.print(f"\n[bold]{len(groups)}[/] groups, [bold yellow]{human_size(wasted)}[/] reclaimable")


@app.command()
def baseline(
    path: Annotated[Path, typer.Argument(help="Directory to fingerprint")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Where to save the baseline")] = Path("baseline.json"),
):
    """Record SHA-256 hashes of every file for later integrity checks."""
    if not path.is_dir():
        die(f"not a directory: {path}")
    with console.status("Hashing files..."):
        data = build_baseline(path)
    output.write_text(json.dumps(data, indent=2))
    console.print(f"Saved baseline of [bold]{len(data['files']):,}[/] files to {output}")


@app.command()
def verify(
    baseline_file: Annotated[Path, typer.Argument(help="Baseline JSON created by 'files baseline'")] = Path("baseline.json"),
    path: Annotated[Path | None, typer.Option(help="Directory to check (default: the baseline's root)")] = None,
):
    """Compare a directory against a baseline; exits 1 if anything changed."""
    try:
        old = json.loads(baseline_file.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        die(f"cannot read baseline: {exc}")
    root = path or Path(old["root"])
    if not root.is_dir():
        die(f"not a directory: {root}")
    with console.status("Hashing files..."):
        diff = compare_baseline(old["files"], build_baseline(root)["files"])

    styles = {"added": "green", "removed": "red", "modified": "yellow"}
    changes = sum(len(v) for v in diff.values())
    for kind, paths in diff.items():
        for p in paths:
            console.print(f"[{styles[kind]}]{kind:>8}[/]  {p}")
    if changes:
        console.print(f"\n[bold red]{changes} change(s)[/] since {old['created']}")
        raise typer.Exit(1)
    console.print(f"[bold green]No changes[/] since {old['created']}")


def risky_permissions(root: Path) -> list[tuple[str, Path]]:
    """World-writable files/dirs and SUID/SGID binaries (POSIX only)."""
    findings = []
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
        for name in dirnames + filenames:
            path = Path(dirpath, name)
            try:
                st = path.lstat()
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                continue
            mode = st.st_mode
            if mode & stat.S_ISUID:
                findings.append(("SUID", path))
            if mode & stat.S_ISGID and not stat.S_ISDIR(mode):
                findings.append(("SGID", path))
            # World-writable dirs with the sticky bit (like /tmp) are expected.
            if mode & stat.S_IWOTH and not (stat.S_ISDIR(mode) and mode & stat.S_ISVTX):
                findings.append(("world-writable dir" if stat.S_ISDIR(mode) else "world-writable", path))
    return findings


@app.command()
def perms(path: Annotated[Path, typer.Argument(help="Directory to audit, e.g. /etc or /usr/bin")]):
    """Find world-writable files and SUID/SGID binaries (Linux/macOS)."""
    if os.name != "posix":
        die("perms audits POSIX permission bits and only works on Linux/macOS")
    if not path.is_dir():
        die(f"not a directory: {path}")
    with console.status("Walking filesystem..."):
        findings = risky_permissions(path)
    table = Table(title=f"Risky permissions under {path}")
    table.add_column("Finding")
    table.add_column("Mode")
    table.add_column("Owner")
    table.add_column("Path", overflow="fold")
    for kind, p in findings:
        try:
            st = p.lstat()
            owner = p.owner()
        except (OSError, KeyError):
            continue
        color = "red" if "writable" in kind else "yellow"
        table.add_row(f"[{color}]{kind}[/]", stat.filemode(st.st_mode), owner, str(p))
    console.print(table)
    console.print(f"{len(findings)} findings. SUID binaries are normal in /usr/bin - look for unexpected ones.")
    if any("writable" in kind for kind, _ in findings):
        raise typer.Exit(1)


@app.command()
def entropy(
    path: Annotated[Path, typer.Argument(help="File or directory")],
    threshold: Annotated[float, typer.Option(help="Flag files at or above this entropy (0-8)")] = 7.5,
    all_files: Annotated[bool, typer.Option("--all", help="Show every file, not just flagged ones")] = False,
):
    """Shannon entropy per file - high values suggest encrypted/packed/compressed data."""
    if not path.exists():
        die(f"not found: {path}")
    targets = [path] if path.is_file() else list(walk_files(path))
    table = Table(title="File entropy (bits/byte)")
    table.add_column("Entropy", justify="right")
    table.add_column("Size", justify="right")
    table.add_column("Path", overflow="fold")
    flagged = 0
    for p in targets:
        try:
            with p.open("rb") as fh:
                value = shannon_entropy(fh.read(4 * 1024 * 1024))
            size = p.stat().st_size
        except OSError:
            continue
        high = value >= threshold
        flagged += high
        if high or all_files:
            table.add_row(f"[{'red' if high else 'green'}]{value:.2f}[/]", human_size(size), str(p))
    console.print(table)
    console.print(f"{flagged} of {len(targets)} files at or above {threshold}")
