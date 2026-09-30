"""Log analysis for incident response and monitoring."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

from pysuite.utils import console, die

app = typer.Typer(no_args_is_help=True)

SSH_FAILED = re.compile(r"Failed \S+ for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
SSH_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
SSH_ACCEPTED = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")

# Common / combined log format (Apache, Nginx).
ACCESS_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?'
)

ATTACK_SIGNATURES = {
    "path traversal": r"\.\./|%2e%2e",
    "sql injection": r"union[\s+%20]+select|'\s*or\s*'?1'?\s*=|sleep\(\d+\)|information_schema",
    "xss": r"<script|%3cscript|javascript:|onerror=",
    "sensitive file probe": r"/\.env|/\.git/|wp-config|/etc/passwd|\.htaccess|\.aws/credentials",
    "admin panel probe": r"/wp-admin|/wp-login|/phpmyadmin|/administrator",
    "shell/command injection": r";\s*(?:wget|curl|bash|sh)\b|\$\(|%24%28|cmd\.exe",
    "scanner user-agent": r"sqlmap|nikto|nmap|masscan|zgrab|nuclei|dirbuster|gobuster",
}


def read_lines(path: Path) -> list[str]:
    if not path.is_file():
        die(f"file not found: {path}")
    return path.read_text(errors="replace").splitlines()


def analyze_auth(lines: list[str]) -> dict:
    failed_ip: Counter = Counter()
    failed_user: Counter = Counter()
    accepted = []
    for line in lines:
        if m := SSH_ACCEPTED.search(line):
            accepted.append((m["user"], m["ip"], m["method"]))
        elif m := SSH_FAILED.search(line) or SSH_INVALID.search(line):
            failed_ip[m["ip"]] += 1
            failed_user[m["user"]] += 1
    return {"failed_ip": failed_ip, "failed_user": failed_user, "accepted": accepted}


def analyze_access(lines: list[str]) -> dict:
    ips: Counter = Counter()
    statuses: Counter = Counter()
    paths: Counter = Counter()
    hits: dict[str, list[tuple[str, str]]] = defaultdict(list)
    parsed = 0
    for line in lines:
        m = ACCESS_LINE.match(line)
        if not m:
            continue
        parsed += 1
        ips[m["ip"]] += 1
        statuses[m["status"]] += 1
        paths[m["path"]] += 1
        haystack = f"{m['path']} {m['agent'] or ''}".lower()
        for name, pattern in ATTACK_SIGNATURES.items():
            if re.search(pattern, haystack):
                hits[name].append((m["ip"], m["path"]))
    return {"parsed": parsed, "ips": ips, "statuses": statuses, "paths": paths, "hits": hits}


def counter_table(title: str, counter: Counter, label: str, top: int) -> Table:
    table = Table(title=title, title_justify="left")
    table.add_column(label, overflow="fold")
    table.add_column("Count", justify="right")
    for key, count in counter.most_common(top):
        table.add_row(key, str(count))
    return table


@app.command()
def auth(
    logfile: Annotated[Path, typer.Argument(help="SSH auth log, e.g. /var/log/auth.log or /var/log/secure")],
    top: Annotated[int, typer.Option("--top", "-n")] = 10,
    threshold: Annotated[int, typer.Option(help="Failures from one IP to flag it as brute force")] = 10,
):
    """Summarize SSH logins: brute-force sources, targeted users, successful logins."""
    result = analyze_auth(read_lines(logfile))
    failed_ip, accepted = result["failed_ip"], result["accepted"]
    total_failed = sum(failed_ip.values())
    console.print(f"[bold]{total_failed}[/] failed attempts from [bold]{len(failed_ip)}[/] IPs, "
                  f"[bold]{len(accepted)}[/] successful logins")
    if failed_ip:
        console.print(counter_table("Top failing source IPs", failed_ip, "IP", top))
        console.print(counter_table("Most targeted usernames", result["failed_user"], "User", top))
    if accepted:
        table = Table(title="Successful logins", title_justify="left")
        for col in ("User", "From", "Method", "Note"):
            table.add_column(col)
        for user, ip, method in accepted:
            note = f"[bold red]{failed_ip[ip]} prior failures from this IP[/]" if failed_ip[ip] >= threshold else ""
            table.add_row(user, ip, method, note)
        console.print(table)
    brute = [ip for ip, n in failed_ip.items() if n >= threshold]
    if brute:
        console.print(f"[yellow]{len(brute)} IP(s) with >= {threshold} failures - consider blocking (e.g. fail2ban).[/]")


@app.command()
def access(
    logfile: Annotated[Path, typer.Argument(help="Apache/Nginx access log (common or combined format)")],
    top: Annotated[int, typer.Option("--top", "-n")] = 10,
    show_hits: Annotated[int, typer.Option(help="Example requests to show per attack category")] = 3,
):
    """Web access log report: top clients, status codes, and attack signatures."""
    result = analyze_access(read_lines(logfile))
    if not result["parsed"]:
        die("no lines matched the common/combined log format")
    statuses = result["statuses"]
    errors4 = sum(n for s, n in statuses.items() if s.startswith("4"))
    errors5 = sum(n for s, n in statuses.items() if s.startswith("5"))
    console.print(f"[bold]{result['parsed']:,}[/] requests, [yellow]{errors4:,}[/] 4xx, [red]{errors5:,}[/] 5xx")
    console.print(counter_table("Top clients", result["ips"], "IP", top))
    console.print(counter_table("Status codes", statuses, "Status", top))
    console.print(counter_table("Top paths", result["paths"], "Path", top))

    if not result["hits"]:
        console.print("[green]No attack signatures detected.[/]")
        return
    table = Table(title="Attack signatures detected", title_justify="left")
    table.add_column("Category")
    table.add_column("Hits", justify="right")
    table.add_column("Source IPs", justify="right")
    table.add_column("Examples", overflow="fold")
    for name, hits in sorted(result["hits"].items(), key=lambda kv: -len(kv[1])):
        examples = "\n".join(f"{ip} {path}" for ip, path in hits[:show_hits])
        table.add_row(f"[red]{name}[/]", str(len(hits)), str(len({ip for ip, _ in hits})), examples)
    console.print(table)
