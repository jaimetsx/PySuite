"""Local system inspection."""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Annotated

import psutil
import typer
from rich.table import Table

from pysuite.utils import console, die, human_size

app = typer.Typer(no_args_is_help=True)


def usage_color(percent: float) -> str:
    return "red" if percent >= 90 else "yellow" if percent >= 75 else "green"


def format_uptime(seconds: float) -> str:
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    return f"{days}d {hours}h {rem // 60}m"


@app.command()
def info():
    """Overview of OS, CPU, memory, disks and network interfaces."""
    boot = psutil.boot_time()
    mem, swap = psutil.virtual_memory(), psutil.swap_memory()
    freq = psutil.cpu_freq()
    cpu_percent = psutil.cpu_percent(interval=0.5)

    table = Table(title="System", show_header=False)
    table.add_column(style="bold cyan")
    table.add_column()
    table.add_row("Hostname", socket.gethostname())
    table.add_row("OS", platform.platform())
    table.add_row("Architecture", platform.machine())
    table.add_row("Boot time", datetime.fromtimestamp(boot).strftime("%Y-%m-%d %H:%M"))
    table.add_row("Uptime", format_uptime(time.time() - boot))
    table.add_row("CPU", f"{platform.processor() or '?'}")
    table.add_row("Cores", f"{psutil.cpu_count(logical=False)} physical / {psutil.cpu_count()} logical"
                  + (f" @ {freq.current:.0f} MHz" if freq else ""))
    table.add_row("CPU usage", f"[{usage_color(cpu_percent)}]{cpu_percent:.0f}%[/]")
    table.add_row("Memory", f"[{usage_color(mem.percent)}]{human_size(mem.used)} / {human_size(mem.total)} ({mem.percent:.0f}%)[/]")
    table.add_row("Swap", f"{human_size(swap.used)} / {human_size(swap.total)} ({swap.percent:.0f}%)")
    console.print(table)

    disks = Table(title="Disks")
    for col in ("Mount", "FS", "Used", "Total", "Use%"):
        disks.add_column(col, justify="right" if col in ("Used", "Total", "Use%") else "left")
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except (PermissionError, OSError):
            continue
        disks.add_row(part.mountpoint, part.fstype, human_size(usage.used), human_size(usage.total),
                      f"[{usage_color(usage.percent)}]{usage.percent:.0f}%[/]")
    console.print(disks)

    nets = Table(title="Network interfaces")
    nets.add_column("Interface")
    nets.add_column("Address")
    nets.add_column("Status")
    stats = psutil.net_if_stats()
    for name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family in (socket.AF_INET, socket.AF_INET6):
                up = stats.get(name) and stats[name].isup
                nets.add_row(name, addr.address, "[green]up[/]" if up else "[dim]down[/]")
    console.print(nets)


@app.command()
def procs(
    sort: Annotated[str, typer.Option("--sort", "-s", help="cpu or mem")] = "cpu",
    limit: Annotated[int, typer.Option("--limit", "-n")] = 15,
):
    """Top processes by CPU or memory."""
    if sort not in ("cpu", "mem"):
        die("--sort must be 'cpu' or 'mem'")
    processes = list(psutil.process_iter(["pid", "name", "username"]))
    for proc in processes:
        try:
            proc.cpu_percent(None)  # prime the counter
        except psutil.Error:
            pass
    time.sleep(0.5)
    rows = []
    for proc in processes:
        try:
            rows.append((proc.info["pid"], proc.info["name"] or "?", proc.info["username"] or "",
                         proc.cpu_percent(None), proc.memory_info().rss))
        except psutil.Error:
            continue
    rows.sort(key=lambda r: r[3] if sort == "cpu" else r[4], reverse=True)

    table = Table(title=f"Top {limit} processes by {sort}")
    for col in ("PID", "Name", "User", "CPU%", "Memory"):
        table.add_column(col, justify="right" if col in ("PID", "CPU%", "Memory") else "left")
    for pid, name, user, cpu, rss in rows[:limit]:
        table.add_row(str(pid), name, user, f"{cpu:.1f}", human_size(rss))
    console.print(table)


@app.command()
def listening(udp: Annotated[bool, typer.Option("--udp", help="Include UDP sockets")] = False):
    """Listening ports and the processes that own them."""
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        die("access denied - run with elevated privileges")

    names: dict[int, str] = {}

    def proc_name(pid: int | None) -> str:
        if not pid:
            return "?"
        if pid not in names:
            try:
                names[pid] = psutil.Process(pid).name()
            except psutil.Error:
                names[pid] = "?"
        return names[pid]

    rows = set()
    for conn in conns:
        is_tcp_listen = conn.type == socket.SOCK_STREAM and conn.status == psutil.CONN_LISTEN
        is_udp = udp and conn.type == socket.SOCK_DGRAM
        if (is_tcp_listen or is_udp) and conn.laddr:
            proto = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
            rows.add((proto, conn.laddr.ip, conn.laddr.port, conn.pid or 0))

    table = Table(title="Listening sockets")
    for col in ("Proto", "Address", "Port", "PID", "Process"):
        table.add_column(col, justify="right" if col in ("Port", "PID") else "left")
    for proto, ip, port, pid in sorted(rows, key=lambda r: (r[0], r[2], r[1])):
        exposed = ip in ("0.0.0.0", "::")
        table.add_row(proto, f"[yellow]{ip}[/]" if exposed else ip, str(port), str(pid or ""), proc_name(pid))
    console.print(table)
    console.print("[dim]Yellow addresses listen on all interfaces.[/]")


def is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


@app.command()
def conns(
    public_only: Annotated[bool, typer.Option("--public", help="Only connections to public IPs")] = False,
    resolve: Annotated[bool, typer.Option(help="Reverse-resolve remote IPs")] = False,
):
    """Established network connections and the processes that own them."""
    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        die("access denied - run with elevated privileges")

    rows = []
    for conn in connections:
        if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
            continue
        if public_only and not is_public(conn.raddr.ip):
            continue
        rows.append(conn)

    names: dict[int, str] = {}
    table = Table(title="Established connections")
    table.add_column("Process", overflow="fold")
    table.add_column("PID", justify="right")
    table.add_column("Local", no_wrap=True)
    table.add_column("Remote", no_wrap=True)
    if resolve:
        table.add_column("Host", overflow="fold")
    for conn in sorted(rows, key=lambda c: (c.pid or 0, c.raddr.ip)):
        pid = conn.pid or 0
        if pid not in names:
            try:
                names[pid] = psutil.Process(pid).name() if pid else "?"
            except psutil.Error:
                names[pid] = "?"
        remote = conn.raddr.ip
        host = ""
        if resolve:
            try:
                host = socket.gethostbyaddr(remote)[0]
            except OSError:
                pass
        remote_text = f"{remote}:{conn.raddr.port}"
        row = [names[pid], str(pid or ""), f"{conn.laddr.ip}:{conn.laddr.port}",
               f"[cyan]{remote_text}[/]" if is_public(remote) else remote_text]
        table.add_row(*row, *([host] if resolve else []))
    console.print(table)
    console.print(f"{len(rows)} connections ([cyan]cyan[/] = public internet)")


def windows_startup_entries() -> list[tuple[str, str, str]]:
    import winreg

    entries = []
    hives = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
    keys = {
        "Run": r"Software\Microsoft\Windows\CurrentVersion\Run",
        "RunOnce": r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "Run (32-bit)": r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    }
    for hive_name, hive in hives.items():
        for label, key_path in keys.items():
            try:
                with winreg.OpenKey(hive, key_path) as key:
                    for i in range(winreg.QueryInfoKey(key)[1]):
                        name, value, _ = winreg.EnumValue(key, i)
                        entries.append((f"{hive_name} {label}", name, str(value)))
            except OSError:
                continue
    folders = [
        Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
        Path(os.environ.get("PROGRAMDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\StartUp",
    ]
    for folder in folders:
        if folder.is_dir():
            for item in folder.iterdir():
                if item.name.lower() != "desktop.ini":
                    entries.append(("Startup folder", item.name, str(item)))
    return entries


def unix_startup_entries() -> list[tuple[str, str, str]]:
    entries = []
    home = Path.home()
    dirs = {
        "cron": [Path("/etc/cron.d"), Path("/var/spool/cron/crontabs"), Path("/var/spool/cron")],
        "systemd (enabled)": [Path("/etc/systemd/system/multi-user.target.wants"), home / ".config/systemd/user/default.target.wants"],
        "autostart": [Path("/etc/xdg/autostart"), home / ".config/autostart"],
        "launchd": [Path("/Library/LaunchDaemons"), Path("/Library/LaunchAgents"), home / "Library/LaunchAgents"],
    }
    for kind, paths in dirs.items():
        for directory in paths:
            try:
                for item in sorted(directory.iterdir()):
                    if item.is_file() or item.is_symlink():
                        target = str(item.resolve()) if item.is_symlink() else str(item)
                        entries.append((kind, item.name, target))
            except OSError:
                continue
    crontab = Path("/etc/crontab")
    if crontab.is_file():
        try:
            for line in crontab.read_text(errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and not ("=" in line.split()[0]):
                    entries.append(("cron", "/etc/crontab", line))
        except OSError:
            pass
    for rc in (Path("/etc/rc.local"),):
        if rc.is_file():
            entries.append(("rc.local", rc.name, str(rc)))
    return entries


@app.command()
def startup():
    """Programs configured to run at boot/logon (common persistence locations)."""
    entries = windows_startup_entries() if sys.platform.startswith("win") else unix_startup_entries()
    table = Table(title="Startup / persistence entries")
    table.add_column("Location")
    table.add_column("Name")
    table.add_column("Command / Path", overflow="fold")
    for location, name, value in entries:
        table.add_row(location, name, value)
    console.print(table)
    console.print(f"{len(entries)} entries - review anything you don't recognize.")


def firewall_status() -> list[tuple[str, bool | None, str]]:
    """Return (profile/backend, enabled, detail) tuples for the current OS."""
    if sys.platform.startswith("win"):
        cmd = ["powershell", "-NoProfile", "-Command",
               "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction | ConvertTo-Json"]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
        profiles = json.loads(out or "[]")
        if isinstance(profiles, dict):
            profiles = [profiles]
        # Enabled comes back as a GpoBoolean (1 = True); DefaultInboundAction 4 = Block, 2 = Allow, 0 = NotConfigured.
        inbound = {0: "inbound: block (Windows default)", 2: "inbound: ALLOW by default", 4: "inbound: block"}
        return [(p["Name"], bool(p["Enabled"]), inbound.get(p.get("DefaultInboundAction"), "")) for p in profiles]
    if sys.platform == "darwin":
        tool = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        out = subprocess.run([tool, "--getglobalstate"], capture_output=True, text=True).stdout
        return [("Application Firewall", "enabled" in out.lower(), out.strip())]
    if shutil.which("ufw"):
        result = subprocess.run(["ufw", "status"], capture_output=True, text=True)
        if result.returncode == 0:
            first = result.stdout.splitlines()[0] if result.stdout else ""
            return [("ufw", "active" in first and "inactive" not in first, first)]
    if shutil.which("firewall-cmd"):
        result = subprocess.run(["firewall-cmd", "--state"], capture_output=True, text=True)
        return [("firewalld", result.stdout.strip() == "running", result.stdout.strip() or result.stderr.strip())]
    if shutil.which("nft"):
        result = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True)
        if result.returncode == 0:
            rules = sum(1 for line in result.stdout.splitlines() if line.strip() and not line.strip().startswith(("table", "chain", "}", "type")))
            return [("nftables", rules > 0, f"{rules} rules")]
    return [("unknown", None, "no supported firewall tool found or insufficient privileges (try sudo)")]


@app.command()
def firewall():
    """Show whether the host firewall is enabled."""
    try:
        status_rows = firewall_status()
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        die(f"could not query firewall: {exc}")
    table = Table(title="Firewall")
    table.add_column("Profile / Backend")
    table.add_column("State")
    table.add_column("Details", overflow="fold")
    all_on = True
    for name, enabled, detail in status_rows:
        state = "[green]enabled[/]" if enabled else "[red]disabled[/]" if enabled is False else "[yellow]unknown[/]"
        all_on &= bool(enabled)
        table.add_row(name, state, detail)
    console.print(table)
    if not all_on:
        raise typer.Exit(1)


@app.command()
def users():
    """Currently logged-in user sessions."""
    table = Table(title="Logged-in users")
    for col in ("User", "Terminal", "Host", "Since"):
        table.add_column(col)
    for u in psutil.users():
        table.add_row(u.name, u.terminal or "", u.host or "local",
                      datetime.fromtimestamp(u.started).strftime("%Y-%m-%d %H:%M"))
    console.print(table)
