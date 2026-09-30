"""Network reconnaissance and diagnostics."""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Annotated, Optional

import typer
from dns import exception as dns_exception
from dns import resolver as dns_resolver
from dns import reversename
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn
from rich.table import Table

from pysuite.utils import console, die, http_get_json, parse_ports

app = typer.Typer(no_args_is_help=True)

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587,
    636, 993, 995, 1433, 1521, 1723, 2049, 3306, 3389, 5432, 5900, 5985, 6379,
    8000, 8080, 8443, 9000, 9200, 11211, 27017,
]

WHOIS_FIELDS = [
    "Domain Name", "Registrar", "Creation Date", "Updated Date",
    "Registry Expiry Date", "Registrar Registration Expiration Date",
    "Expiration Date", "Name Server", "Domain Status", "DNSSEC",
]


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "?"


def probe_port(host: str, port: int, timeout: float, grab_banner: bool) -> tuple[int, bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = ""
            if grab_banner:
                try:
                    banner = sock.recv(256).decode(errors="replace").strip()
                except OSError:
                    pass
            return port, True, banner
    except OSError:
        return port, False, ""


def ping_host(ip: str, timeout_ms: int) -> bool:
    if sys.platform.startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    result = subprocess.run(cmd, capture_output=True)
    # Windows ping exits 0 on "Destination host unreachable", so look for a real reply.
    return result.returncode == 0 and b"ttl=" in result.stdout.lower()


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def subnet_info(cidr: str) -> dict[str, str]:
    net = ipaddress.ip_network(cidr, strict=False)
    info = {
        "Network": str(net.network_address),
        "Prefix": f"/{net.prefixlen}",
        "Netmask": str(net.netmask),
        "Wildcard": str(net.hostmask),
        "Total addresses": f"{net.num_addresses:,}",
    }
    if net.version == 4:
        info["Broadcast"] = str(net.broadcast_address)
    hosts = list(net.hosts()) if net.num_addresses <= 2**16 else None
    if hosts:
        info["First host"] = str(hosts[0])
        info["Last host"] = str(hosts[-1])
        info["Usable hosts"] = f"{len(hosts):,}"
    info["Private"] = "yes" if net.is_private else "no"
    return info


def whois_query(server: str, query: str, timeout: float = 10.0) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall(f"{query}\r\n".encode())
        chunks = []
        while data := sock.recv(4096):
            chunks.append(data)
    return b"".join(chunks).decode(errors="replace")


def parse_whois(text: str) -> list[tuple[str, str]]:
    fields = []
    seen = set()
    for line in text.splitlines():
        key, sep, value = line.strip().partition(":")
        key, value = key.strip(), value.strip()
        if sep and value and key in WHOIS_FIELDS and (key, value.lower()) not in seen:
            seen.add((key, value.lower()))
            fields.append((key, value))
    return fields


@app.command()
def scan(
    host: Annotated[str, typer.Argument(help="Target hostname or IP")],
    ports: Annotated[Optional[str], typer.Option("--ports", "-p", help="e.g. 22,80,8000-8100 (default: common ports)")] = None,
    timeout: Annotated[float, typer.Option(help="Connect timeout in seconds")] = 0.5,
    workers: Annotated[int, typer.Option(help="Concurrent connections")] = 200,
    banner: Annotated[bool, typer.Option("--banner", "-b", help="Try to grab service banners")] = False,
    show_closed: Annotated[bool, typer.Option(help="Also list closed ports")] = False,
):
    """TCP connect port scan. Only scan hosts you are authorized to test."""
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        die(f"cannot resolve {host}")
    try:
        port_list = parse_ports(ports) if ports else COMMON_PORTS
    except ValueError as exc:
        die(str(exc))

    console.print(f"Scanning [bold]{host}[/] ({ip}) - {len(port_list)} ports")
    results = []
    with Progress(TextColumn("{task.description}"), BarColumn(), MofNCompleteColumn(), transient=True) as progress:
        task = progress.add_task("scanning", total=len(port_list))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(probe_port, ip, p, timeout, banner) for p in port_list]
            for future in as_completed(futures):
                results.append(future.result())
                progress.advance(task)

    table = Table(title=f"Scan results for {host}")
    table.add_column("Port", justify="right")
    table.add_column("State")
    table.add_column("Service")
    if banner:
        table.add_column("Banner", overflow="fold")
    open_count = 0
    for port, is_open, text in sorted(results):
        if not is_open and not show_closed:
            continue
        open_count += is_open
        row = [str(port), "[green]open[/]" if is_open else "[dim]closed[/]", service_name(port)]
        if banner:
            row.append(text)
        table.add_row(*row)
    console.print(table)
    console.print(f"[bold]{open_count}[/] open / {len(port_list)} scanned")


@app.command()
def sweep(
    cidr: Annotated[str, typer.Argument(help="Network to sweep, e.g. 192.168.1.0/24")],
    timeout: Annotated[int, typer.Option(help="Ping timeout in ms")] = 800,
    workers: Annotated[int, typer.Option(help="Concurrent pings")] = 64,
    resolve: Annotated[bool, typer.Option(help="Reverse-resolve live hosts")] = True,
):
    """Discover live hosts in a network with ICMP ping."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        die(str(exc))
    if net.num_addresses > 4096:
        die("network too large (max 4096 addresses, e.g. /20)")
    hosts = [str(h) for h in net.hosts()] or [str(net.network_address)]

    alive = []
    with Progress(TextColumn("{task.description}"), BarColumn(), MofNCompleteColumn(), transient=True) as progress:
        task = progress.add_task("pinging", total=len(hosts))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(ping_host, h, timeout): h for h in hosts}
            for future in as_completed(futures):
                if future.result():
                    alive.append(futures[future])
                progress.advance(task)

    alive.sort(key=ipaddress.ip_address)
    table = Table(title=f"Live hosts in {net}")
    table.add_column("IP")
    table.add_column("Hostname")
    for ip in alive:
        table.add_row(ip, reverse_dns(ip) if resolve else "")
    console.print(table)
    console.print(f"[bold]{len(alive)}[/] of {len(hosts)} hosts responded")


@app.command("dns")
def dns_lookup(
    name: Annotated[str, typer.Argument(help="Domain name, or an IP for reverse lookup")],
    types: Annotated[list[str], typer.Option("--type", "-t", help="Record type (repeatable)")] = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"],
    server: Annotated[Optional[str], typer.Option(help="Use this DNS server instead of the system one")] = None,
):
    """Query DNS records (or PTR for an IP address)."""
    res = dns_resolver.Resolver()
    if server:
        res.nameservers = [server]
    try:
        ipaddress.ip_address(name)
        name, types = str(reversename.from_address(name)), ["PTR"]
    except ValueError:
        pass

    table = Table(title=f"DNS records for {name}")
    table.add_column("Type")
    table.add_column("TTL", justify="right")
    table.add_column("Value", overflow="fold")
    for rtype in types:
        try:
            answer = res.resolve(name, rtype.upper())
        except (dns_resolver.NoAnswer, dns_resolver.NXDOMAIN, dns_resolver.NoNameservers):
            continue
        except dns_exception.Timeout:
            table.add_row(rtype.upper(), "", "[red]timeout[/]")
            continue
        except dns_exception.DNSException as exc:
            die(str(exc))
        for record in answer:
            table.add_row(rtype.upper(), str(answer.rrset.ttl), record.to_text())
    if not table.rows:
        die(f"no records found for {name}")
    console.print(table)


@app.command()
def whois(
    domain: Annotated[str, typer.Argument(help="Domain or IP to look up")],
    raw: Annotated[bool, typer.Option("--raw", help="Print the full WHOIS response")] = False,
):
    """WHOIS lookup, following registry referrals."""
    try:
        response = whois_query("whois.iana.org", domain)
        server = "whois.iana.org"
        if match := re.search(r"^(?:refer|whois):\s*(\S+)", response, re.M | re.I):
            server = match.group(1)
            response = whois_query(server, domain)
        # Thin registries (.com/.net) point to the registrar's own WHOIS server.
        if match := re.search(r"Registrar WHOIS Server:\s*(\S+)", response, re.I):
            registrar_server = match.group(1).removeprefix("whois://").removeprefix("http://").rstrip("/")
            if registrar_server.lower() != server.lower():
                try:
                    detailed = whois_query(registrar_server, domain)
                    if detailed.strip():
                        response, server = detailed, registrar_server
                except OSError:
                    pass
    except OSError as exc:
        die(f"WHOIS query failed: {exc}")

    console.print(f"[dim]source: {server}[/]")
    fields = parse_whois(response)
    if raw or not fields:
        console.print(response, markup=False, highlight=False)
        return
    table = Table(title=f"WHOIS {domain}", show_header=False)
    table.add_column(style="bold cyan")
    table.add_column()
    for key, value in fields:
        table.add_row(key, value)
    console.print(table)


@app.command()
def subnet(cidr: Annotated[str, typer.Argument(help="e.g. 10.0.0.0/22 or 192.168.1.10/255.255.255.0")]):
    """Subnet calculator."""
    try:
        info = subnet_info(cidr)
    except ValueError as exc:
        die(str(exc))
    table = Table(title=cidr, show_header=False)
    table.add_column(style="bold cyan")
    table.add_column()
    for key, value in info.items():
        table.add_row(key, value)
    console.print(table)


def txt_records(res: dns_resolver.Resolver, name: str) -> list[str]:
    try:
        answer = res.resolve(name, "TXT")
    except (dns_resolver.NoAnswer, dns_resolver.NXDOMAIN, dns_resolver.NoNameservers, dns_exception.Timeout):
        return []
    return [b"".join(r.strings).decode(errors="replace") for r in answer]


def assess_spf(records: list[str]) -> tuple[str, str]:
    spf = [r for r in records if r.lower().startswith("v=spf1")]
    if not spf:
        return "fail", "no SPF record - anyone can spoof mail from this domain"
    if len(spf) > 1:
        return "fail", "multiple SPF records (invalid, receivers will ignore them)"
    record = spf[0]
    if "+all" in record or record.rstrip().endswith(" all"):
        return "fail", f"{record}  (+all allows every sender)"
    if "-all" in record:
        return "ok", record
    return "warn", f"{record}  (~all/?all is soft - consider -all)"


def assess_dmarc(records: list[str]) -> tuple[str, str]:
    dmarc = [r for r in records if r.lower().startswith("v=dmarc1")]
    if not dmarc:
        return "fail", "no DMARC record"
    record = dmarc[0]
    policy = re.search(r"\bp=(\w+)", record)
    policy = policy.group(1).lower() if policy else "none"
    if policy == "reject":
        return "ok", record
    if policy == "quarantine":
        return "warn", f"{record}  (quarantine - reject is stronger)"
    return "fail", f"{record}  (p=none only monitors, it does not block spoofing)"


@app.command()
def check(
    host: Annotated[str, typer.Argument(help="Hostname or IP")],
    port: Annotated[int, typer.Argument(help="TCP port")],
    count: Annotated[int, typer.Option("--count", "-c", help="Number of attempts")] = 4,
    timeout: Annotated[float, typer.Option(help="Timeout per attempt in seconds")] = 3,
):
    """Check TCP reachability of host:port and measure connect latency."""
    if not 1 <= port <= 65535:
        die("port must be 1-65535")
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        die(f"cannot resolve {host}")
    times = []
    for i in range(count):
        start = time.perf_counter()
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                elapsed = (time.perf_counter() - start) * 1000
            times.append(elapsed)
            console.print(f"[green]connected[/] to {host} ({ip}):{port}  {elapsed:.1f} ms")
        except OSError as exc:
            console.print(f"[red]failed[/]    {host} ({ip}):{port}  {exc.strerror or exc}")
        if i < count - 1:
            time.sleep(0.5)
    if times:
        console.print(f"\n{len(times)}/{count} succeeded - min {min(times):.1f} / avg {sum(times) / len(times):.1f} / max {max(times):.1f} ms")
    else:
        console.print(f"\n[bold red]0/{count} succeeded[/]")
        raise typer.Exit(1)


@app.command()
def mailsec(domain: Annotated[str, typer.Argument(help="Domain to audit, e.g. example.com")]):
    """Audit a domain's email anti-spoofing setup (MX, SPF, DMARC, MTA-STS)."""
    res = dns_resolver.Resolver()
    try:
        mx = sorted((r.preference, r.exchange.to_text()) for r in res.resolve(domain, "MX"))
    except (dns_resolver.NoAnswer, dns_resolver.NXDOMAIN, dns_resolver.NoNameservers, dns_exception.Timeout):
        mx = []
    checks = [
        ("MX", ("ok", ", ".join(f"{p} {h}" for p, h in mx)) if mx else ("warn", "no MX records (domain does not receive mail)")),
        ("SPF", assess_spf(txt_records(res, domain))),
        ("DMARC", assess_dmarc(txt_records(res, f"_dmarc.{domain}"))),
    ]
    mta_sts = [r for r in txt_records(res, f"_mta-sts.{domain}") if r.lower().startswith("v=stsv1")]
    checks.append(("MTA-STS", ("ok", mta_sts[0]) if mta_sts else ("warn", "not configured (optional, enforces TLS for inbound mail)")))

    labels = {"ok": "[green]OK[/]", "warn": "[yellow]WARN[/]", "fail": "[red]FAIL[/]"}
    table = Table(title=f"Email security for {domain}")
    table.add_column("Check")
    table.add_column("Result")
    table.add_column("Details", overflow="fold")
    for name, (state, detail) in checks:
        table.add_row(name, labels[state], detail)
    console.print(table)
    if any(state == "fail" for _, (state, _) in checks):
        raise typer.Exit(1)


@app.command()
def myip():
    """Show your public IP address and its geolocation."""
    try:
        data = http_get_json("https://ipinfo.io/json")
    except OSError as exc:
        die(f"lookup failed: {exc}")
    table = Table(show_header=False)
    table.add_column(style="bold cyan")
    table.add_column()
    for key in ("ip", "hostname", "org", "city", "region", "country", "timezone"):
        if data.get(key):
            table.add_row(key, str(data[key]))
    console.print(table)
