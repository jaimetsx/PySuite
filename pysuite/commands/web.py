"""Web and TLS auditing."""

from __future__ import annotations

import socket
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Annotated

import typer
from rich.table import Table

from pysuite.utils import USER_AGENT, console, die

app = typer.Typer(no_args_is_help=True)

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Forces HTTPS on future visits",
    "Content-Security-Policy": "Restricts where scripts/styles can load from (XSS mitigation)",
    "X-Content-Type-Options": "Stops MIME-type sniffing",
    "X-Frame-Options": "Prevents clickjacking via framing",
    "Referrer-Policy": "Limits referrer information leakage",
    "Permissions-Policy": "Restricts browser features (camera, geolocation...)",
}

LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"]


def normalize_url(url: str) -> str:
    return url if "://" in url else f"https://{url}"


def grade_headers(headers: Mapping[str, str]) -> dict:
    lowered = {k.lower(): v for k, v in headers.items()}
    present = {h: lowered[h.lower()] for h in SECURITY_HEADERS if h.lower() in lowered}
    missing = [h for h in SECURITY_HEADERS if h not in present]
    leaks = {h: lowered[h.lower()] for h in LEAKY_HEADERS if h.lower() in lowered}
    score = len(present) / len(SECURITY_HEADERS)
    grade = next(g for threshold, g in [(1, "A"), (0.8, "B"), (0.6, "C"), (0.4, "D"), (0, "F")] if score >= threshold)
    return {"present": present, "missing": missing, "leaks": leaks, "grade": grade}


def fetch(url: str, timeout: float, method: str = "GET") -> tuple[int, Mapping[str, str], str]:
    request = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.headers, response.url
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, url


def get_certificate(host: str, port: int, timeout: float) -> tuple[dict, str, tuple]:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(), tls.version(), tls.cipher()


def flatten_name(name: tuple) -> dict[str, str]:
    return {key: value for rdn in name for key, value in rdn}


@app.command()
def headers(
    url: Annotated[str, typer.Argument(help="URL to audit (https:// assumed)")],
    timeout: Annotated[float, typer.Option(help="Request timeout in seconds")] = 10,
    full: Annotated[bool, typer.Option("--full", help="Show full header values")] = False,
):
    """Audit HTTP security headers and information leaks."""
    url = normalize_url(url)
    try:
        status, response_headers, final_url = fetch(url, timeout)
    except (OSError, ValueError) as exc:
        die(f"request failed: {exc}")

    result = grade_headers(response_headers)
    colors = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "red"}
    console.print(f"[bold]{final_url}[/] -> HTTP {status}")
    console.print(f"Grade: [bold {colors[result['grade']]}]{result['grade']}[/]")

    table = Table()
    table.add_column("Header")
    table.add_column("Status")
    table.add_column("Value / Why it matters", overflow="fold")
    for name, why in SECURITY_HEADERS.items():
        if name in result["present"]:
            value = result["present"][name]
            if not full and len(value) > 120:
                value = value[:117] + "..."
            table.add_row(name, "[green]present[/]", value)
        else:
            table.add_row(name, "[red]missing[/]", f"[dim]{why}[/]")
    for name, value in result["leaks"].items():
        table.add_row(name, "[yellow]info leak[/]", value)
    console.print(table)


@app.command("ssl")
def ssl_check(
    host: Annotated[str, typer.Argument(help="Hostname (optionally host:port)")],
    timeout: Annotated[float, typer.Option(help="Connect timeout in seconds")] = 10,
    warn_days: Annotated[int, typer.Option(help="Warn if certificate expires within N days")] = 30,
):
    """Inspect a server's TLS certificate and expiry."""
    host = host.removeprefix("https://").split("/")[0]
    hostname, _, port = host.partition(":")
    try:
        cert, version, cipher = get_certificate(hostname, int(port or 443), timeout)
    except ssl.SSLCertVerificationError as exc:
        die(f"certificate verification FAILED: {exc.verify_message}")
    except (OSError, ssl.SSLError) as exc:
        die(f"TLS connection failed: {exc}")

    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
    days_left = (expires - datetime.now(timezone.utc)).days
    color = "red" if days_left < 0 else "yellow" if days_left <= warn_days else "green"
    subject, issuer = flatten_name(cert["subject"]), flatten_name(cert["issuer"])
    sans = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]

    table = Table(title=f"TLS certificate for {hostname}", show_header=False)
    table.add_column(style="bold cyan")
    table.add_column(overflow="fold")
    table.add_row("Subject", subject.get("commonName", "?"))
    table.add_row("Issuer", f"{issuer.get('organizationName', '')} {issuer.get('commonName', '')}".strip())
    table.add_row("Valid from", cert["notBefore"])
    table.add_row("Valid until", cert["notAfter"])
    table.add_row("Days left", f"[{color}]{days_left}[/]")
    table.add_row("Protocol", version or "?")
    table.add_row("Cipher", f"{cipher[0]} ({cipher[2]} bits)")
    table.add_row("SANs", ", ".join(sans[:20]) + (f" (+{len(sans) - 20} more)" if len(sans) > 20 else ""))
    table.add_row("Chain", "[green]trusted[/]")
    console.print(table)
    if days_left <= warn_days:
        raise typer.Exit(1)


@app.command()
def status(
    urls: Annotated[list[str], typer.Argument(help="One or more URLs")],
    timeout: Annotated[float, typer.Option(help="Request timeout in seconds")] = 10,
):
    """Check availability and response time of URLs."""

    def check(url: str) -> tuple[str, str, float]:
        start = time.perf_counter()
        try:
            code, _, _ = fetch(normalize_url(url), timeout)
            result = str(code)
        except (OSError, ValueError) as exc:
            result = f"ERR {getattr(exc, 'reason', exc)}"
        return url, result, (time.perf_counter() - start) * 1000

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(check, urls))

    table = Table()
    table.add_column("URL")
    table.add_column("Status")
    table.add_column("Time", justify="right")
    failures = 0
    for url, result, ms in results:
        ok = result[:1] in ("2", "3")
        failures += not ok
        table.add_row(url, f"[{'green' if ok else 'red'}]{result}[/]", f"{ms:.0f} ms")
    console.print(table)
    if failures:
        raise typer.Exit(1)
