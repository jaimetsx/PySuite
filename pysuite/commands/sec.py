"""Crypto, password and forensics helpers."""

from __future__ import annotations

import base64
import codecs
import hashlib
import hmac
import json
import math
import re
import secrets
import string
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.json import JSON
from rich.table import Table

from pysuite.utils import console, die, http_get

app = typer.Typer(no_args_is_help=True)

HASH_ALGOS = ["md5", "sha1", "sha256", "sha512", "sha3_256", "blake2b"]
CODECS = ["b64", "b64url", "hex", "url", "rot13"]
AMBIGUOUS = set("Il1O0o")
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?"
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "letmein", "admin",
    "welcome", "iloveyou", "monkey", "dragon", "football", "baseball", "111111",
    "123123", "sunshine", "master", "passw0rd", "shadow", "trustno1",
}

IOC_PATTERNS = {
    "ipv4": r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
    "url": r"\bhttps?://[^\s\"'<>()]+",
    "email": r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[a-zA-Z]{2,}\b",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "sha1": r"\b[a-fA-F0-9]{40}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "cve": r"\bCVE-\d{4}-\d{4,7}\b",
}


# ---------- pure helpers ----------

def hash_bytes_stream(chunks, algos: list[str]) -> dict[str, str]:
    hashers = {a: hashlib.new(a) for a in algos}
    for chunk in chunks:
        for h in hashers.values():
            h.update(chunk)
    return {a: h.hexdigest() for a, h in hashers.items()}


def hash_file(path: Path, algos: list[str]) -> dict[str, str]:
    with path.open("rb") as fh:
        return hash_bytes_stream(iter(lambda: fh.read(1 << 20), b""), algos)


def generate_password(length: int = 20, symbols: bool = True, avoid_ambiguous: bool = False) -> str:
    classes = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        classes.append(SYMBOLS)
    if avoid_ambiguous:
        classes = ["".join(c for c in cls if c not in AMBIGUOUS) for cls in classes]
    if length < len(classes):
        raise ValueError(f"length must be at least {len(classes)}")
    alphabet = "".join(classes)
    # One char from each class guarantees complexity rules; shuffle so position is random.
    chars = [secrets.choice(cls) for cls in classes]
    chars += [secrets.choice(alphabet) for _ in range(length - len(classes))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def password_strength(password: str) -> dict:
    pool = 0
    pool += 26 if re.search(r"[a-z]", password) else 0
    pool += 26 if re.search(r"[A-Z]", password) else 0
    pool += 10 if re.search(r"\d", password) else 0
    pool += 33 if re.search(r"[^a-zA-Z0-9]", password) else 0
    entropy = len(password) * math.log2(pool) if pool else 0.0

    issues = []
    if password.lower() in COMMON_PASSWORDS:
        issues.append("is a very common password")
        entropy = min(entropy, 5)
    if len(password) < 12:
        issues.append("shorter than 12 characters")
    if re.search(r"(.)\1{2,}", password):
        issues.append("contains repeated characters")
        entropy *= 0.8
    lowered = password.lower()
    sequences = ("abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl")
    if any(seq[i:i + 4] in lowered for seq in sequences for i in range(len(seq) - 3)):
        issues.append("contains a keyboard/alphabet sequence")
        entropy *= 0.8
    if re.fullmatch(r"[A-Za-z]+\d{1,4}[^A-Za-z0-9]{0,2}", password):
        issues.append("predictable word + number pattern (e.g. Summer2024!)")
        entropy *= 0.6
    if pool and pool <= 26:
        issues.append("uses a single character class")

    rating = next(r for limit, r in [(100, "very strong"), (70, "strong"), (50, "moderate"), (30, "weak"), (-1, "very weak")] if entropy > limit)
    return {"entropy": round(entropy, 1), "rating": rating, "issues": issues}


def pwned_count(password: str) -> int:
    """Have I Been Pwned range query - only the first 5 SHA-1 hex chars leave this machine."""
    digest = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    body = http_get(f"https://api.pwnedpasswords.com/range/{prefix}").decode()
    for line in body.splitlines():
        candidate, _, count = line.partition(":")
        if hmac.compare_digest(candidate.strip(), suffix):
            return int(count)
    return 0


def encode(data: str, fmt: str) -> str:
    raw = data.encode()
    match fmt:
        case "b64":
            return base64.b64encode(raw).decode()
        case "b64url":
            return base64.urlsafe_b64encode(raw).decode().rstrip("=")
        case "hex":
            return raw.hex()
        case "url":
            return urllib.parse.quote(data, safe="")
        case "rot13":
            return codecs.encode(data, "rot13")
    raise ValueError(f"unknown format {fmt}")


def decode(data: str, fmt: str) -> str:
    match fmt:
        case "b64" | "b64url":
            padded = data.strip() + "=" * (-len(data.strip()) % 4)
            raw = base64.urlsafe_b64decode(padded.replace("+", "-").replace("/", "_"))
        case "hex":
            raw = bytes.fromhex(data.strip().removeprefix("0x"))
        case "url":
            return urllib.parse.unquote(data)
        case "rot13":
            return codecs.decode(data, "rot13")
        case _:
            raise ValueError(f"unknown format {fmt}")
    return raw.decode(errors="replace")


def decode_jwt(token: str) -> tuple[dict, dict]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("a JWT has three dot-separated parts")
    header, payload = (json.loads(decode(p, "b64url")) for p in parts[:2])
    return header, payload


def refang(text: str) -> str:
    return (text.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
            .replace("hxxp", "http").replace("hXXp", "http"))


def extract_iocs(text: str) -> dict[str, list[str]]:
    text = refang(text)
    found = {}
    for kind, pattern in IOC_PATTERNS.items():
        matches = list(dict.fromkeys(re.findall(pattern, text)))
        if matches:
            found[kind] = matches
    return found


# ---------- commands ----------

@app.command("hash")
def hash_cmd(
    target: Annotated[str, typer.Argument(help="File path, or text with --text")],
    text: Annotated[bool, typer.Option("--text", "-t", help="Hash the argument as a string")] = False,
    algo: Annotated[list[str], typer.Option("--algo", "-a", help=f"One of {', '.join(HASH_ALGOS)}")] = ["md5", "sha1", "sha256"],
    verify: Annotated[Optional[str], typer.Option("--verify", "-v", help="Expected hash to compare against")] = None,
):
    """Compute (and optionally verify) hashes of a file or string."""
    unknown = [a for a in algo if a not in HASH_ALGOS]
    if unknown:
        die(f"unsupported algorithm(s): {', '.join(unknown)}")
    if verify:
        # Make sure the algorithm matching the expected hash length is included.
        by_len = {len(hashlib.new(a).hexdigest()): a for a in ["md5", "sha1", "sha256", "sha512"]}
        if (extra := by_len.get(len(verify.strip()))) and extra not in algo:
            algo = [*algo, extra]
    if text:
        digests = hash_bytes_stream([target.encode()], algo)
    else:
        path = Path(target)
        if not path.is_file():
            die(f"file not found: {target} (use --text to hash a string)")
        digests = hash_file(path, algo)

    table = Table(show_header=False)
    table.add_column(style="bold cyan")
    table.add_column()
    for name, digest in digests.items():
        table.add_row(name, digest)
    console.print(table)
    if verify:
        expected = verify.strip().lower()
        matched = [a for a, d in digests.items() if hmac.compare_digest(d, expected)]
        if matched:
            console.print(f"[bold green]MATCH[/] ({matched[0]})")
        else:
            console.print("[bold red]NO MATCH[/]")
            raise typer.Exit(1)


@app.command()
def passgen(
    length: Annotated[int, typer.Option("--length", "-l")] = 20,
    count: Annotated[int, typer.Option("--count", "-n")] = 1,
    no_symbols: Annotated[bool, typer.Option("--no-symbols")] = False,
    no_ambiguous: Annotated[bool, typer.Option("--no-ambiguous", help="Avoid Il1O0o")] = False,
):
    """Generate cryptographically secure passwords."""
    try:
        for _ in range(count):
            console.print(generate_password(length, not no_symbols, no_ambiguous), markup=False, highlight=False)
    except ValueError as exc:
        die(str(exc))


@app.command()
def passcheck(
    password: Annotated[Optional[str], typer.Argument(help="Omit to be prompted (keeps it out of shell history)")] = None,
    pwned: Annotated[bool, typer.Option("--pwned", help="Check Have I Been Pwned (k-anonymity, password never sent)")] = False,
):
    """Estimate password strength and optionally check known breaches."""
    if password is None:
        password = typer.prompt("Password", hide_input=True)
    result = password_strength(password)
    colors = {"very weak": "red", "weak": "red", "moderate": "yellow", "strong": "green", "very strong": "green"}
    console.print(f"Strength: [bold {colors[result['rating']]}]{result['rating']}[/] (~{result['entropy']} bits)")
    for issue in result["issues"]:
        console.print(f"  [yellow]![/] {issue}")
    if pwned:
        try:
            count = pwned_count(password)
        except OSError as exc:
            die(f"HIBP lookup failed: {exc}")
        if count:
            console.print(f"[bold red]Found in {count:,} breaches - do not use it.[/]")
            raise typer.Exit(1)
        console.print("[green]Not found in known breaches.[/]")


@app.command("encode")
def encode_cmd(
    data: Annotated[str, typer.Argument(help="Text to encode")],
    fmt: Annotated[str, typer.Option("--format", "-f", help=f"One of {', '.join(CODECS)}")] = "b64",
):
    """Encode text (base64, hex, url, rot13)."""
    try:
        console.print(encode(data, fmt), markup=False, highlight=False)
    except ValueError as exc:
        die(str(exc))


@app.command("decode")
def decode_cmd(
    data: Annotated[str, typer.Argument(help="Text to decode")],
    fmt: Annotated[str, typer.Option("--format", "-f", help=f"One of {', '.join(CODECS)}")] = "b64",
):
    """Decode text (base64, hex, url, rot13)."""
    try:
        console.print(decode(data, fmt), markup=False, highlight=False)
    except (ValueError, TypeError) as exc:
        die(f"could not decode: {exc}")


@app.command()
def jwt(token: Annotated[str, typer.Argument(help="JSON Web Token")]):
    """Decode a JWT and show its claims (signature is NOT verified)."""
    try:
        header, payload = decode_jwt(token)
    except (ValueError, TypeError) as exc:
        die(f"invalid JWT: {exc}")
    console.print("[bold]Header[/]")
    console.print(JSON.from_data(header))
    console.print("[bold]Payload[/]")
    console.print(JSON.from_data(payload))
    now = datetime.now(timezone.utc).timestamp()
    for claim in ("iat", "nbf", "exp"):
        if isinstance(payload.get(claim), (int, float)):
            when = datetime.fromtimestamp(payload[claim], timezone.utc).isoformat()
            note = ""
            if claim == "exp":
                note = " [red](expired)[/]" if payload[claim] < now else " [green](valid)[/]"
            console.print(f"{claim}: {when}{note}")
    if header.get("alg", "").lower() == "none":
        console.print("[bold red]Warning: alg=none - token is unsigned[/]")
    console.print("[dim]Signature not verified.[/]")


@app.command()
def iocs(
    source: Annotated[str, typer.Argument(help="File to scan, or - for stdin")],
    as_json: Annotated[bool, typer.Option("--json", help="Output JSON")] = False,
):
    """Extract indicators of compromise (IPs, URLs, emails, hashes, CVEs) from text/logs."""
    if source == "-":
        text = sys.stdin.read()
    else:
        path = Path(source)
        if not path.is_file():
            die(f"file not found: {source}")
        text = path.read_text(errors="replace")
    found = extract_iocs(text)
    if as_json:
        print(json.dumps(found, indent=2))
        return
    if not found:
        console.print("No indicators found.")
        return
    for kind, values in found.items():
        table = Table(title=f"{kind} ({len(values)})", show_header=False, title_justify="left")
        table.add_column(overflow="fold")
        for value in values:
            table.add_row(value)
        console.print(table)
