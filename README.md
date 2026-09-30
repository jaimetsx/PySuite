# PySuite

A cybersecurity and sysadmin toolkit for the terminal. One command, `pysuite`, five tool groups, no GUI needed.

```
pysuite net    Network recon: port scan, ping sweep, DNS, WHOIS, subnets
pysuite web    Web auditing: security headers, TLS certificates, uptime
pysuite sec    Security: hashing, passwords, encoding, JWT, IOC extraction
pysuite sys    System: overview, processes, listening ports, users
pysuite files  Files: large files, duplicates, integrity baselines, entropy, permissions
pysuite logs   Logs: SSH auth and web access log analysis
```

## Install

Requires Python 3.10+.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
pysuite --help
```

On Windows, if PowerShell refuses to run `Activate.ps1` because script execution is disabled, either run
`Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` once, or skip activation and call
`.venv\Scripts\pysuite.exe` directly.

You can also run it without installing: `python -m pysuite --help`.

## Commands

### `net`
| Command | What it does |
|---|---|
| `pysuite net scan HOST [-p 22,80,8000-8100] [-b]` | Multithreaded TCP connect scan, with optional banner grabbing |
| `pysuite net sweep 192.168.1.0/24` | Find live hosts with ICMP ping and reverse DNS |
| `pysuite net dns example.com [-t MX -t TXT] [--server 1.1.1.1]` | DNS records, or PTR when you pass an IP |
| `pysuite net whois github.com [--raw]` | WHOIS lookup that follows registry and registrar referrals |
| `pysuite net subnet 10.0.0.0/22` | Subnet calculator |
| `pysuite net myip` | Public IP, ISP and geolocation |
| `pysuite net check HOST PORT [-c 4]` | TCP reachability and connect latency, like `Test-NetConnection` |
| `pysuite net mailsec example.com` | Audits email anti-spoofing: MX, SPF, DMARC and MTA-STS |

### `web`
| Command | What it does |
|---|---|
| `pysuite web headers example.com [--full]` | Grades security headers (HSTS, CSP, ...) and flags version leaks |
| `pysuite web ssl example.com[:port] [--warn-days 30]` | Certificate issuer, SANs, expiry, TLS version and cipher |
| `pysuite web status URL [URL...]` | HTTP status and latency for each URL |

### `sec`
| Command | What it does |
|---|---|
| `pysuite sec hash FILE [-a sha512] [--verify HASH]` | Hashes a file and optionally verifies a download against a published hash |
| `pysuite sec hash "text" --text` | Hashes a string |
| `pysuite sec passgen [-l 24] [-n 5] [--no-symbols] [--no-ambiguous]` | Generates secure passwords |
| `pysuite sec passcheck [--pwned]` | Estimates strength and checks Have I Been Pwned (k-anonymity) |
| `pysuite sec encode/decode TEXT -f b64\|b64url\|hex\|url\|rot13` | Encoders and decoders |
| `pysuite sec jwt TOKEN` | Decodes JWT claims, checks expiry and flags `alg=none` |
| `pysuite sec iocs FILE\|- [--json]` | Pulls IPs, URLs, emails, hashes and CVEs out of logs (refangs `hxxp` and `[.]`) |

### `sys`
| Command | What it does |
|---|---|
| `pysuite sys info` | OS, uptime, CPU, memory, disks and interfaces |
| `pysuite sys procs [-s mem] [-n 20]` | Top processes by CPU or memory |
| `pysuite sys listening [--udp]` | Listening ports and the processes that own them |
| `pysuite sys users` | Logged-in sessions |
| `pysuite sys conns [--public] [--resolve]` | Established connections per process; public IPs highlighted |
| `pysuite sys startup` | Autorun entries: Registry Run keys and Startup folders, or cron/systemd/launchd |
| `pysuite sys firewall` | Whether the host firewall is on (Windows, ufw, firewalld, nftables, macOS) |

### `files`
| Command | What it does |
|---|---|
| `pysuite files large PATH [-n 20]` | Largest files |
| `pysuite files dupes PATH [--min-size 1M]` | Duplicate files, compared by SHA-256 |
| `pysuite files baseline PATH -o base.json` | Records file hashes (file integrity monitoring) |
| `pysuite files verify base.json` | Reports added, removed and modified files; exits 1 on changes |
| `pysuite files entropy PATH [--threshold 7.5]` | Flags high-entropy files (encrypted, packed or ransomware output) |
| `pysuite files perms PATH` | World-writable files and SUID/SGID binaries (Linux/macOS) |

### `logs`
| Command | What it does |
|---|---|
| `pysuite logs auth /var/log/auth.log [--threshold 10]` | Failed SSH logins by IP and user; flags successful logins from IPs with many failures |
| `pysuite logs access access.log` | Top clients, status codes and paths, plus attack signatures (SQLi, XSS, traversal, `.env` probes, scanners) |

## Scripting

When a check fails, the command exits with code 1 so you can use it in cron jobs or CI:
- `web ssl` when the certificate expires within `--warn-days`
- `web status` when any URL is down
- `files verify` when files changed
- `sec hash --verify` on a mismatch
- `sec passcheck --pwned` when the password appears in a breach
- `net check` when every attempt fails
- `net mailsec` when SPF or DMARC fails
- `sys firewall` when any profile is off
- `files perms` when world-writable files are found

```bash
pysuite web ssl mysite.com --warn-days 14 || notify "cert expiring"
```

## Development

```bash
pytest
```

## Legal

Only scan and probe systems you own or are explicitly authorized to test.
