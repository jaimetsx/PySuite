# PySuite

PySuite is a terminal-based toolkit for cybersecurity, networking, and sysadmin workflows.

It provides a menu-driven interface that groups practical utilities into a single command-line application, making common inspection and analysis tasks faster and easier from the terminal.

## Features

PySuite currently includes:

- File hash calculation
- DNS lookup
- Reverse DNS lookup
- HTTP inspection
- Security headers check
- IP and subnet inspection
- Port checking
- Whois lookup
- Encoding and decoding tools
- File inspection with optional content preview

## Why PySuite

PySuite is designed to avoid the usual problem of having dozens of isolated scripts with different usage patterns.

Instead of maintaining unrelated one-off tools, PySuite provides:

- A single entry point
- A consistent interactive menu
- Reusable modules
- Clear terminal output with Rich
- A structure that is easy to extend over time

This makes it useful both as a personal toolkit and as a portfolio project.

## Installation

### Requirements

- Python 3.10 or newer
- Linux, macOS, or Windows
- Internet connection for DNS, HTTP, and Whois-related tools

### Clone the repository

```bash
git clone https://github.com/jaimetsx/pysuite.git
cd pysuite
```

### Create a virtual environment

```bash
python -m venv .venv
```

#### Linux / macOS

```bash
source .venv/bin/activate
```

#### Windows

```bash
.venv\Scripts\activate(.ps1|.bat)
```

### Install dependencies

```bash
pip install -r requirements.txt
```

### Run the application

```bash
python main.py
```

## Package installation

You can also install PySuite in editable mode and expose it as a CLI command:

```bash
pip install -e .
pysuite
```

## Usage

When you start PySuite, you will see an interactive menu with the available tools.

Example flow:

```text
1. File Hash Checker
2. DNS Lookup
3. HTTP Inspector
4. Security Headers Check
5. IP / Subnet Tools
6. Port Checker
7. Whois Lookup
8. Encoding / Decoding Tools
9. File Inspector
0. Exit
```

Each module asks for the required input and displays results in a structured terminal view.

## Project Structure

```text
pysuite/
├── pyproject.toml
├── requirements.txt
├── README.md
├── main.py
├── core/
│   ├── __init__.py
│   ├── console.py
│   ├── menu.py
│   ├── utils.py
│   ├── validators.py
│   └── formatters.py
└── modules/
    ├── __init__.py
    ├── hash_tools.py
    ├── dns_tools.py
    ├── http_tools.py
    ├── security_headers.py
    ├── ip_tools.py
    ├── port_tools.py
    ├── whois_tools.py
    ├── encoding_tools.py
    └── file_tools.py
```

## Included Tools

| Tool | Description |
|------|-------------|
| File Hash Checker | Calculates MD5, SHA1, SHA256, and SHA512 hashes for files. |
| DNS Lookup | Resolves common DNS records such as A, AAAA, MX, NS, TXT, and CNAME. |
| Reverse DNS Lookup | Resolves PTR records from IP addresses. |
| HTTP Inspector | Retrieves basic HTTP response details such as status code, final URL, and headers. |
| Security Headers Check | Checks common security-related HTTP headers. |
| IP / Subnet Tools | Displays information about IP addresses and networks. |
| Port Checker | Tests whether selected TCP ports are open on a target host. |
| Whois Lookup | Retrieves domain registration information. |
| Encoding / Decoding Tools | Supports Base64 and URL encode/decode operations. |
| File Inspector | Displays file metadata and can optionally preview file contents. |

## Notes

- PySuite uses stable dependency versions pinned in `requirements.txt`.
- The project avoids deprecated patterns such as `os.system(...)`.
- Some tools depend on network access and may fail if the target blocks requests or rate limits queries.
- File content preview is intended for text files and uses a safe truncated preview.

## Roadmap

Planned improvements:

- JSON export for results
- Logging support
- Better category submenus
- JWT inspector
- Entropy checker
- Certificate inspection
- Simple log parser
- Plugin-style module loading

## Contributing

Contributions, refactors, and ideas for new practical modules are welcome.

If you want to improve the codebase, a good place to start is:

- Adding a new module
- Improving validation
- Extending export options
- Refining the UI and menu flow

## License

This project is licensed under the MIT License.