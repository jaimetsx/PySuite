import ipaddress
from pathlib import Path
from urllib.parse import urlparse

def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
    
def is_valid_network(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False
    
def is_valid_url(value: str) -> bool:
    parsed = urlparse(value)
    return bool(parsed.scheme and parsed.netloc)

def file_exists(path: str) -> bool:
    return Path(path).is_file()