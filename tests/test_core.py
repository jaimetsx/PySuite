import json

import pytest
from typer.testing import CliRunner

from pysuite.cli import app
from pysuite.commands import files, net, sec, web
from pysuite.utils import human_size, parse_ports, parse_size

runner = CliRunner()


def test_parse_ports():
    assert parse_ports("22, 80,443") == [22, 80, 443]
    assert parse_ports("10-12,11") == [10, 11, 12]
    assert parse_ports("5-3") == [3, 4, 5]
    with pytest.raises(ValueError):
        parse_ports("0,70000")


def test_sizes():
    assert human_size(512) == "512 B"
    assert human_size(1536) == "1.5 KB"
    assert parse_size("2K") == 2048
    assert parse_size("1.5MB") == int(1.5 * 1024**2)


def test_subnet_info():
    info = net.subnet_info("192.168.1.10/24")
    assert info["Network"] == "192.168.1.0"
    assert info["Broadcast"] == "192.168.1.255"
    assert info["Usable hosts"] == "254"
    assert info["Private"] == "yes"


def test_parse_whois():
    text = "Domain Name: EXAMPLE.COM\nName Server: A.IANA-SERVERS.NET\nName Server: a.iana-servers.net\nNoise: x"
    assert net.parse_whois(text) == [("Domain Name", "EXAMPLE.COM"), ("Name Server", "A.IANA-SERVERS.NET")]


def test_grade_headers():
    result = web.grade_headers({"strict-transport-security": "max-age=1", "Server": "nginx/1.2"})
    assert "Strict-Transport-Security" in result["present"]
    assert result["leaks"] == {"Server": "nginx/1.2"}
    assert result["grade"] == "F"
    full = {h: "x" for h in web.SECURITY_HEADERS}
    assert web.grade_headers(full)["grade"] == "A"


@pytest.mark.parametrize("fmt", sec.CODECS)
def test_codec_roundtrip(fmt):
    text = "héllo wörld/?&=+"
    assert sec.decode(sec.encode(text, fmt), fmt) == text


def test_hash_text():
    digests = sec.hash_bytes_stream([b"abc"], ["md5", "sha256"])
    assert digests["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert digests["sha256"].startswith("ba7816bf")


def test_generate_password():
    pw = sec.generate_password(24, symbols=True, avoid_ambiguous=True)
    assert len(pw) == 24
    assert not set(pw) & sec.AMBIGUOUS
    assert any(c in sec.SYMBOLS for c in pw)
    assert sec.generate_password(10, symbols=False).isalnum()


def test_password_strength():
    assert sec.password_strength("password")["rating"] == "very weak"
    assert sec.password_strength("Summer2024!")["rating"] in ("weak", "very weak")
    strong = sec.password_strength("r7#Kq!v2Lp@9xZ$m")
    assert strong["rating"] in ("strong", "very strong")
    assert not strong["issues"]


def test_decode_jwt():
    token = ".".join([sec.encode('{"alg":"HS256"}', "b64url"), sec.encode('{"sub":"42"}', "b64url"), "sig"])
    header, payload = sec.decode_jwt(token)
    assert header == {"alg": "HS256"}
    assert payload == {"sub": "42"}


def test_extract_iocs():
    text = "beacon to hxxp://evil[.]com/x from 10.0.0.5 and 10.0.0.5, mail bad@evil.com, CVE-2024-3094 " + "a" * 64
    found = sec.extract_iocs(text)
    assert found["ipv4"] == ["10.0.0.5"]
    assert found["url"] == ["http://evil.com/x"]
    assert found["email"] == ["bad@evil.com"]
    assert found["cve"] == ["CVE-2024-3094"]
    assert len(found["sha256"]) == 1 and "md5" not in found


def test_duplicates_and_baseline(tmp_path):
    (tmp_path / "a.txt").write_text("same content")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.txt").write_text("same content")
    (tmp_path / "c.txt").write_text("different!!!")
    groups = files.find_duplicates(tmp_path)
    assert len(groups) == 1 and {p.name for p in groups[0]} == {"a.txt", "b.txt"}

    before = files.build_baseline(tmp_path)["files"]
    (tmp_path / "a.txt").write_text("tampered")
    (tmp_path / "c.txt").unlink()
    (tmp_path / "new.txt").write_text("x")
    diff = files.compare_baseline(before, files.build_baseline(tmp_path)["files"])
    assert diff == {"added": ["new.txt"], "removed": ["c.txt"], "modified": ["a.txt"]}


def test_entropy():
    assert files.shannon_entropy(b"aaaa") == 0
    assert files.shannon_entropy(bytes(range(256))) == pytest.approx(8.0)


def test_cli_smoke(tmp_path):
    assert runner.invoke(app, ["--version"]).exit_code == 0
    result = runner.invoke(app, ["sec", "hash", "abc", "--text", "--verify", "900150983cd24fb0d6963f7d28e17f72"])
    assert result.exit_code == 0 and "MATCH" in result.output
    assert runner.invoke(app, ["sec", "hash", "abc", "--text", "--verify", "0" * 32]).exit_code == 1

    (tmp_path / "f.txt").write_text("data")
    out = tmp_path / "base.json"
    assert runner.invoke(app, ["files", "baseline", str(tmp_path), "-o", str(out)]).exit_code == 0
    assert "f.txt" in json.loads(out.read_text())["files"]
    assert runner.invoke(app, ["files", "verify", str(out)]).exit_code == 1  # base.json itself was added
    assert runner.invoke(app, ["net", "subnet", "10.0.0.0/30"]).exit_code == 0
