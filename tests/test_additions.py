import os
import sys

import pytest
from typer.testing import CliRunner

from pysuite.cli import app
from pysuite.commands import files, logs, net

runner = CliRunner()

AUTH_LOG = """\
Sep 30 10:00:01 srv sshd[1]: Failed password for root from 203.0.113.9 port 5000 ssh2
Sep 30 10:00:02 srv sshd[1]: Failed password for invalid user admin from 203.0.113.9 port 5001 ssh2
Sep 30 10:00:03 srv sshd[1]: Invalid user oracle from 198.51.100.7 port 4000
Sep 30 10:00:04 srv sshd[1]: Failed password for root from 203.0.113.9 port 5002 ssh2
Sep 30 10:00:05 srv sshd[1]: Accepted password for root from 203.0.113.9 port 5003 ssh2
Sep 30 10:00:06 srv sshd[1]: Accepted publickey for jaime from 192.0.2.1 port 6000 ssh2
Sep 30 10:00:07 srv CRON[2]: pam_unix(cron:session): session opened for user root
"""

ACCESS_LOG = """\
192.0.2.1 - - [30/Sep/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0"
192.0.2.1 - - [30/Sep/2026:10:00:01 +0000] "GET /about HTTP/1.1" 200 256 "-" "Mozilla/5.0"
203.0.113.9 - - [30/Sep/2026:10:00:02 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/8"
203.0.113.9 - - [30/Sep/2026:10:00:03 +0000] "GET /item?id=1%20union%20select%201 HTTP/1.1" 500 0 "-" "sqlmap/1.8"
203.0.113.9 - - [30/Sep/2026:10:00:04 +0000] "GET /../../etc/passwd HTTP/1.1" 400 0 "-" "Mozilla/5.0"
not a log line
"""


def test_analyze_auth():
    result = logs.analyze_auth(AUTH_LOG.splitlines())
    assert result["failed_ip"] == {"203.0.113.9": 3, "198.51.100.7": 1}
    assert result["failed_user"]["root"] == 2
    assert ("root", "203.0.113.9", "password") in result["accepted"]
    assert len(result["accepted"]) == 2


def test_analyze_access():
    result = logs.analyze_access(ACCESS_LOG.splitlines())
    assert result["parsed"] == 5
    assert result["ips"]["203.0.113.9"] == 3
    assert result["statuses"]["200"] == 2
    hits = result["hits"]
    assert "sensitive file probe" in hits
    assert "sql injection" in hits
    assert "path traversal" in hits
    assert "scanner user-agent" in hits
    assert all(ip == "203.0.113.9" for kind in hits.values() for ip, _ in kind)


def test_logs_cli(tmp_path):
    auth_file = tmp_path / "auth.log"
    auth_file.write_text(AUTH_LOG)
    result = runner.invoke(app, ["logs", "auth", str(auth_file), "--threshold", "3"])
    assert result.exit_code == 0
    assert "prior failures" in result.output
    access_file = tmp_path / "access.log"
    access_file.write_text(ACCESS_LOG)
    result = runner.invoke(app, ["logs", "access", str(access_file)])
    assert result.exit_code == 0 and "sql injection" in result.output


@pytest.mark.parametrize("records,state", [
    ([], "fail"),
    (["v=spf1 include:_spf.google.com -all"], "ok"),
    (["v=spf1 include:_spf.google.com ~all"], "warn"),
    (["v=spf1 +all"], "fail"),
    (["v=spf1 a all"], "fail"),
    (["v=spf1 -all", "v=spf1 ~all"], "fail"),
    (["google-site-verification=abc"], "fail"),
])
def test_assess_spf(records, state):
    assert net.assess_spf(records)[0] == state


@pytest.mark.parametrize("record,state", [
    ("v=DMARC1; p=reject; rua=mailto:x@y.z", "ok"),
    ("v=DMARC1; p=quarantine", "warn"),
    ("v=DMARC1; p=none", "fail"),
])
def test_assess_dmarc(record, state):
    assert net.assess_dmarc([record])[0] == state
    assert net.assess_dmarc([])[0] == "fail"


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_risky_permissions(tmp_path):
    safe = tmp_path / "safe"
    safe.write_text("x")
    safe.chmod(0o644)
    writable = tmp_path / "writable"
    writable.write_text("x")
    writable.chmod(0o666)
    kinds = {(k, p.name) for k, p in files.risky_permissions(tmp_path)}
    assert ("world-writable", "writable") in kinds
    assert not any(name == "safe" for _, name in kinds)


@pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows only")
def test_perms_rejected_on_windows(tmp_path):
    assert runner.invoke(app, ["files", "perms", str(tmp_path)]).exit_code == 1
