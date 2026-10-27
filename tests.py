#!/usr/bin/env python3
"""Asserts for parsers, scanners, JSON output and cache handling.

Run: python3 tests.py
No test executes a GTFOBins snippet, changes system security settings or needs
root/network access.
"""

import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import shlex
import stat
import tempfile
import urllib.error
import unittest.mock as mock

loader = importlib.machinery.SourceFileLoader("esc", "escabin")
spec = importlib.util.spec_from_loader("esc", loader)
esc = importlib.util.module_from_spec(spec)
loader.exec_module(esc)


# --- helpers ---------------------------------------------------------------

def temp_file(directory, name, mode=0o755):
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("test\n")
    os.chmod(path, mode)
    return path


def api(executables=None):
    return {
        "executables": executables or {"vim": {"functions": {}}},
        "functions": {},
        "contexts": {},
    }


def db_with(*names):
    functions = {}
    for name in names:
        functions[name] = {"functions": {"shell": [{
            "code": name + " -c test",
            "contexts": {
                "sudo": None,
                "suid": None,
                "capabilities": {"list": ["CAP_SETUID"]},
            },
        }]}}
    return esc.DB(api(functions))


def empty_sudo():
    return {"ok": True, "rules": [], "error": None, "status": "complete"}


def empty_privileged():
    return {"suid": set(), "sgid": set(), "status": "complete",
            "reason": None, "complete": True}


def empty_caps():
    return {"caps": {}, "status": "complete", "reason": None, "checked": True}


def run_check(db, sudo=None, privileged=None, caps=None, fail_on=None,
              as_json=True, platform="darwin"):
    sudo = empty_sudo() if sudo is None else sudo
    privileged = empty_privileged() if privileged is None else privileged
    caps = empty_caps() if caps is None else caps
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(esc.sys, "platform", platform), \
            mock.patch.object(esc, "scan_sudo", return_value=sudo), \
            mock.patch.object(esc, "scan_privileged", return_value=privileged), \
            mock.patch.object(esc, "scan_caps", return_value=caps), \
            contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = esc.cmd_check(db, False, as_json, fail_on=fail_on)
    return code, out.getvalue(), err.getvalue()


def sudo_rule(path, args="", runas="root", nopasswd=False, **extra):
    rule = {
        "all": False,
        "path": path,
        "args": args,
        "runas": runas,
        "nopasswd": nopasswd,
        "raw": f"({runas}) {'NOPASSWD: ' if nopasswd else ''}{path} {args}".strip(),
        "spec": f"{'NOPASSWD: ' if nopasswd else ''}{path} {args}".strip(),
        "permitted": f"{path} {args}".strip(),
        "manual": False,
    }
    rule.update(extra)
    return rule


def write_cached(path, payload):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)
    return open(path, "rb").read()


# --- sudo -l parsing -------------------------------------------------------
SAMPLE = """Matching Defaults entries for bob on host:
    env_reset, mail_badpass

User bob may run the following commands on host:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/vim, /usr/bin/systemctl restart nginx
    (root) /usr/bin/find, (ALL) NOPASSWD: /bin/cat
"""
rules = esc.parse_sudo(SAMPLE)
assert len(rules) == 5, rules
assert rules[0]["all"] and not rules[0]["nopasswd"]
assert rules[1]["path"] == "/usr/bin/vim" and rules[1]["nopasswd"]
assert rules[2]["path"] == "/usr/bin/systemctl" and rules[2]["nopasswd"]
assert rules[2]["args"] == "restart nginx"
assert rules[3]["path"] == "/usr/bin/find" and not rules[3]["nopasswd"]
assert rules[4]["path"] == "/bin/cat" and rules[4]["nopasswd"] and rules[4]["runas"] == "ALL"
assert rules[1]["spec"] == "NOPASSWD: /usr/bin/vim"
assert rules[1]["permitted"] == "/usr/bin/vim"
assert rules[1]["raw"].endswith("/usr/bin/systemctl restart nginx")

MORE = """
User alice may run the following commands on host:
\t(root) NOPASSWD: /bin/ls, /bin/cat, PASSWD: /bin/echo, /bin/tee
    (root, www-data : www-data) /usr/bin/id
    (ALL) /usr/bin/foo a\\,b
    (root) /usr/bin/systemctl  restart   nginx
    (root) /usr/bin/* wildcard
    (root) /opt/scripts/
    (root) sudoedit /etc/hosts
    (root) ALL, !/bin/su
    (:dialer) /usr/bin/tip
"""
more = esc.parse_sudo(MORE)
assert [r["path"] for r in more if not r["all"] and not r["manual"]][:4] == [
    "/bin/ls", "/bin/cat", "/bin/echo", "/bin/tee"], more
assert all(r["nopasswd"] for r in more[:2])
assert not more[2]["nopasswd"] and not more[3]["nopasswd"]
assert more[4]["path"] == "/usr/bin/id" and more[4]["runas"] == "root, www-data : www-data"
assert more[5]["path"] == "/usr/bin/foo" and more[5]["args"] == "a\\,b"
assert not more[5]["manual"] and more[5]["runas"] == "ALL"
assert more[6]["args"] == "restart   nginx"
assert more[7]["manual"] and more[7]["reason"] == "wildcard command path"
assert more[8]["manual"] and more[8]["reason"] == "directory command path"
assert more[9]["manual"] and more[9]["path"] is None
assert more[10]["all"] and len(more) == 12, more  # !/bin/su is a denial
assert more[11]["runas"] == ":dialer" and not more[11]["manual"]

assert esc.runas_users("root, www-data : www-data") == ["root", "www-data"]
assert esc.runas_user({"runas": "www-data : www-data"}) == "www-data"
assert esc.runas_user({}) == "root"
assert esc.is_root_runas("ALL") and esc.is_root_runas("root")
assert esc.is_root_runas("root, www-data") and not esc.is_root_runas("www-data")
assert not esc.is_root_runas(":dialer")

prefix, root, manual = esc.sudo_prefix({"runas": "root", "path": "/bin/ls"})
assert prefix == "sudo " and root and not manual
prefix, root, manual = esc.sudo_prefix({"runas": "www-data", "path": "/bin/ls"})
assert prefix == "sudo -u www-data " and not root and not manual
prefix, root, manual = esc.sudo_prefix({"runas": ":dialer", "path": "/bin/ls"})
assert prefix == "" and not root and manual


# --- command rewriting -----------------------------------------------------
rw = esc.rewrite_commands
assert rw("echo x | at now", "at", "/usr/bin/at", "sudo ") == \
    "echo x | sudo /usr/bin/at now"
assert rw("echo DATA >/f\nmv /f /out", "mv", "/opt/bin/mv") == \
    "echo DATA >/f\n/opt/bin/mv /f /out"
assert rw("PAGER='x y' git -p help", "git", "/usr/bin/git", "sudo ") == \
    "sudo PAGER='x y' /usr/bin/git -p help"
assert rw("echo 'find | x'", "find", "/usr/bin/find", "sudo ") == "echo 'find | x'"
assert rw("sudo /bin/sh", "sudo", "/usr/bin/sudo", "sudo ") == "sudo /usr/bin/sudo /bin/sh"
assert rw("if true; then find .; fi", "find", "/usr/bin/find") == \
    "if true; then /usr/bin/find .; fi"
assert rw("echo $(find .)", "find", "/usr/bin/find") == \
    "echo $(/usr/bin/find .)"
assert rw("find . | xargs find /x", "find", "/usr/bin/find") == \
    "/usr/bin/find . | xargs find /x"
assert rw("find .", "find", "/opt/my dir/find") == \
    "'/opt/my dir/find' ."
assert rw("id", "id", "/usr/bin/id", "sudo -u www-data ") == \
    "sudo -u www-data /usr/bin/id"


# --- data lookup and validation -------------------------------------------
data = {
    "executables": {
        "apt-get": {"functions": {"shell": []}},
        "apt": {"alias": "apt-get"},
        "python": {"functions": {}},
        "gcc": {"functions": {}},
    },
    "functions": {},
    "contexts": {},
}
db = esc.DB(data)
assert db.canon("apt") == "apt-get"
assert db.canon("/usr/bin/python3.11") == "python"
assert db.canon("gcc-12") == "gcc"
assert db.canon("no-such-binary") is None

esc.validate_api(api())
for bad in (
    [],
    {"executables": {}, "functions": {}, "contexts": {}},
    {"executables": [], "functions": {}, "contexts": {}},
    {"executables": {"x": []}, "functions": {}, "contexts": {}},
    {"executables": {"x": {"alias": 1}}, "functions": {}, "contexts": {}},
    {"executables": {"x": {"comment": 1}}, "functions": {}, "contexts": {}},
    {"executables": {"x": {"functions": {"shell": [{"code": 1}]}}},
     "functions": {}, "contexts": {}},
    {"executables": {"x": {"functions": {"shell": [{"contexts": []}]}}},
     "functions": {}, "contexts": {}},
    {"executables": {"x": {"functions": {"shell": [{
        "contexts": {"capabilities": {"list": [1]}}}]}}},
     "functions": {}, "contexts": {}},
    {"executables": {"x": {"functions": {}}}, "functions": [], "contexts": {}},
):
    try:
        esc.validate_api(bad)
        raise AssertionError("malformed API accepted: %r" % (bad,))
    except ValueError:
        pass


# --- capability gating -----------------------------------------------------
cap_data = {
    "executables": {"python": {"functions": {"shell": [{
        "code": "python -c x",
        "contexts": {"capabilities": {"list": ["CAP_SETUID"]}},
    }]}}},
    "functions": {},
    "contexts": {},
}
cap_db = esc.DB(cap_data)
key, funcs = esc.matching(cap_db, "/usr/bin/python3", "capabilities", {"cap_setuid"})
assert key == "python" and [f for f, _ in funcs] == ["shell"]
assert esc.matching(cap_db, "/usr/bin/python3", "capabilities", {"cap_net_raw"})[1] == []


# --- root and writable SUID ------------------------------------------------
assert not esc.writable_by_us(0o4755, 0, True)   # root: access() is always true
assert esc.writable_by_us(0o4777, 0, False)
assert esc.writable_by_us(0o4755, 1000, True)
assert not esc.writable_by_us(0o4755, 1000, False)
assert not esc.writable_by_us(0o4770, 1000, False)  # group-writable, not a member


# --- text cleanup and terminal safety -------------------------------------
assert esc.clean_md("see [cron](https://x)") == "see cron (https://x)"
assert esc.safe_text("a\x1b[31mb") == "a\\x1b[31mb"
assert esc.safe_text("a\u202eb") == "a\\u202eb"
assert esc.safe_text("a\udcffb") == "a\\udcffb"


# --- getcap parsing and scanning ------------------------------------------
GETCAP = """/usr/bin/ping cap_net_raw=ep
/usr/bin/python3 cap_setuid,cap_setgid=ep
not a cap line
/usr/bin/empty =
/usr/bin/plus cap_net_raw+ep
"""
parsed = esc.parse_getcap(GETCAP)
assert parsed["/usr/bin/ping"] == {"cap_net_raw"}
assert parsed["/usr/bin/python3"] == {"cap_setuid", "cap_setgid"}
assert "/usr/bin/plus" not in parsed
assert "/usr/bin/empty" not in parsed

with mock.patch.object(esc, "system_tool", return_value=None):
    caps = esc.scan_caps()
assert caps["status"] == "unavailable" and not caps["caps"] and not caps["checked"]

with mock.patch.object(esc, "system_tool", return_value="/usr/bin/getcap"), \
        mock.patch.object(esc.subprocess, "run", return_value=esc.subprocess.CompletedProcess(
            [], 0, stdout=GETCAP, stderr="")):
    caps = esc.scan_caps()
assert caps["status"] == "complete" and caps["checked"] and len(caps["caps"]) == 2

timeout = esc.subprocess.TimeoutExpired([], 1, output=GETCAP)
with mock.patch.object(esc, "system_tool", return_value="/usr/bin/getcap"), \
        mock.patch.object(esc.subprocess, "run", side_effect=timeout):
    caps = esc.scan_caps()
assert caps["status"] == "partial" and caps["caps"] and not caps["checked"]

with mock.patch.object(esc, "system_tool", return_value="/usr/bin/getcap"), \
        mock.patch.object(esc.subprocess, "run", side_effect=OSError("nope")):
    caps = esc.scan_caps()
assert caps["status"] == "failed" and not caps["checked"]


# --- sudo scanning ---------------------------------------------------------
with mock.patch.object(esc, "system_tool", return_value="/usr/bin/sudo"), \
        mock.patch.object(esc.subprocess, "run", return_value=esc.subprocess.CompletedProcess(
            [], 0, stdout=SAMPLE, stderr="")):
    sudo = esc.scan_sudo()
assert sudo["ok"] and sudo["status"] == "complete" and len(sudo["rules"]) == 5

with mock.patch.object(esc, "system_tool", return_value="/usr/bin/sudo"), \
        mock.patch.object(esc.subprocess, "run", return_value=esc.subprocess.CompletedProcess(
            [], 1, stdout="", stderr="sudo: a password is required")):
    sudo = esc.scan_sudo()
assert not sudo["ok"] and sudo["status"] == "skipped"
assert "password" in sudo["error"]

with mock.patch.object(esc, "system_tool", return_value=None):
    sudo = esc.scan_sudo()
assert sudo["status"] == "unavailable" and "not installed" in sudo["error"]

with mock.patch.object(esc, "system_tool", return_value="/usr/bin/sudo"), \
        mock.patch.object(esc.subprocess, "run",
                          side_effect=esc.subprocess.TimeoutExpired([], 1)):
    sudo = esc.scan_sudo()
assert sudo["status"] == "failed" and "timed out" in sudo["error"]


# --- SUID/SGID scanning ----------------------------------------------------
with tempfile.TemporaryDirectory() as tmp:
    suid = temp_file(tmp, "suidfile", 0o4755)
    sgid = temp_file(tmp, "sgidfile", 0o2755)
    plain = temp_file(tmp, "plain", 0o644)
    output = "\0".join([suid, sgid, suid, plain]) + "\0"
    with mock.patch.object(esc, "fast_roots", return_value=[tmp]), \
            mock.patch.object(esc, "system_tool", return_value="/usr/bin/find"), \
            mock.patch.object(esc.subprocess, "run", return_value=esc.subprocess.CompletedProcess(
                [], 0, stdout=output, stderr="")):
        found = esc.scan_privileged(False)
    assert found["status"] == "complete" and found["complete"], found
    assert found["suid"] == {suid} and found["sgid"] == {sgid}, found

    timeout = esc.subprocess.TimeoutExpired([], 1, output=suid + "\0")
    with mock.patch.object(esc, "fast_roots", return_value=[tmp]), \
            mock.patch.object(esc, "system_tool", return_value="/usr/bin/find"), \
            mock.patch.object(esc.subprocess, "run", side_effect=timeout):
        found = esc.scan_privileged(False)
    assert found["status"] == "partial" and found["suid"] == {suid}
    assert "timed out" in found["reason"] and not found["complete"]

    with mock.patch.object(esc, "fast_roots", return_value=[tmp]), \
            mock.patch.object(esc, "system_tool", return_value="/usr/bin/find"), \
            mock.patch.object(esc.subprocess, "run", return_value=esc.subprocess.CompletedProcess(
                [], 1, stdout=suid + "\0", stderr="find: Permission denied")):
        found = esc.scan_privileged(False)
    assert found["status"] == "partial" and "Permission denied" in found["reason"]

    with mock.patch.object(esc, "fast_roots", return_value=[tmp]), \
            mock.patch.object(esc, "system_tool", return_value="/usr/bin/find"), \
            mock.patch.object(esc.subprocess, "run", return_value=esc.subprocess.CompletedProcess(
                [], 0, stdout="", stderr="")):
        found = esc.scan_privileged(False)
    assert found["status"] == "complete" and not found["suid"] and not found["sgid"]

    with mock.patch.object(esc, "fast_roots", return_value=[tmp]), \
            mock.patch.object(esc, "system_tool", return_value="/usr/bin/find"), \
            mock.patch.object(esc.subprocess, "run", return_value=esc.subprocess.CompletedProcess(
                [], 1, stdout="", stderr="find: Permission denied")):
        found = esc.scan_privileged(False)
    assert found["status"] == "failed" and not found["complete"]

with mock.patch.object(esc, "system_tool", return_value=None):
    found = esc.scan_privileged(False)
assert found["status"] == "unavailable" and "find not installed" in found["reason"]

with tempfile.TemporaryDirectory() as tmp:
    missing = os.path.join(tmp, "missing")
    with mock.patch.object(esc, "fast_roots", return_value=[missing]), \
            mock.patch.object(esc, "system_tool", return_value="/usr/bin/find"):
        found = esc.scan_privileged(False)
    assert found["status"] == "unavailable" and "no scan roots" in found["reason"]

with tempfile.TemporaryDirectory() as tmp:
    real = temp_file(tmp, "real", 0o4755)
    link = os.path.join(tmp, "link")
    os.symlink(real, link)
    assert esc._dedupe_paths([link, real]) == {real}

with mock.patch.object(esc.sys, "platform", "darwin"):
    assert "/opt/homebrew/bin" in esc.fast_roots()
with mock.patch.object(esc.sys, "platform", "linux"):
    assert "/snap/bin" in esc.fast_roots()

with mock.patch.object(esc, "system_tool", return_value="/usr/bin/find"), \
        mock.patch.object(esc.subprocess, "run", return_value=esc.subprocess.CompletedProcess(
            [], 0, stdout="", stderr="")) as find_run:
    esc.scan_privileged(True)
args = find_run.call_args[0][0]
assert "/" in args and "-print0" in args and "-perm" in args and "-4000" in args
assert "-2000" in args and "-path" in args

mounts = tempfile.NamedTemporaryFile("w", delete=False)
try:
    mounts.write("server:/export /mnt/nfs nfs rw 0 0\n"
                 "proc /proc proc rw 0 0\n"
                 "sshfs /home/u/remote fuse.sshfs rw 0 0\n")
    mounts.close()
    assert esc.network_mounts(mounts.name) == ["/mnt/nfs", "/home/u/remote"]
finally:
    os.unlink(mounts.name)


# --- dataset download and cache preservation ------------------------------
class FakeResponse:
    def __init__(self, payload, length=None):
        self.payload = payload
        self.pos = 0
        self.headers = {} if length is None else {"Content-Length": str(length)}

    def read(self, size=-1):
        if size is None or size < 0:
            size = len(self.payload) - self.pos
        chunk = self.payload[self.pos:self.pos + size]
        self.pos += len(chunk)
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def fake_urlopen(payload, length=None):
    return mock.Mock(return_value=FakeResponse(payload, length))


valid_raw = json.dumps(api()).encode("utf-8")
with tempfile.TemporaryDirectory() as tmp:
    target = os.path.join(tmp, "api.json")
    with mock.patch.object(esc.urllib.request, "urlopen", fake_urlopen(valid_raw)):
        size, digest = esc.download(path=target)
    assert size == len(valid_raw) and len(digest) == 64
    assert open(target, "rb").read() == valid_raw
    assert esc.load_api(path=target)["executables"]

    before = open(target, "rb").read()
    with mock.patch.object(esc.urllib.request, "urlopen",
                           fake_urlopen(b'{"executables": []}')):
        try:
            esc.download(path=target)
            raise AssertionError("invalid data accepted")
        except ValueError:
            pass
    assert open(target, "rb").read() == before
    assert not [name for name in os.listdir(tmp) if name.startswith(".api.")]

    with mock.patch.object(esc.urllib.request, "urlopen",
                           fake_urlopen(b"", length=0)):
        try:
            esc.download(path=target)
            raise AssertionError("empty data accepted")
        except ValueError:
            pass
    assert open(target, "rb").read() == before

    with mock.patch.object(esc.urllib.request, "urlopen",
                           fake_urlopen(valid_raw, length=esc.MAX_DOWNLOAD + 1)):
        try:
            esc.download(path=target)
            raise AssertionError("oversized data accepted")
        except ValueError:
            pass
    assert open(target, "rb").read() == before

    deep = b"[" * 5000 + b"]" * 5000
    with mock.patch.object(esc.urllib.request, "urlopen", fake_urlopen(deep)):
        try:
            esc.download(path=target)
            raise AssertionError("deeply nested JSON accepted")
        except ValueError:
            pass
    assert open(target, "rb").read() == before

    with mock.patch.object(esc, "MAX_DOWNLOAD", 16), \
            mock.patch.object(esc.urllib.request, "urlopen", fake_urlopen(valid_raw)):
        try:
            esc.download(path=target)
            raise AssertionError("streamed oversized data accepted")
        except ValueError:
            pass
    assert open(target, "rb").read() == before

    http_error = urllib.error.HTTPError("https://x/api.json", 503, "down", {}, None)
    with mock.patch.object(esc.urllib.request, "urlopen", side_effect=http_error):
        try:
            esc.download(path=target)
            raise AssertionError("HTTP error accepted")
        except ValueError as exc:
            assert "HTTP 503" in str(exc)
    assert open(target, "rb").read() == before

    with mock.patch.object(esc, "download", side_effect=ValueError("network down")), \
            contextlib.redirect_stderr(io.StringIO()) as stderr:
        try:
            esc.load_api(refresh=True, path=target)
            raise AssertionError("failed refresh did not exit")
        except SystemExit as exc:
            assert exc.code == 1
    assert "existing cache left unchanged" in stderr.getvalue()
    assert open(target, "rb").read() == before

    corrupt = os.path.join(tmp, "corrupt.json")
    with open(corrupt, "w", encoding="utf-8") as fh:
        fh.write('{"executables": "bad"}')
    with contextlib.redirect_stderr(io.StringIO()) as stderr:
        try:
            esc.load_api(path=corrupt)
            raise AssertionError("corrupt cache accepted")
        except SystemExit as exc:
            assert exc.code == 1
    assert "cannot use data file" in stderr.getvalue()


# --- JSON output, evidence, confidence and exit codes ---------------------
baseline_code, baseline_out, baseline_err = run_check(db_with("find"))
baseline = json.loads(baseline_out)
assert baseline_code == 0
assert baseline["version"] == esc.VERSION and baseline["schema_version"] == 1
assert baseline["findings"] == [] and baseline_err == ""
assert baseline["tested"]["suid"] == 0 and baseline["tested"]["sgid"] == 0
assert baseline["tested"]["capabilities_checked"] is False  # darwin
assert baseline["coverage"]["checks"]["sgid"]["status"] == "complete"
assert baseline["coverage"]["complete"] is True

text_code, text_out, _ = run_check(db_with("find"), as_json=False)
assert text_code == 0 and "coverage: complete" in text_out
assert "scan complete: no GTFOBins" in text_out

with tempfile.TemporaryDirectory() as tmp:
    find_path = temp_file(tmp, "find", 0o4755)
    matched_sudo = {
        "ok": True, "status": "complete", "error": None,
        "rules": [sudo_rule(find_path, nopasswd=True)],
    }
    with mock.patch.object(esc, "writable_by_us", return_value=False):
        code, out, err = run_check(db_with("find"), sudo=matched_sudo, fail_on="high")
    payload = json.loads(out)
    finding = payload["findings"][0]
    assert code == esc.EXIT_FINDINGS and err == ""
    assert finding["severity"] == "high" and finding["confidence"] == "medium"
    assert finding["exploitability"] == "unverified" and finding["manual_review"] is False
    assert finding["evidence"]["sudo_rule"]["nopasswd"] is True
    assert finding["evidence"]["sudo_rule"]["arguments"] == ""
    assert finding["evidence"]["functions"] == ["shell"]
    assert finding["functions"][0]["code"].startswith("sudo " + shlex.quote(find_path))
    assert payload["tested"]["sudo"] is True
    assert payload["coverage"]["checks"]["sudo"]["status"] == "complete"

    code, out, _ = run_check(db_with("find"), sudo=matched_sudo)
    assert code == 0   # default behavior remains zero with findings
    code, out, _ = run_check(db_with("find"), sudo=matched_sudo, fail_on="critical")
    assert code == 0
    code, out, _ = run_check(db_with("find"), sudo=matched_sudo, fail_on="medium")
    assert code == esc.EXIT_FINDINGS

    restricted = {
        "ok": True, "status": "complete", "error": None,
        "rules": [sudo_rule(find_path, args="restart nginx", nopasswd=True)],
    }
    code, out, _ = run_check(db_with("find"), sudo=restricted)
    finding = json.loads(out)["findings"][0]
    assert finding["severity"] == "medium" and finding["confidence"] == "low"
    assert finding["manual_review"] is True
    assert finding["evidence"]["sudo_rule"]["arguments"] == "restart nginx"
    assert finding["command"] == "sudo " + shlex.quote(find_path) + " restart nginx"

    all_rule = {
        "all": True, "path": None, "args": "", "runas": "root",
        "nopasswd": True, "raw": "(ALL : ALL) NOPASSWD: ALL",
        "spec": "NOPASSWD: ALL", "permitted": "ALL", "manual": False,
    }
    code, out, _ = run_check(db_with("find"), sudo={
        "ok": True, "status": "complete", "error": None, "rules": [all_rule]})
    finding = json.loads(out)["findings"][0]
    assert finding["severity"] == "critical" and finding["command"] == "sudo -i"
    assert finding["evidence"]["sudo_rule"]["permitted"] == "ALL"

    group_rule = sudo_rule(find_path, runas=":dialer")
    group_rule["manual"] = False
    code, out, _ = run_check(db_with("find"), sudo={
        "ok": True, "status": "complete", "error": None, "rules": [group_rule]})
    finding = json.loads(out)["findings"][0]
    assert finding["severity"] == "medium" and finding["manual_review"] is True
    assert finding["functions"] == [] and finding["confidence"] == "low"

    # SUID findings: non-writable matched binary vs writable privileged binary.
    with mock.patch.object(esc, "writable_by_us", return_value=False):
        code, out, _ = run_check(
            db_with("find"),
            privileged={"suid": {find_path}, "sgid": set(), "status": "complete",
                        "reason": None, "complete": True},
            fail_on="high")
    payload = json.loads(out)
    finding = payload["findings"][0]
    assert code == esc.EXIT_FINDINGS
    assert finding["vector"] == "suid" and finding["severity"] == "high"
    assert finding["confidence"] == "medium" and finding["evidence"]["setuid"] is True
    assert finding["evidence"]["scan_complete"] is True
    assert finding["functions"][0]["code"].startswith(shlex.quote(find_path))

    limited_db = esc.DB(api({"find": {"functions": {"list": [{
        "code": "find /",
        "contexts": {"suid": None, "capabilities": {"list": ["CAP_NET_RAW"]}},
    }]}}}))
    with mock.patch.object(esc, "writable_by_us", return_value=False):
        code, out, _ = run_check(
            limited_db,
            privileged={"suid": {find_path}, "sgid": set(), "status": "complete",
                        "reason": None, "complete": True})
        assert json.loads(out)["findings"][0]["severity"] == "medium"
        assert json.loads(out)["findings"][0]["confidence"] == "medium"
        code, out, _ = run_check(
            limited_db, platform="linux",
            caps={"caps": {find_path: {"cap_net_raw"}}, "status": "complete",
                  "reason": None, "checked": True})
        limited_cap = json.loads(out)["findings"][0]
        assert limited_cap["severity"] == "medium"
        assert limited_cap["confidence"] == "medium"

    fake_stat = os.stat_result((stat.S_IFREG | 0o4755, 1, 1, 1, 0, 0, 0, 0, 0, 0))
    with mock.patch.object(esc, "writable_by_us", return_value=True), \
            mock.patch.object(esc.os, "lstat", return_value=fake_stat):
        code, out, _ = run_check(
            db_with("find"),
            privileged={"suid": {find_path}, "sgid": set(), "status": "complete",
                        "reason": None, "complete": True})
    finding = json.loads(out)["findings"][0]
    assert finding["title"].startswith("writable SUID binary:")
    assert finding["severity"] == "critical" and finding["confidence"] == "high"
    assert finding["evidence"]["owner"] == "root"

    # SGID is separate and never correlated with GTFOBins snippets.
    sgid_path = temp_file(tmp, "find-sgid", 0o2755)
    with mock.patch.object(esc, "writable_by_us", return_value=True), \
            mock.patch.object(esc.grp, "getgrgid", return_value=mock.Mock(gr_name="root")):
        code, out, _ = run_check(
            db_with("find"),
            privileged={"suid": set(), "sgid": {sgid_path}, "status": "complete",
                        "reason": None, "complete": True})
    finding = json.loads(out)["findings"][0]
    assert finding["vector"] == "sgid" and finding["severity"] == "critical"
    assert finding["functions"] == [] and finding["evidence"]["setgid"] is True
    assert "no SGID contexts" in finding["evidence"]["limitations"]

    with mock.patch.object(esc, "writable_by_us", return_value=True), \
            mock.patch.object(esc.grp, "getgrgid", return_value=mock.Mock(gr_name="users")):
        code, out, _ = run_check(
            db_with("find"),
            privileged={"suid": set(), "sgid": {sgid_path}, "status": "complete",
                        "reason": None, "complete": True})
    nonpriv = json.loads(out)["findings"][0]
    assert nonpriv["vector"] == "sgid" and nonpriv["severity"] == "high"

    # Linux capabilities: matching cap and a writable binary with caps.
    python_path = temp_file(tmp, "python3")
    caps = {"caps": {python_path: {"cap_setuid"}}, "status": "complete",
            "reason": None, "checked": True}
    with mock.patch.object(esc, "writable_by_us", return_value=False):
        code, out, _ = run_check(
            db_with("find", "python"), caps=caps, platform="linux", fail_on="high")
    payload = json.loads(out)
    finding = payload["findings"][0]
    assert code == esc.EXIT_FINDINGS
    assert finding["vector"] == "capabilities" and finding["severity"] == "high"
    assert finding["evidence"]["capabilities"] == ["cap_setuid"]
    assert finding["evidence"]["scan_complete"] is True
    assert finding["functions"][0]["name"] == "shell"

    with mock.patch.object(esc, "writable_by_us", return_value=True), \
            mock.patch.object(esc.os, "lstat", return_value=os.stat_result(
                (stat.S_IFREG | 0o755, 1, 1, 1, 0, 0, 0, 0, 0, 0))):
        code, out, _ = run_check(
            db_with("python"), caps=caps, platform="linux")
    finding = json.loads(out)["findings"][0]
    assert finding["title"].startswith("writable binary with capabilities:")
    assert finding["severity"] == "critical"

    # Incomplete scans stay visible, keep partial findings and do not look clean.
    partial = {"suid": {find_path}, "sgid": set(), "status": "partial",
               "reason": "timed out", "complete": False}
    with mock.patch.object(esc, "writable_by_us", return_value=False):
        code, out, _ = run_check(db_with("find"), privileged=partial)
    payload = json.loads(out)
    assert code == 0  # partial coverage is not an operational failure
    assert payload["tested"]["suid_complete"] is False
    assert payload["tested"]["sgid_complete"] is False
    assert payload["coverage"]["complete"] is False
    assert payload["coverage"]["checks"]["suid"]["status"] == "partial"
    assert payload["findings"][0]["evidence"]["scan_complete"] is False
    assert any("SUID/SGID scan partial" in note for note in payload["notes"])

    failed = {"suid": set(), "sgid": set(), "status": "failed",
              "reason": "find failed", "complete": False}
    code, out, _ = run_check(db_with("find"), privileged=failed)
    payload = json.loads(out)
    assert code == esc.EXIT_ERROR and payload["findings"] == []
    assert payload["coverage"]["checks"]["suid"]["status"] == "failed"

    unavailable_caps = {"caps": {}, "status": "unavailable",
                        "reason": "getcap not installed", "checked": False}
    code, out, _ = run_check(db_with("find"), caps=unavailable_caps, platform="linux")
    payload = json.loads(out)
    assert payload["tested"]["capabilities_checked"] is False
    assert payload["coverage"]["checks"]["capabilities"]["status"] == "unavailable"
    assert any("getcap" in note for note in payload["notes"])

    skipped_sudo = {"ok": False, "rules": [],
                    "error": "sudo: a password is required", "status": "skipped"}
    code, out, _ = run_check(db_with("find"), sudo=skipped_sudo)
    payload = json.loads(out)
    assert payload["coverage"]["checks"]["sudo"]["status"] == "skipped"
    assert payload["coverage"]["complete"] is False
    assert payload["findings"] == []

    # Terminal output never emits control characters from a discovered path.
    evil = temp_file(tmp, "evil\x1b[31mfind", 0o4755)
    code, out, _ = run_check(
        db_with("find"),
        privileged={"suid": {evil}, "sgid": set(), "status": "complete",
                    "reason": None, "complete": True},
        as_json=False)
    assert "\x1b" not in out and "\\x1b" in out


# --- command-line exit-code wiring ----------------------------------------
with mock.patch.object(esc, "load_api", return_value=api()), \
        mock.patch.object(esc, "cmd_check", return_value=esc.EXIT_FINDINGS) as check, \
        mock.patch.object(esc.sys, "argv",
                          ["escabin", "check", "--json", "--fail-on", "high"]):
    try:
        esc.main()
        raise AssertionError("check did not exit")
    except SystemExit as exc:
        assert exc.code == esc.EXIT_FINDINGS
assert check.call_args[0][4] == "high"


# --- exit-code threshold helper -------------------------------------------
synthetic = [{"severity": "high"}]
assert esc.check_exit_code(synthetic, None) == 0
assert esc.check_exit_code(synthetic, "critical") == 0
assert esc.check_exit_code(synthetic, "high") == esc.EXIT_FINDINGS
assert esc.check_exit_code(synthetic, "medium") == esc.EXIT_FINDINGS
assert esc.check_exit_code([{"severity": "critical"}], "high") == esc.EXIT_FINDINGS
assert esc.check_exit_code([{"severity": "medium"}], "high") == 0
assert esc.check_exit_code([], "medium") == 0


print("all tests passed")
