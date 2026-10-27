#!/usr/bin/env python3
"""Asserts for the parsers that produce user-facing commands. Run: python3 tests.py"""

import importlib.machinery
import importlib.util

loader = importlib.machinery.SourceFileLoader("gt", "gtfobins")
spec = importlib.util.spec_from_loader("gt", loader)
gt = importlib.util.module_from_spec(spec)
loader.exec_module(gt)

# --- sudo -l parsing -------------------------------------------------------
SAMPLE = """Matching Defaults entries for bob on host:
    env_reset, mail_badpass

User bob may run the following commands on host:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/vim, /usr/bin/systemctl restart nginx
    (root) /usr/bin/find, (ALL) NOPASSWD: /bin/cat
"""
rules = gt.parse_sudo(SAMPLE)
assert len(rules) == 5, rules
assert rules[0]["all"] and not rules[0]["nopasswd"]
assert rules[1]["path"] == "/usr/bin/vim" and rules[1]["nopasswd"]
assert rules[2]["path"] == "/usr/bin/systemctl" and rules[2]["nopasswd"]
assert rules[2]["args"] == "restart nginx"
assert rules[3]["path"] == "/usr/bin/find" and not rules[3]["nopasswd"]
assert rules[4]["path"] == "/bin/cat" and rules[4]["nopasswd"] and rules[4]["runas"] == "ALL"

assert gt.runas_user({"runas": "www-data : www-data"}) == "www-data"
assert gt.runas_user({}) == "root"
assert gt.is_root_runas("ALL") and gt.is_root_runas("root")
assert not gt.is_root_runas("www-data")

# --- command rewriting -----------------------------------------------------
rw = gt.rewrite_commands
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

# --- data lookup -----------------------------------------------------------
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
db = gt.DB(data)
assert db.canon("apt") == "apt-get"
assert db.canon("/usr/bin/python3.11") == "python"
assert db.canon("gcc-12") == "gcc"
assert db.canon("no-such-binary") is None

# --- capability gating -----------------------------------------------------
cap_data = {
    "executables": {"python": {"functions": {"shell": [{
        "code": "python -c x",
        "contexts": {"capabilities": {"list": ["CAP_SETUID"]}},
    }]}}},
    "functions": {},
    "contexts": {},
}
cap_db = gt.DB(cap_data)
key, funcs = gt.matching(cap_db, "/usr/bin/python3", "capabilities", {"cap_setuid"})
assert key == "python" and [f for f, _ in funcs] == ["shell"]
assert gt.matching(cap_db, "/usr/bin/python3", "capabilities", {"cap_net_raw"})[1] == []

# --- root and writable SUID ------------------------------------------------
assert not gt.writable_by_us(0o4755, 0, True)   # root: access() is always true
assert gt.writable_by_us(0o4777, 0, False)
assert gt.writable_by_us(0o4755, 1000, True)
assert not gt.writable_by_us(0o4755, 1000, False)

# --- text cleanup ----------------------------------------------------------
assert gt.clean_md("see [cron](https://x)") == "see cron (https://x)"

print("all tests passed")
