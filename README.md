# escabin

[![version](https://img.shields.io/badge/version-2.1-5c4ee5?style=flat-square)](#escabin)
[![Python 3.7+](https://img.shields.io/badge/Python-3.7%2B-3776ab?style=flat-square&logo=python&logoColor=white)](#requirements)
[![Linux | macOS](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-f4c430?style=flat-square)](#requirements)
[![stdlib only](https://img.shields.io/badge/dependencies-none-2ea44f?style=flat-square)](#requirements)
[![GTFOBins](https://img.shields.io/badge/data-GTFOBins-cb3837?style=flat-square)](https://gtfobins.org)

Offline [GTFOBins](https://gtfobins.org) lookup and a fast local privilege-escalation
audit. One Python file, standard library only.

- `check` finds SUID binaries, writable SUID/SGID files, sudo rules and Linux
  file capabilities, then maps them to GTFOBins and ranks them by severity and
  confidence.
- `show`, `search` and `list` browse the full dataset without a network connection.
- `check` never executes the GTFOBins snippets it prints; it only runs
  `sudo -l`, `find` and `getcap`.

Use it only on systems you are authorized to assess.

## Contents

- [Quick start](#quick-start)
- [Install](#install)
- [Commands](#commands)
- [check](#check)
- [Coverage and exit status](#coverage-and-exit-status)
- [JSON output](#json-output)
- [Data and trust](#data-and-trust)
- [Limitations](#limitations)
- [Uninstall](#uninstall)
- [Development](#development)
- [Credits](#credits)

## Quick start

```sh
curl -fsSL https://raw.githubusercontent.com/two35s/Escabin/main/install.sh | sh
escabin check --ask-sudo
```

See [Install](#install) for the inspect-first option, `PATH` notes and the
clone-based install. From a clone, `./escabin check` runs without installing.

If the data file is missing, the first command downloads it to
`~/.local/share/escabin/api.json`.

## Install

### One-line install

```sh
curl -fsSL https://raw.githubusercontent.com/two35s/Escabin/main/install.sh | sh
```

The script downloads the CLI from this repository, installs it to
`~/.local/share/escabin/escabin`, symlinks `~/.local/bin/escabin`, and
refreshes the GTFOBins data. It needs `curl` and network access.

The new file is staged, checked with `--version`, then moved into place
atomically; a failed download or a broken download does not replace a working
install. The installer refuses to overwrite an existing `~/.local/bin/escabin`
that is not its own symlink.

To inspect the installer before running it:

```sh
curl -fsSL https://raw.githubusercontent.com/two35s/Escabin/main/install.sh -o /tmp/install.sh
less /tmp/install.sh
sh /tmp/install.sh
```

Make sure `~/.local/bin` is on your `PATH`; the installer warns if it is not.

### From a clone

```sh
git clone https://github.com/two35s/Escabin.git
cd Escabin
./install.sh
```

Re-run the same command to upgrade (pull first for a clone).

Manual install:

```sh
mkdir -p ~/.local/bin
install -m 755 escabin ~/.local/bin/escabin
escabin update        # optional; the first run downloads data anyway
```

### Requirements

- Python 3.7 or newer.
- `curl` for the one-line installer.
- Linux or macOS. Windows is not supported (POSIX permissions and sudo).
- `find` for the SUID/SGID scan. `check` exits `1` if it is unavailable or fails.
- Optional: `sudo` for the sudo scan, `getcap` for Linux capabilities.

No third-party Python packages.

If you are offline, install the files manually and place a trusted `api.json`
in the data directory before the first run (see [Data and trust](#data-and-trust)).

## Commands

| Command | What it does |
| --- | --- |
| `escabin show <binary>` | Show every documented trick for one binary. |
| `escabin <binary>` | Shortcut for `show`. |
| `escabin search <term> [-n N]` | Search names, function labels, commands and comments. Default limit: 40. |
| `escabin list` | List every binary in the dataset. |
| `escabin check [options]` | Audit the local machine. |
| `escabin update` | Download fresh data and print its size and SHA-256. |
| `escabin --version` | Print the version. |

`show` accepts a name, a path or a versioned name: `vim`, `/usr/bin/vim`,
`python3.11`, `/usr/bin/gcc-12`.

```sh
escabin show vim
escabin show /usr/bin/vim
escabin search 'reverse shell' -n 5
escabin list
```

## check

```sh
escabin check                 # fast scan, non-interactive sudo
escabin check --ask-sudo      # let sudo prompt, so your rules are visible
escabin check --full          # scan the whole filesystem (slow)
escabin check --json          # machine-readable output
escabin check --fail-on high  # exit 3 when a high or critical finding exists
```

### What it scans

1. **Sudo** with `sudo -l`. Without `--ask-sudo` it uses `sudo -n -l`, so rules
   are only seen when sudo does not need a password. `--ask-sudo` lets sudo
   prompt normally. The tool parses the displayed rules; it does not read
   `/etc/sudoers` directly.
2. **SUID and SGID regular files** in one `find` traversal. Symlinks are not
   followed and paths are NUL-separated, so unusual filenames are handled.
   The default scan covers the usual system paths:
   - Linux: `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/libexec`,
     `/usr/local/bin`, `/usr/local/sbin`, `/opt`, `/snap/bin`, `/tmp`,
     `/var/tmp`.
   - macOS: `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/libexec`,
     `/usr/local/bin`, `/usr/local/sbin`, `/opt/homebrew/bin`,
     `/opt/homebrew/sbin`, `/Applications`, `/Library`, `/System/Applications`,
     `/System/Library/CoreServices`, `/private/tmp`, `/private/var/tmp` and
     `/Users/Shared`.

   `--full` scans `/` and prunes pseudo-filesystems, `/snap`, container
   layers, macOS volume mounts, `/net` and network filesystems listed in
   `/proc/self/mounts`.
3. **Linux file capabilities** with `getcap -r /`. This step is unsupported on
   macOS, and is marked unavailable, failed or partial when `getcap` is
   missing, errors or times out.

The checks run in parallel. A SUID/SGID scan has a fast default timeout of
120 seconds (900 for `--full`), capabilities 180 seconds, and sudo 20 seconds
(300 with `--ask-sudo`). Partial results are kept.

### How findings are built

- Sudo rules are matched against GTFOBins. The displayed snippet is rewritten
  to use the actual path in the sudoers rule and inserts `sudo` (or
  `sudo -u <user>` for a non-root runas) at command positions, including
  pipelines and multi-line scripts. `NOPASSWD` and `PASSWD` are inherited across
  a command list, runas lists are parsed, and group-only runas is flagged for
  manual review.
- A sudo rule with restricted arguments is reported as `medium` with the exact
  permitted command and `manual_review: true`. GTFOBins cannot know whether
  those arguments are exploitable, so no snippet is claimed.
- Command aliases, `sudoedit`, digests, extra sudoers options, wildcard paths
  and directory rules are flagged for manual review rather than guessed.
- SUID and capability snippets are retargeted to the binary that was found.
  Capability entries are only shown when the binary has the capabilities the
  GTFOBins entry requires.
- A writable SUID binary is reported as `critical` when owned by root and
  `high` otherwise: you can replace it, so a replacement would run with the
  binary's privileges.
- A writable SGID binary is reported as `critical` when its group is
  privileged (`root`, `wheel`, `admin`, `shadow`, `disk`, `docker`, `lxd`,
  `sudo`) and `high` otherwise. Only writable SGID files are reported;
  GTFOBins has no SGID contexts, so no SGID snippet is correlated.
- A writable capability binary is reported even when GTFOBins has no entry for
  it: `critical` when owned by root, `high` otherwise.
- "Writable" means writable by the current user. When `check` runs as root,
  group/other write bits are used instead, because root can write almost
  anything.

### Confidence and severity

Severity describes the class of access. Confidence describes how direct the
evidence is. `exploitability` is always `unverified`: the tool observed a
configuration and matched documentation; it did not execute a snippet.

| Confidence | Meaning |
| --- | --- |
| `high` | Direct defect, such as a writable privileged file or an unrestricted rule. |
| `medium` | Confirmed privileged path plus a documented GTFOBins technique. |
| `low` | Conditional or manual-review case; the tool makes no exploit claim. |

| Severity | Meaning in this tool |
| --- | --- |
| `critical` | Unrestricted root sudo (password or NOPASSWD); writable root-owned SUID or capability binary; writable SGID binary with a privileged group. |
| `high` | NOPASSWD sudo of a serious binary; unrestricted sudo as another user; SUID/capability binary with serious functions; writable SUID/capability binary owned by a non-root user; writable SGID binary with an unprivileged group. |
| `medium` | Password-protected sudo of a specific serious binary; NOPASSWD sudo of a limited binary; restricted-argument sudo (manual review); SUID/capability binary with limited functions such as upload, download, list or tty. |

The "serious" functions are shell, command, reverse-shell, bind-shell,
privilege-escalation, file-read and file-write.

### Example output

Trimmed example; your paths, rules and output will differ.

```text
$ escabin check --ask-sudo
Escabin local check  linux  user=alice  1.8s
checks: sudo complete (1); suid complete (41); sgid complete (3); capabilities complete (6)
coverage: complete

HIGH       sudo /usr/bin/find (NOPASSWD)
          medium confidence; exploitability unverified
          sudo rule: (root) NOPASSWD: /usr/bin/find
          evidence: path=/usr/bin/find  runas=root  nopasswd=yes  rule=NOPASSWD: /usr/bin/find  gtfobins=shell  scan=complete
          shell
          $ sudo /usr/bin/find . -exec /bin/sh \; -quit
          risk: The rule runs /usr/bin/find as root; the documented function may provide a shell or file access.
          limitations: GTFOBins documents a technique, not a proof that this version and configuration are exploitable; the snippet was not executed.
          remediation: Restrict or remove the sudo rule; avoid granting interpreters, editors, pagers and file tools; review sudoers regularly.
```

Displayed commands are suggestions. Fill in placeholders such as
`/path/to/input-file`, and review a command before running it. A "no vector
found" result means nothing matched in the paths that were scanned, not that
the machine is secure.

## Coverage and exit status

Each check reports one of these statuses in `coverage.checks`:

| Status | Meaning |
| --- | --- |
| `complete` | The check finished. |
| `partial` | Some results are available, but the check timed out or could not read everything. Partial findings are kept. |
| `failed` | The check produced no usable results. |
| `skipped` | The check was not run, for example sudo needed a password. |
| `unavailable` | The required tool is not installed. |
| `unsupported` | The platform does not support the check (capabilities on macOS). |

`coverage.complete` is true only when every check is `complete` or
`unsupported`. A missing or failed `find` makes the SUID/SGID check unusable and
exits `1`. A partial SUID/SGID scan still reports findings and exits `0` unless
`--fail-on` matches.

Exit status:

| Code | Meaning |
| --- | --- |
| `0` | Scan finished. Findings are present in the output, but do not fail the command by default. |
| `1` | Operational failure: data could not be loaded, or `find` is unavailable or failed. |
| `2` | Invalid command-line arguments. |
| `3` | `--fail-on` matched a finding at or above the requested severity. |

`--fail-on` applies to critical, high or medium findings:

```sh
escabin check --fail-on critical   # exit 3 only for critical findings
escabin check --fail-on high       # critical or high
escabin check --fail-on medium     # any reported finding
```

## JSON output

`--json` prints one object to stdout. It contains the scan metadata, findings
and coverage. Fields are additive within `schema_version: 1`; consumers should
ignore unknown keys.

| Field | Meaning |
| --- | --- |
| `version` | Tool version. |
| `schema_version` | JSON schema generation. Currently `1`. |
| `platform` | `sys.platform` of the audited machine. |
| `user` | Current user. |
| `elapsed` | Scan time in seconds. |
| `tested.suid` | Number of SUID binaries found. |
| `tested.sgid` | Number of SGID binaries found. |
| `tested.capabilities` | Number of files with capabilities found (0 if unavailable or unsupported). |
| `tested.sudo` | Whether `sudo -l` succeeded. |
| `tested.suid_complete` | False if the SUID/SGID scan was partial, failed or unavailable. |
| `tested.sgid_complete` | Same scan status for SGID. |
| `tested.capabilities_checked` | True only when the capability scan completed. |
| `coverage.complete` | Whether every check is complete or unsupported. |
| `coverage.checks.<name>` | `status`, `reason` and `count` for `sudo`, `suid`, `sgid` and `capabilities`. |
| `findings[].severity` | `critical`, `high` or `medium`. |
| `findings[].confidence` | `high`, `medium` or `low`. |
| `findings[].exploitability` | Always `unverified`. |
| `findings[].vector` | `sudo`, `suid`, `sgid` or `capabilities`. |
| `findings[].title` | Human-readable finding. |
| `findings[].detail` | The sudo rule or ownership/mode details. |
| `findings[].command` | A direct command when one is enough (for example `sudo -i`), else `null`. |
| `findings[].functions[]` | GTFOBins `name` and rewritten `code` snippets; empty when no function is correlated (SGID, manual sudo rules, unmatched writable binaries). |
| `findings[].manual_review` | True when a human should check the rule or file. |
| `findings[].evidence` | Structured evidence for the finding. |
| `notes[]` | Warnings about skipped or incomplete checks. |

File evidence (`suid`, `sgid`, `capabilities`) contains `check`, `path`,
`owner`, `group`, `mode`, `setuid`, `setgid`, `writable`, `scan_complete`,
`functions`, `risk`, `limitations` and `remediation`. Capability findings also
include `capabilities`. Sudo evidence contains `check`, `path`,
`sudo_rule.raw`, `sudo_rule.spec`, `sudo_rule.permitted`, `sudo_rule.runas`,
`sudo_rule.nopasswd`, `sudo_rule.arguments`, `scan_complete`, `functions`,
`path_exists` when relevant, plus `risk`, `limitations` and `remediation`.

```json
{
  "version": "2.1",
  "schema_version": 1,
  "platform": "linux",
  "user": "alice",
  "elapsed": 1.84,
  "tested": {
    "suid": 41,
    "sgid": 3,
    "capabilities": 6,
    "sudo": true,
    "suid_complete": true,
    "sgid_complete": true,
    "capabilities_checked": true
  },
  "coverage": {
    "complete": true,
    "checks": {
      "sudo": {"status": "complete", "reason": null, "count": 1},
      "suid": {"status": "complete", "reason": null, "count": 41},
      "sgid": {"status": "complete", "reason": null, "count": 3, "note": "GTFOBins has no SGID contexts; only writable SGID files are reported."},
      "capabilities": {"status": "complete", "reason": null, "count": 6}
    }
  },
  "findings": [
    {
      "severity": "high",
      "confidence": "medium",
      "exploitability": "unverified",
      "vector": "sudo",
      "title": "sudo /usr/bin/find (NOPASSWD)",
      "detail": "sudo rule: (root) NOPASSWD: /usr/bin/find",
      "command": null,
      "functions": [
        {
          "name": "shell",
          "code": "sudo /usr/bin/find . -exec /bin/sh \\; -quit"
        }
      ],
      "manual_review": false,
      "evidence": {
        "check": "sudo",
        "path": "/usr/bin/find",
        "sudo_rule": {
          "raw": "(root) NOPASSWD: /usr/bin/find",
          "spec": "NOPASSWD: /usr/bin/find",
          "permitted": "/usr/bin/find",
          "runas": "root",
          "nopasswd": true,
          "arguments": ""
        },
        "scan_complete": true,
        "path_exists": true,
        "functions": ["shell"],
        "risk": "The rule runs /usr/bin/find as root; the documented function may provide a shell or file access.",
        "limitations": "GTFOBins documents a technique, not a proof that this version and configuration are exploitable; the snippet was not executed.",
        "remediation": "Restrict or remove the sudo rule; avoid granting interpreters, editors, pagers and file tools; review sudoers regularly."
      }
    }
  ],
  "notes": []
}
```

Optional filtering with `jq`:

```sh
escabin check --json | jq -r '.findings[] | "\(.severity)\t\(.confidence)\t\(.title)"'
```

## Data and trust

- Data comes from `https://gtfobins.org/api.json` over HTTPS.
- It is cached at `$ESCABIN_HOME/api.json`, defaulting to
  `~/.local/share/escabin/api.json`.
- Downloads are capped at 8 MiB and use a 30-second network timeout.
- The JSON is shape-checked before it is written: top-level
  `executables`/`functions`/`contexts` objects, non-empty executables, and
  string/list types for aliases, comments, code, function labels and capability
  lists.
- A validated download replaces the cache atomically (`os.replace`). A failed
  download, invalid JSON or malformed data leaves the existing cache unchanged.
- `update` prints the file size and SHA-256. The data is **not signed or
  hash-pinned**, so the hash is for comparison, not verification.
- For a trusted or offline copy, put an `api.json` in `ESCABIN_HOME` and do not
  run `update`:

```sh
mkdir -p ~/.escabin-data
cp /path/to/trusted/api.json ~/.escabin-data/api.json
ESCABIN_HOME=~/.escabin-data escabin check
```

Other environment variables:

- `NO_COLOR` disables ANSI colors. Colors are only used on a TTY.

## Limitations

- This is not a complete privilege-escalation scanner. It only knows GTFOBins:
  no kernel exploits, cron jobs, services or timers, credentials, or
  configuration auditing.
- `check` audits the current account. Run it as the user you are assessing; as
  root, `sudo -l` shows root's rules, not a normal user's.
- Sudo rules are only as visible as `sudo -l` makes them. Use `--ask-sudo`
  when your sudo setup requires a password. Aliases, includes and policy
  details are not re-parsed; unusual specifications are flagged for manual
  review.
- Restricted-argument sudo rules are left for manual review; the tool does not
  try to find a way to abuse the allowed arguments.
- SGID files are scanned but not correlated with GTFOBins, because GTFOBins
  has no SGID contexts. Only writable SGID files are reported.
- Capabilities are Linux-only and depend on `getcap`; a timeout leaves them
  partially checked rather than silently empty.
- The default SUID/SGID scan is fast but not exhaustive. Use `--full` to include
  home directories and other paths; `--full` is slow and skips `/snap`, network
  mounts, pseudo-filesystems and container layers.
- A few GTFOBins snippets invoke a different program or assume you are already
  inside the target shell (for example `bash` history tricks or `egrep` using
  `grep`). Those are printed as documented and are not sudo-rewritten.
- On macOS, SIP and other protections may prevent an otherwise matching binary
  from being exploitable. Treat a finding as a lead, not as proof.
- Severity and confidence reflect the documented function class and the
  observed configuration, not the actual exploitability of your exact version.
- Not implemented yet: SARIF output, cron/systemd checks and configuration
  auditing. The Linux capability and SGID paths are unit-tested with mocks;
  validate them on the distribution you are assessing.

## Uninstall

```sh
rm -f ~/.local/bin/escabin
rm -rf ~/.local/share/escabin
```

If you set `ESCABIN_HOME`, remove that directory instead of the default one.

## Development

The tool is deliberately one stdlib-only file (`escabin`). There is no build
step.

```sh
python3 -m py_compile escabin
python3 tests.py
```

`tests.py` is offline and needs no root access. It uses mocks and temporary
files to cover sudo parsing (runas, tags, escaped commas, restricted args),
command rewriting, path/version normalization, capability gating, dataset
validation and cache preservation, SUID/SGID scan partials and timeouts,
writable-file logic, JSON/evidence/confidence output, exit codes and terminal
sanitization. It never executes a GTFOBins snippet or changes system settings.

## Credits

Data and snippets come from the [GTFOBins](https://gtfobins.org) project
([source](https://github.com/GTFOBins/GTFOBins.github.io)). Escabin is not
affiliated with GTFOBins.
