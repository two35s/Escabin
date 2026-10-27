# gtfobins

Offline [GTFOBins](https://gtfobins.org) lookup and a fast local privilege-escalation
audit. One Python file, standard library only.

- `check` finds SUID binaries, sudo rules and Linux file capabilities that
  GTFOBins can abuse, ranked by severity.
- `show`, `search` and `list` browse the full dataset without a network connection.
- `check` never executes the GTFOBins snippets it prints; it only runs
  `sudo -l`, `find` and `getcap`.

Use it only on systems you are authorized to assess.

## Contents

- [Quick start](#quick-start)
- [Install](#install)
- [Commands](#commands)
- [check](#check)
- [JSON output](#json-output)
- [Data and trust](#data-and-trust)
- [Limitations](#limitations)
- [Uninstall](#uninstall)
- [Development](#development)
- [Credits](#credits)

## Quick start

```sh
git clone https://github.com/two35s/Escabin.git
cd Escabin
./install.sh
gtfobins check --ask-sudo
```

You can also run it without installing:

```sh
./gtfobins check
```

If the data file is missing, the first command downloads it to
`~/.local/share/gtfobins/api.json`.

## Install

`./install.sh` does four things:

1. Copies the CLI to `~/.local/share/gtfobins/gtfobins`.
2. Symlinks it as `~/.local/bin/gtfobins`.
3. Runs `gtfobins update` to download the latest data (needs network).
4. Warns if `~/.local/bin` is not in your `PATH`.

Re-run the installer to upgrade. It refuses to overwrite a `gtfobins` at that
path that is not its own symlink.

Manual install:

```sh
mkdir -p ~/.local/bin
install -m 755 gtfobins ~/.local/bin/gtfobins
gtfobins update        # optional; the first run downloads data anyway
```

### Requirements

- Python 3.7 or newer.
- Linux or macOS. Windows is not supported (POSIX permissions and sudo).
- `find` for the SUID scan.
- Optional: `sudo` for the sudo scan, `getcap` for Linux capabilities.

No third-party Python packages.

If you are offline, install the files manually and place a trusted `api.json`
in the data directory before the first run (see [Data and trust](#data-and-trust)).

## Commands

| Command | What it does |
| --- | --- |
| `gtfobins show <binary>` | Show every documented trick for one binary. |
| `gtfobins <binary>` | Shortcut for `show`. |
| `gtfobins search <term> [-n N]` | Search names, function labels, commands and comments. Default limit: 40. |
| `gtfobins list` | List every binary in the dataset. |
| `gtfobins check [options]` | Audit the local machine. |
| `gtfobins update` | Download fresh data and print its size and SHA-256. |
| `gtfobins --version` | Print the version. |

`show` accepts a name, a path or a versioned name: `vim`, `/usr/bin/vim`,
`python3.11`, `/usr/bin/gcc-12`.

```sh
gtfobins show vim
gtfobins show /usr/bin/vim
gtfobins search 'reverse shell' -n 5
gtfobins list
```

## check

```sh
gtfobins check                 # fast scan, non-interactive sudo
gtfobins check --ask-sudo      # let sudo prompt, so your rules are visible
gtfobins check --full          # scan the whole filesystem (slow)
gtfobins check --json          # machine-readable output
```

### What it scans

1. **Sudo** with `sudo -l`. Without `--ask-sudo` it uses `sudo -n -l`, so rules
   are only seen when sudo does not need a password. `--ask-sudo` lets sudo
   prompt normally.
2. **SUID binaries** with `find -perm -4000`. The default scan covers the usual
   system paths:
   - Linux: `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/libexec`,
     `/usr/local/bin`, `/usr/local/sbin`, `/opt`, `/snap/bin`, `/tmp`,
     `/var/tmp`.
   - macOS: `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/libexec`,
     `/usr/local/bin`, `/usr/local/sbin`, `/opt/homebrew/bin`,
     `/opt/homebrew/sbin`, `/Applications`, `/Library`, `/System/Applications`,
     `/System/Library/CoreServices`, `/private/tmp`, `/private/var/tmp` and
     `/Users/Shared`.

   `--full` scans `/` and prunes pseudo-filesystems and container layers
   (`/proc`, `/sys`, `/dev`, `/run`, `/snap`, `/var/lib/docker`, macOS volume
   mounts and swap files).
3. **Linux file capabilities** with `getcap -r /`. This step is skipped on
   macOS, when `getcap` is missing, or when it times out; the output says which.

SUID and capability scans run in parallel. Scan timeouts are reported, and
partial SUID results are kept rather than discarded.

### How findings are built

- Sudo rules are matched against GTFOBins. The displayed snippet is rewritten
  to use the actual path in the sudoers rule and inserts `sudo` (or
  `sudo -u <user>` for a non-root runas) at command positions, including
  pipelines and multi-line scripts.
- SUID and capability snippets are retargeted to the binary that was found.
- A writable SUID binary is reported as `critical`: you can replace it, so
  anyone who runs it executes your file with the binary's privileges.
- Sudo rules with restricted arguments are reported as `medium` with the exact
  permitted command. GTFOBins cannot know whether those arguments are
  exploitable, so this needs a manual look.

### Severity

Severity is a heuristic based on the documented GTFOBins functions, not a proof
that the machine is exploitable. The "serious" functions are shell, command,
reverse-shell, bind-shell, privilege-escalation, file-read and file-write.

| Severity | Meaning in this tool |
| --- | --- |
| `critical` | Unrestricted root sudo (password or NOPASSWD), or a SUID binary you can replace. |
| `high` | NOPASSWD sudo of a serious binary; unrestricted sudo as another user; SUID/capability binary with serious functions. |
| `medium` | Password-protected sudo of a specific serious binary; NOPASSWD sudo of a limited binary; restricted-argument sudo (manual review); SUID/capability binary with limited functions such as upload, download, list or tty. |

### Example output

Trimmed example; your paths and rules will differ.

```text
$ gtfobins check --ask-sudo
GTFOBins local check  linux  user=alice  1.8s
scanned 41 SUID binaries, 6 capabilities; sudo -l ok

HIGH       sudo /usr/bin/find (NOPASSWD)
          sudo rule: (root) NOPASSWD: /usr/bin/find
          shell
          $ sudo /usr/bin/find . -exec /bin/sh \; -quit

MEDIUM     sudo /usr/bin/systemctl (restricted args) (NOPASSWD)
          sudo rule: (root) NOPASSWD: /usr/bin/systemctl restart nginx - check manually whether the allowed arguments can be abused
          $ sudo /usr/bin/systemctl restart nginx
```

Displayed commands are suggestions. Fill in placeholders such as
`/path/to/input-file`, and review a command before running it. A "no vector
found" result means nothing matched in the paths that were scanned, not that
the machine is secure.

### Exit status

`check` exits `0` even when it finds vectors; read the findings or the JSON.
It exits non-zero only for operational errors (no data, download failure,
missing `find`, bad arguments).

## JSON output

`--json` prints one object to stdout. Severities, vectors, `notes` and scan
coverage are all included.

| Field | Meaning |
| --- | --- |
| `version` | Tool version. |
| `platform` | `sys.platform` of the audited machine. |
| `user` | Current user. |
| `elapsed` | Scan time in seconds. |
| `tested.suid` | Number of SUID binaries found. |
| `tested.capabilities` | Number of files with capabilities (0 if not checked). |
| `tested.sudo` | Whether `sudo -l` succeeded. |
| `tested.suid_complete` | False if any SUID scan timed out or failed. |
| `tested.capabilities_checked` | False on macOS, without `getcap`, or if `getcap` fails or times out. |
| `findings[].severity` | `critical`, `high` or `medium`. |
| `findings[].vector` | `sudo`, `suid` or `capabilities`. |
| `findings[].title` | Human-readable finding. |
| `findings[].detail` | The sudo rule or ownership/mode details. |
| `findings[].command` | A direct command when one is enough (for example `sudo -i`), else `null`. |
| `findings[].functions[].name` | GTFOBins function name. |
| `findings[].functions[].code` | Snippet rewritten for the discovered path. |
| `notes[]` | Warnings about skipped or incomplete checks. |

```json
{
  "version": "1.1",
  "platform": "linux",
  "user": "alice",
  "elapsed": 1.84,
  "tested": {
    "suid": 41,
    "capabilities": 6,
    "sudo": true,
    "suid_complete": true,
    "capabilities_checked": true
  },
  "findings": [
    {
      "severity": "high",
      "vector": "sudo",
      "title": "sudo /usr/bin/find (NOPASSWD)",
      "detail": "sudo rule: (root) NOPASSWD: /usr/bin/find",
      "command": null,
      "functions": [
        {
          "name": "shell",
          "code": "sudo /usr/bin/find . -exec /bin/sh \\; -quit"
        }
      ]
    }
  ],
  "notes": []
}
```

Optional filtering with `jq`:

```sh
gtfobins check --json | jq -r '.findings[] | "\(.severity)\t\(.title)"'
```

## Data and trust

- Data comes from `https://gtfobins.org/api.json` over HTTPS.
- It is cached at `$GTFOBINS_HOME/api.json`, defaulting to
  `~/.local/share/gtfobins/api.json`.
- The JSON is shape-checked before it is written and replaced atomically.
- `update` prints the file size and SHA-256. The data is **not signed or
  hash-pinned**, so the hash is for comparison, not verification.
- For a trusted or offline copy, put an `api.json` in `GTFOBINS_HOME` and do not
  run `update`:

```sh
mkdir -p ~/.gtfobins-data
cp /path/to/trusted/api.json ~/.gtfobins-data/api.json
GTFOBINS_HOME=~/.gtfobins-data gtfobins check
```

Other environment variables:

- `NO_COLOR` disables ANSI colors. Colors are only used on a TTY.

## Limitations

- This is not a complete privilege-escalation scanner. It only knows GTFOBins:
  no kernel exploits, cron jobs, services, credentials or configuration checks.
- `check` audits the current account. Run it as the user you are assessing; as
  root, `sudo -l` shows root's rules, not a normal user's.
- Sudo rules are only as visible as `sudo -l` makes them. Use `--ask-sudo`
  when your sudo setup requires a password.
- Restricted-argument sudo rules are left for manual review; the tool does not
  try to find a way to abuse the allowed arguments.
- SGID binaries are not scanned, and `/etc/sudoers` is not parsed directly.
- Capabilities are Linux-only and depend on `getcap`; a timeout leaves them
  unchecked rather than silently empty.
- The default SUID scan is fast but not exhaustive. Use `--full` to include
  home directories and other paths.
- A few GTFOBins snippets invoke a different program or assume you are already
  inside the target shell (for example `bash` history tricks or `egrep` using
  `grep`). Those are printed as documented and are not sudo-rewritten.
- On macOS, SIP and other protections may prevent an otherwise matching binary
  from being exploitable. Treat a finding as a lead, not as proof.
- Severity reflects the documented function class, not the actual
  exploitability of your exact version and configuration.

## Uninstall

```sh
rm -f ~/.local/bin/gtfobins
rm -rf ~/.local/share/gtfobins
```

If you set `GTFOBINS_HOME`, remove that directory instead of the default one.

## Development

The tool is deliberately one stdlib-only file (`gtfobins`). There is no build
step.

```sh
python3 -m py_compile gtfobins
python3 tests.py
```

`tests.py` covers sudo parsing (including NOPASSWD, runas and restricted args),
command rewriting, path/version normalization, capability gating, writable-SUID
logic and markdown cleanup.

## Credits

Data and snippets come from the [GTFOBins](https://gtfobins.org) project
([source](https://github.com/GTFOBins/GTFOBins.github.io)). This tool is not
affiliated with GTFOBins.
