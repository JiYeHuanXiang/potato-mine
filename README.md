# Potato Mine

**A self-protecting network watcher for desktop applications.**

**Version V0.01** · [中文文档](README.zh-CN.md)

Potato Mine is two small tools plus a browser console:

| Component | What it does |
|---|---|
| `netwatch.py` | Watches an application's **outbound TCP** connections: who it talks to and whether it reaches storage/logging/telemetry infrastructure beyond its documented services. Upload **byte counts** come from `deep` capture; `watch` and `record` track destinations. Pure observation — no interception. |
| `potato_mine.py` | ("The mine") Watches **the watcher**: if a process tries to copy or archive a guarded directory to somewhere outside it — the classic first step of exfiltrating evidence — the mine fires and records full forensics (name, PID, parent PID and image name, parent chain, command line, files touched). |
| `webui.py` | Browser console for both: choose the watched process and the host apps that must never be killed, toggle destination recording, add/remove guarded directories, set each one's trigger action (**warn** or **explode**), and run the same preflight checks as `--check`. |

The idea is simple: a monitoring tool that can be quietly bundled up and shipped
off the machine is not much of a monitoring tool. So the tool defends itself.

---

## Why

If you use a closed-source desktop app that has access to your files, and you
want to *verify* what it does, you need an independent observer on the machine.
But that observer itself becomes a target: the cheapest way to defeat it is to
copy it away (or tar it up and upload it) before anyone reads the results.

Potato Mine closes that loop. `netwatch.py` gives you evidence; `potato_mine.py`
makes sure the evidence stays where you put it.

---

## Requirements

- Windows 10/11
- Python 3.10+ (no third-party packages — standard library only)
- **Administrator rights** for `potato_mine.py` (it uses the Security audit log
  and file system audit ACEs) and for `netwatch.py deep` (packet capture).
  `netwatch.py watch` and `netwatch.py record` run without elevation.

---

## Quick start

### 1. Configure

```bash
copy watch-config.example.json watch-config.json
```

Then edit `watch-config.json`:

```json
{
  "monitor_processes": ["yourapp.exe"],
  "host_apps": ["yourapp.exe"],
  "marker_groups": [
    {
      "label": "cloud / object storage / CDN",
      "suspicious": true,
      "markers": [["example-cloud.com", "example cloud"], ["oss-", "object storage"]]
    },
    {
      "label": "ads / analytics / tracking",
      "suspicious": false,
      "markers": [["example-ads.example", "example ad network"]]
    }
  ],
  "cloud_cidrs": ["203.0.113.0/24"],
  "cloud_cidr_files": ["vendor-ranges.json"]
}
```

| Key | Meaning |
|---|---|
| `monitor_processes` | Executable names whose connections `netwatch` attributes. Electron apps spawn many child processes with the same name — all are included. |
| `host_apps` | Programs you use *to do your analysis* (your IDE, the app under study, remote-desktop tools). Processes in the mine's "host app" trees may **read** the guarded directory (it logs a warning) but are never killed for it. A copy launched as a separate executable with a different image name is still stopped by Layer B; a copy made inside the host app's own process only warns. |
| `marker_groups` | Domain markers, grouped and labelled. `suspicious: true` groups are treated as possible exfiltration destinations and land in `watch-candidates.txt` / `watch-blockable.txt`; `suspicious: false` groups are *labelled only* — they get their own section in the report and never enter the block list. That second kind is for ad/analytics/tracking infrastructure: worth seeing, not worth blocking. A hostname is classified by its **longest** matching marker. |
| `cloud_cidrs` | Optional. IP ranges used as a **fallback** — they only decide a destination's nature when no hostname could be resolved. Domain markers do the real work. |
| `cloud_cidr_files` | Optional. Extra files holding large CIDR lists, so a multi-thousand-range list does not turn this file into a wall. Ranges are merged at load and looked up by binary search, so tens of thousands of entries stay cheap. |
| `cloud_domain_markers` | Legacy flat list. Still works — it behaves like one `suspicious: true` group. |
| `service_kinds` | Optional. `[["substring", "label"]]` pairs to name known services in reports. |

Both tools load this file from their own directory. Nothing vendor-specific is
built into the code — and the lists themselves are yours to fill in: only the
schema ships with the repo.

**Rule categories are a fixed vocabulary.** `rules.txt` uses
`category | domain-pattern | note`, and the category must be one of the names in
`BENIGN_CATEGORIES` / `LABEL_ONLY_CATEGORIES` (or a name you deliberately want
flagged). An English label such as `Model API` is *not* benign and would be
exported for blocking. `rules.example.txt` lists the canonical names.

**Where the IP ranges come from.** Providers with an official list (AWS,
Google, Cloudflare) publish machine-readable data; for the rest, announced
prefixes can be pulled per ASN from RIPEstat. `vendor-fetch.py` (kept locally,
alongside your filled-in `vendors.local.json`) generates `vendor-ranges.json`
in that shape — rerun it every so often, since ranges drift.

### 2. Watch traffic

```bash
python netwatch.py watch                 # live view, no admin needed
python netwatch.py record                # long-term, accumulates destinations
python netwatch.py deep --seconds 300    # packet capture: real domains + byte counts
```

What writes what:

| Mode | Output |
|---|---|
| `watch` | Live console plus a timestamped `netwatch-*.jsonl` log. No cumulative exports. |
| `record` | `watch-ips.json`, `watch-candidates.txt`, `watch-blockable.txt`, `targets-alerts.txt`. Long-term destination tracking and block-list export. Does **not** measure bytes. |
| `deep` | `pktmon` capture, TLS SNI, and per-destination upload/download byte counts. Requires Administrator. |

`watch` and `record` sample the Windows TCP connection table. QUIC/HTTP3
traffic is UDP and is not sampled there; `deep` captures UDP packets but cannot
attribute them by process and cannot read QUIC's encrypted SNI, so a QUIC-only
application can look quieter than it is. Inbound connections are excluded: a
connection whose local port is also a listening port is treated as inbound.

### 3. Arm the mine

```bash
python potato_mine.py --check     # pre-flight: rights, audit policy, Security log, ACEs
python potato_mine.py --arm       # enable auditing: File System + Process Creation + audit ACE
python potato_mine.py --run       # run it (add --dry-run to only log, never kill)
```

Or use the launchers, which request elevation for you:

```bash
arm-potato.cmd                    # arm + run in the background
stop-potato.cmd                   # stop + disarm
```

`--strict-orphans` changes the default for processes whose parent has already
exited (unknown origin): the mine warns by default and kills only with this
flag. This applies to both detection layers.

Logs: `potato-mine.log` (every event, JSONL) and `potato-mine-kills.txt`
(kill records plus warn-mode triggers).

### 4. Or use the web console

```bash
python webui.py --open           # http://127.0.0.1:8756
webui.cmd                        # same, but requests elevation for you
```

The console wraps the above:

- **监视的主进程** — pick from the running process list (or type a name).
  Written back to `watch-config.json`, so `netwatch.py` uses it too.
- **宿主应用** — the never-kill list. Add or remove executable names; their
  reads are logged as warnings, never killed. A watched app usually belongs
  here too.
- **可疑上传行为监视** — on/off. When on, the console supervises
  `netwatch.py record` (accumulates outbound destinations and restarts it if it
  dies). It records **destinations**, not byte counts; use `deep` for volume.
- **触发地雷后的行为** — **警告** (record forensics only, kill nothing) or
  **爆炸** (kill the one process doing the moving). This is the default for
  *new* mines; each row can override it, and **应用到全部地雷** applies the
  current global choice to every existing row.
- **正在运行的地雷** — one row per guarded directory: `总计 x 个 · y 个正在运行`,
  each with its own 开关, its own 触发动作, and a badge for 运行中 /
  已布雷·守护未运行 / 未布雷·等待守护 / 已停用 / 目录缺失.
- **体检** — the same checks as `--check`: administrator rights, monitor
  processes, host apps, File System and Process Creation auditing, the 4688
  command-line policy, Security log readability and capacity, each mine's ACE,
  and whether a daemon is running.

The console listens on `127.0.0.1` by default — it can terminate processes, so do
not bind it to `0.0.0.0` or expose it to a network. Without Administrator it can
still edit configuration, but arming and running are refused and the page says
so. State-changing requests are rejected when the browser's `Origin` does not
match the console's own host, so another website cannot stop the mine with a
cross-site POST.

---

## How the mine works

Two independent layers, because neither one alone is sufficient:

**Layer A — read tripwire (file-system auditing).**
Arming adds a `ReadData / ListDirectory` audit ACE for `Everyone` to the
guarded directory (and propagates it to files that already exist — a detail that
programmatic ACL editing does not do for you). With the `File System` audit
sub-category enabled, Windows then writes an event **4663** for every content
read and directory listing under that path. This catches things a command-line
scan cannot: a programmatic `CopyFile`, an archiver walking the tree, a backup
agent. The mine reads the Security log in-process through `wevtapi.dll` and
classifies each event by the reader's process ancestry.

**Layer B — birth check (process-creation auditing).**
Process creation is logged by Windows (event 4688); the mine reads the Security
log in-process and inspects every new process. A command line that contains
(a) a path inside the guarded directory, (b) a copy/archive/upload verb, and
(c) a destination outside it — a path or a non-loopback URL — is stopped
immediately. Because the audit event carries the parent's image path and the
child's command line, this works even for processes that have already exited by
the time they are classified.

Both layers read the Security log **in-process** (a direct `wevtapi.dll` call),
not by shelling out: spawning a reader process per poll would itself generate
process-creation events, filling the fixed-size Security log until events are
overwritten before they can be read — a self-reinforcing feedback loop that
silently blinds the mine. A startup process snapshot does the same for
ancestry lookups and records the mine's own ancestor chain.

### Kill policy

| Situation | Action |
|---|---|
| Layer B: guarded-directory source **and** outside destination | **Kill**, unless a row below applies (host app, unknown origin, session shell) |
| Layer B: shells (cmd/bash/powershell) inside your own session tree | Warn only — the real mover gets born as its own process and is killed on its own event |
| Layer B: parent already exited, origin unknown | Warn only; `--strict-orphans` kills instead |
| Layer A: headless tree (`services.exe` / `svchost.exe` / `WmiPrvSE.exe` …) running a known copy/archive/upload tool | **Kill** |
| Layer A: your host apps, editors, terminals, file managers, antivirus, indexers | Warn only |
| Layer A: orphaned or unknown ancestry | Warn; `--strict-orphans` kills known copy/archive/upload tools |
| Any case where the process could not be identified | Warn only — missing information is never treated as evidence |

Every trigger is recorded in full, whichever action is set: process name, PID,
executable path, command line, **parent PID and parent image name**, full
ancestor chain, and the files it had touched.

### Blast radius (hard limits)

This is a defensive tool, so it is built to be boring about worst cases.
**爆炸 kills exactly one process**: `taskkill /F /PID <pid>`, never `/T`.

- **No parents.** The parent is usually a shell — your terminal, IDE, or remote
  desktop session. Killing it reaches outside the event and interrupts your own
  work. It is never touched.
- **No children.** A child of the mover may be entirely your own work, nothing
  to do with the copy. It is never touched.
- **No systems.** `SYSTEM_PROTECTED` covers `csrss.exe`, `lsass.exe`,
  `services.exe`, `wininit.exe`, `svchost.exe`, `explorer.exe`, `conhost.exe`
  and friends on a **never-kill** list, enforced at every code path.
- **No host apps.** Whatever you listed in `host_apps` — your editor, the app
  under study, your remote-desktop channel — is never killed. A copy launched as
  a separate executable with a different image name is still stopped by Layer B,
  which fires on the copy command itself; a copy made inside the host app's own
  process only warns.
- **No self-harm.** The mine records its own ancestor chain at startup and
  refuses to kill any of it; it cannot shoot the session it lives in.
- **No guessing.** When a process could not be identified (no image path, no
  ancestry), that is not evidence. The mine warns and stops there.
- Forensics compensate for the narrow blast radius: the record keeps the parent
  PID, the parent image name and the whole ancestor chain, so you can still see
  who sent the mover.
- Result: a worst-case misjudgement terminates one user-mode process that can
  simply be restarted. There is no irreversible action anywhere in the tool.

---

## Limitations (read these)

- **Static observation, not interception.** `netwatch` reports what the OS
  connection table and capture show. A short-lived connection may come and go
  between samples. Absence of evidence is not proof of absence.
- **TCP-centric sampling.** `watch` and `record` read the TCP connection table
  only. QUIC/HTTP3 traffic is UDP; `deep` captures it but cannot attribute it to
  a process and cannot read QUIC's encrypted SNI. Treat QUIC-heavy applications
  as partially observed.
- **Upload byte counts need `deep`.** `record` and the web console's upload
  monitor accumulate destinations and connection state, not megabytes.
- **Layer A latency.** The Security log is read about every 0.5-0.6 s. A single
  small file copied by a very short-lived process can complete before the
  classification runs. Bulk operations, directory walks, and archives — the
  shapes that matter for exfiltration — are interrupted mid-flight. Layer B
  closes most of that gap because the audit event carries the command line,
  so a copy is detected from its own creation, not from its reads.
- **Security log size matters.** Arming turns on process-creation auditing,
  which every process on the machine feeds. If your Security log is small and
  already near capacity, older events are overwritten in a circular log;
  `--check` reports the maximum size and record count. Raise the limit
  (`wevtutil sl Security /ms:67108864`) if you see gaps.
- **Layer B matches command lines.** Only real copy/archive/upload semantics
  count: `curl`/`wget` need an upload flag (`-T`, `-F`, `--form`,
  `--upload-file`, `--post-file`, `-d @file`). Access to a loopback URL is not
  an external destination. A shell that merely mentions a copy is treated as a
  shell-in-session and only warned about, and unknown ancestry warns by default,
  precisely to avoid false kills. The trade-off is that a mover whose parent
  exited and which carries no recognizable upload flag can be missed; use
  `--strict-orphans` when you would rather take that risk.
- **Administrator rights are required** for auditing, and anything running as
  SYSTEM can remove the ACEs. This raises the cost of a quiet grab; it does not
  make one impossible.
- **Not a sandbox.** Nothing here prevents network access. It observes and
  records.
- **Stop semantics.** A graceful stop (Ctrl+C or the web console's stop button)
  removes the audit ACEs and restores the 4688 command-line policy. A hard
  `--stop` uses `taskkill`, so the ACEs and policy can remain; run `--disarm`
  afterwards (`stop-potato.cmd` does). If the daemon is hosted by the web console,
  use the console's stop button — `--stop` would terminate the console process
  along with it. Audit sub-categories stay enabled either way, but without an
  ACE they produce no file-read events.

---

## Files

```
netwatch.py                  outbound-connection watcher
test_netwatch_classify.py    regression tests for destination classification
test_mine_core.py            regression tests for the mine engine
potato_mine.py               self-protection mine (CLI)
mine_core.py                 shared engine: mines, judgement, forensics
webui.py                     web console backend (stdlib HTTP + JSON API)
webui.html                   web console page
webui.cmd                    elevate + start the web console
watch-config.example.json    copy to watch-config.json and edit
mines.example.json           copy to mines.json and edit
rules.example.txt            destination classification rules (category|pattern|note)
exclusions.example.txt       benign destinations to ignore
arm-potato.cmd               elevate + arm + run (background)
stop-potato.cmd              stop + disarm
```

Runtime artifacts (created on first run, not tracked): `watch-config.json`,
`mines.json`, `potato-mine.log`, `potato-mine-kills.txt`, `potato-mine.pid`,
`potato-mine-auditpol-state.json`, `netwatch-webui.log`, `watch-ips.json`,
`watch-candidates.txt`, `watch-blockable.txt`, `targets-alerts.txt`,
`rules.txt`, `exclusions.txt`, `netwatch-*.jsonl`,
`targets-capture-*.etl/.pcapng`, `_sni.*`.

`mines.json` is yours to edit. Existing `_comment` / `_field_guide` keys are
preserved when the console saves the file, and an explicit empty `mines: []`
means "no mines" — only a missing `mines.json` falls back to guarding the tool
directory.

---

## License

MIT — see [LICENSE](LICENSE).
