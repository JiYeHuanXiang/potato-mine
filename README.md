# Potato Mine

**A self-protecting network watcher for desktop applications.**
**一个会保护自己的应用流量监视器。**

Potato Mine is two small tools that work together:

| Component | What it does |
|---|---|
| `netwatch.py` | Watches an application's **outbound** connections: who it talks to, how much it uploads, and whether it ever reaches storage/logging/telemetry infrastructure beyond its documented services. Pure observation — no interception. |
| `potato_mine.py` | ("The mine") Watches **the watcher**: if any process tries to copy or archive this tool directory to somewhere outside it — the classic first step of exfiltrating evidence — the mine fires and records full forensics (name, PID, parent PID and image name, parent chain, command line, files touched). |
| `webui.py` | Browser console for both: choose the process to watch, toggle suspicious-upload monitoring, add/remove guarded directories, and set each one's trigger action (**warn** or **explode**) with its own on/off switch. |

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
  `netwatch.py watch` runs without elevation.

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
  "cloud_cidrs": ["203.0.113.0/24"],
  "cloud_domain_markers": ["example-cloud.com"]
}
```

| Key | Meaning |
|---|---|
| `monitor_processes` | Executable names whose connections `netwatch` attributes. Electron apps spawn many child processes with the same name — all are included. |
| `host_apps` | Programs you use *to do your analysis* (your IDE, the app under study, remote-desktop tools). Processes in the mine's "host app" trees may **read** the tool directory (it logs a warning) but are never killed for it. Their copy operations are still killed. |
| `cloud_cidrs` | Optional. IP ranges belonging to the cloud provider you care about, used as a fallback when a connection's hostname is unknown. |
| `cloud_domain_markers` | Optional. Domain substrings that identify that provider (e.g. object-storage hostnames). |
| `service_kinds` | Optional. `[["substring", "label"]]` pairs to name known services in reports. |

Both tools load this file from their own directory. Nothing vendor-specific is
built into the code.

### 2. Watch traffic

```bash
python netwatch.py watch          # live view, no admin needed
python netwatch.py deep --seconds 300   # packet capture: real domains + byte counts
```

Reports land in `watch-ips.json`, `watch-candidates.txt`, `watch-blockable.txt`.

### 3. Arm the mine

```bash
python potato_mine.py --check     # pre-flight: rights, audit ACE, event log, config
python potato_mine.py --arm       # enable auditing: File System + Process Creation + audit ACE
python potato_mine.py --run       # run it (add --dry-run to only log, never kill)
```

Or use the launchers, which request elevation for you:

```bash
arm-potato.cmd                    # arm + run in the background
stop-potato.cmd                   # stop + disarm
```

Logs: `potato-mine.log` (every event, JSONL) and `potato-mine-kills.txt`
(kill/interrupt records only).

### 4. Or use the web console

```bash
python webui.py --open           # http://127.0.0.1:8756
webui.cmd                        # same, but requests elevation for you
```

The console wraps all of the above:

- **监视的主进程** — pick from the running process list (or type a name).
  Written back to `watch-config.json`, so `netwatch.py` uses it too.
- **监控可疑上传行为** — on/off. When on, the console supervises
  `netwatch.py record` (accumulates outbound targets and upload volume, and
  restarts it if it dies).
- **触发地雷后的行为** — **警告** (record forensics only, kill nothing) or
  **爆炸** (kill the one process doing the moving). Applies to all mines, and
  each row can override it.
- **正在运行的地雷** — one row per guarded directory: `总计 x 个 · y 个正在运行`,
  each with its own 开关, its own 触发动作, and a badge for 运行中 / 已布雷 /
  目录缺失.

The console listens on `127.0.0.1` only — it can terminate processes, so do
not bind it to `0.0.0.0` or expose it to a network. Arming and running need
Administrator; without it the console stays read-only and says so.

---

## How the mine works

Two independent layers, because neither one alone is sufficient:

**Layer A — read tripwire (file-system auditing).**
Arming adds a `ReadData / ListDirectory` audit ACE for `Everyone` to the tool
directory (and propagates it to files that already exist — a detail that
programmatic ACL editing does not do for you). With the `File System` audit
sub-category enabled, Windows then writes an event **4663** for every content
read and directory listing under that path. This catches things a command-line
scan cannot: a programmatic `CopyFile`, an archiver walking the tree, a backup
agent. The mine polls the Security log via `wevtutil` and classifies each event
by the reader's process ancestry.

**Layer B — birth check (process-creation auditing).**
Process creation is logged by Windows (event 4688); the mine reads the Security
log in-process and inspects every new process. A command line that contains
(a) a path inside the tool directory, (b) a copy/archive/upload verb, and
(c) a destination outside it — a path or a URL — is killed immediately,
regardless of who its parent is. Because the audit event carries the parent's
image path and the child's command line, this works even for processes that
have already exited by the time they are classified.

Both layers read the Security log **in-process** (a direct `wevtapi.dll` call),
not by shelling out: spawning a reader process per poll would itself generate
process-creation events, filling the fixed-size Security log until events are
overwritten before they can be read — a self-reinforcing feedback loop that
silently blinds the mine.

### Kill policy

| Situation | Action |
|---|---|
| Layer B: tool-dir source **and** outside destination | **Kill** (GUI file-manager copies excluded — that's you, by hand) |
| Layer B: shells (cmd/bash/powershell) inside your own session tree | Warn only — the real mover gets born as its own process and is killed on its own event |
| Layer A: headless tree (`services.exe` / `svchost.exe` / `WmiPrvSE.exe` …) reading the directory | **Kill** |
| Layer A: unknown-origin process from a non-system path | **Kill** |
| Layer A: your host apps, editors, terminals, file managers, antivirus, indexers | Warn only |
| Layer A: orphaned ancestry (intermediate parent already exited) | Warn (add `--strict-orphans` to kill instead) |
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
  under study, your remote-desktop channel — is never killed. Their *copies*
  are still stopped by Layer B, which fires on the copy command itself.
- **No self-harm.** The mine refuses to kill its own ancestor chain; it cannot
  shoot the session it lives in.
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
- **Layer A latency.** The Security log is read about every 0.5-0.6 s. A single
  small file copied by a very short-lived process can complete before the
  classification runs. Bulk operations, directory walks, and archives — the
  shapes that matter for exfiltration — are interrupted mid-flight. Layer B
  closes most of that gap because the audit event carries the command line,
  so a copy is detected from its own creation, not from its reads.
- **Security log size matters.** Arming turns on process-creation auditing,
  which every process on the machine feeds. If your Security log is small and
  already near capacity, older events are overwritten in a circular log;
  `--check` reports the log's state. Raise the limit
  (`wevtutil sl Security /ms:67108864`) if you see gaps.
- **Layer B matches command lines.** A command line that merely *mentions* a
  copy (a shell running a script that contains the word `copy`) is treated as
  a shell-in-session and only warned about, precisely to avoid false kills.
- **Administrator rights are required** for auditing, and anything running as
  SYSTEM can remove the ACEs. This raises the cost of a quiet grab; it does not
  make one impossible.
- **Not a sandbox.** Nothing here prevents network access. It observes and
  records.

---

## Files

```
netwatch.py                  outbound-connection watcher
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
`netwatch-webui.log`, `watch-ips.json`, `rules.txt`, `exclusions.txt`.

---

## License

MIT — see [LICENSE](LICENSE).

---

## 中文速览

Potato Mine 是两个互相配合的小工具，外加一个网页控制台：

- **`netwatch.py`** —— 监视目标应用的**出站**连接：它联系谁、上传了多少、
  有没有碰对象存储/日志/遥测基础设施。纯观察，不拦截。
- **`potato_mine.py`（土豆地雷）** —— 监视"监视工具本身"。任何进程试图把
  工具目录复制或打包到目录之外（窃取证据的第一步），地雷立即触发并留下
  完整取证：进程名、PID、父进程 PID 与映像名、祖先链、命令行、触碰的文件。
- **`webui.py`（网页控制台）** —— 选择要监视的主进程、开关「可疑上传行为」
  监视、为每个守护目录设置「警告 / 爆炸」并单独开关。

**为什么需要它**：能被悄悄打包带走的监视工具，算不上监视工具。

**威力上限（硬边界）—— 爆炸只杀一个进程**：`taskkill /F /PID <pid>`，
不带 `/T`，不连带子进程。

- 不杀父进程：父进程通常是会话的壳（终端/IDE/远控），杀它会把手伸到事件
  之外，还会打断你自己的工作。
- 不杀子进程：子进程可能是你自己的其它工作，与本次搬运无关。
- 系统命脉（`csrss.exe`/`lsass.exe`/`services.exe`/`svchost.exe`/
  `explorer.exe` 等）与你在 `host_apps` 里配置的宿主应用，在任何代码
  路径下都不可被杀；地雷也拒绝击杀自己的祖先链。
- 信息不足时只告警：查不到映像路径或祖先来源，「不知道」不等于「可疑」。
- 取证补上收窄的代价：记录里保留父进程 PID、父映像名与完整祖先链。
- 因此最坏情况只是某个用户态进程被终止（可重开），**不存在不可逆破坏路径**。

**布雷做了什么**：`--arm` 会启用两个审计子类别（File System + Process
Creation）与 4688 命令行记录策略，并给守护目录加上 `Everyone:ReadData`
审计 ACE（含对既有文件的显式传播）。`--disarm` 会移除 ACE 并把命令行
策略还原为原值；审计子类别保留启用（无 ACE 时不产生任何事件，属无害常态）。

**配置**：

- 复制 `watch-config.example.json` 为 `watch-config.json`，填入要监视的
  可执行文件名（`monitor_processes`）与你日常分析的宿主应用
  （`host_apps`，其读取只告警不击杀）。
- 复制 `mines.example.json` 为 `mines.json`，列出要守护的目录（每项一个
  地雷，含 `action` 与 `enabled`）。没有 `mines.json` 时沿用旧行为：
  守护脚本所在目录。

**用法**：

```bash
python netwatch.py watch                       # 实时观察（免管理员）
python netwatch.py deep --seconds 300          # 抓包：真实域名 + 上传字节数
python potato_mine.py --check                  # 体检
python potato_mine.py --arm                    # 布雷（审计 + SACL）
python potato_mine.py --run --dry-run          # 试运行：只记录不击杀
python potato_mine.py --list                   # 列出地雷清单

python webui.py --open                         # 网页控制台（127.0.0.1:8756）
```

日志：`potato-mine.log`（JSONL 全事件）、`potato-mine-kills.txt`（击杀档案）。
控制台只监听回环地址：它能终止进程，不要绑定到 `0.0.0.0` 或暴露到网络。
