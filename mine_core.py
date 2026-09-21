#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mine_core.py —— Potato Mine 引擎（多守护目录 / 可配置触发动作）

从 potato_mine.py 抽出的公共引擎，命令行与 Web UI 共用同一份判定逻辑。

概念
----
地雷（mine）= 一个被守护的目录。可以有任意多个，每个独立布雷、独立开关。

  守护目录 A  [开关]   触发动作: 警告
  守护目录 B  [开关]   触发动作: 爆炸

「监视的主进程」（watch-config.json 的 monitor_processes）是被观察的应用；
「监控可疑上传行为」托管 netwatch.py record 子进程（累积出站目标与上传量）；
「触发后的动作」决定地雷炸响时做什么：
    警告 (warn)    —— 只记全档，不终止任何进程
    爆炸 (explode) —— 终止执行搬运的那一个进程

击杀语义（硬边界）
------------------
只终止【执行操作的那个进程本身】：taskkill /F /PID <pid>，不带 /T。
    · 不向上杀父进程：父进程是会话的壳（终端/IDE/远控），杀了等于把手伸到
      事件之外，还会打断用户自己的工作。
    · 不向下连带子进程：子进程可能完全是用户的其它工作，与本次搬运无关。
    · 代价由取证补偿：进程名 / PID / 父进程 PID 与映像名 / 完整祖先链 /
      命令行 / 映像路径 / 触碰的文件 / 目的地，全部落盘。

两层探测
--------
Layer A 读绊网（SACL 审计）：守护目录上 Everyone:ReadData 审计 ACE →
    Security 日志 4663。程序化复制、打包器枚举目录都会留痕，不依赖命令行。
Layer B 出生检查（4688）：新进程的命令行同时满足
    (a) 引用守护目录路径 (b) 复制/打包/上传动词 (c) 目录外的目的地
    → 立即触发，与其祖先是谁无关。
"""

import ctypes
from ctypes import wintypes
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
WATCH_CONFIG = os.path.join(HERE, "watch-config.json")
MINES_JSON = os.path.join(HERE, "mines.json")
NETWATCH = os.path.join(HERE, "netwatch.py")
PID_FILE = os.path.join(HERE, "potato-mine.pid")
LOG_JSONL = os.path.join(HERE, "potato-mine.log")
LOG_KILL = os.path.join(HERE, "potato-mine-kills.txt")
AUDIT_STATE = os.path.join(HERE, "potato-mine-auditpol-state.json")
UPLOAD_LOG = os.path.join(HERE, "netwatch-webui.log")

# 审计子类别 GUID（locale 无关）
FS_SUBCAT = "{0CCE921D-69AE-11D9-BED3-505054503030}"      # File System
PROC_SUBCAT = "{0CCE922B-69AE-11D9-BED3-505054503030}"    # Process Creation
# 注意必须带冒号（PSDrive 形式）；不带冒号会被当成相对文件路径解析
CMD_POLICY_KEY = (r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"
                  r"\Policies\System\Audit")
CMD_POLICY_VAL = "ProcessCreationIncludeCmdLine_Enabled"
EVERYONE_SID = "S-1-1-0"

DANGEROUS = {
    "python.exe", "pythonw.exe", "py.exe", "node.exe", "nodejs.exe",
    "tar.exe", "7z.exe", "7za.exe", "7zr.exe", "zip.exe", "rar.exe",
    "winrar.exe", "xcopy.exe", "robocopy.exe", "scp.exe", "sftp.exe",
    "rsync.exe", "curl.exe", "wget.exe", "pwsh.exe", "powershell.exe",
    "cmd.exe", "mshta.exe", "wscript.exe", "cscript.exe", "bash.exe",
}
WARN_SET = {
    "explorer.exe", "userinit.exe", "searchindexer.exe",
    "searchprotocolhost.exe", "searchfilterhost.exe", "dllhost.exe",
    "sihost.exe", "runtimebroker.exe", "shellexperiencehost.exe",
    "startmenuexperiencehost.exe", "textinputhost.exe",
    "applicationframehost.exe", "svchost.exe", "conhost.exe", "dwm.exe",
    "ctfmon.exe", "fontdrvhost.exe", "msmpeng.exe", "nissrv.exe",
    "onedrive.exe",
}
SYSTEM_PROTECTED = {
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "logonui.exe", "fontdrvhost.exe",
    "dwm.exe", "explorer.exe", "conhost.exe", "svchost.exe",
}
BASE_TREE_WARN_ROOTS = {
    "explorer.exe", "userinit.exe",
    "sihost.exe", "windowsterminal.exe", "openconsole.exe", "wt.exe",
    "powershell_ise.exe",
    "code.exe", "cursor.exe", "devenv.exe",
}
TREE_HEADLESS_ROOTS = {"services.exe", "svchost.exe", "wininit.exe",
                       "wmiprvse.exe", "taskhostw.exe"}

SHELL_NAMES = {"bash.exe", "sh.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
               "wscript.exe", "cscript.exe", "mshta.exe", "fish.exe", "zsh.exe"}

COPY_VERBS = re.compile(
    r"(?i)\b(copy-item|compress-archive|move-item|expand-archive|robocopy|"
    r"xcopy|copy|cp|mv|move|tar|7z|7za|zip|rar|scp|rsync|curl|wget|"
    r"uploadfile|shutil\.copy|copyfile|copytree|make_archive|"
    r"--upload-file|-T\s|-F\s|--form\b|-f\s|put_object|upload_file)"
)
PATHISH = re.compile(r'(?:"([^"]+)"|(\S+))')
_ABS_WIN = re.compile(r"^[A-Za-z]:[\\/]|^\\\\")
# Git-Bash 风格的根路径 /d/backup 算目的地；/E、/Y 这类开关不算。
# 判据：第一个路径段长度 >= 2 —— 命令行开关几乎都是单字母。
_ABS_POSIX_ROOTED = re.compile(r"^/([^/]{2,})(/|$)")


def is_abs_path(tok):
    """是否为绝对目的地（Windows 盘符 / UNC / Git-Bash 根路径）。

    刻意不把 /E、/Y、/MIR 这类开关当成路径：否则目录内的 copy ... /Y
    会被判定为"目录外目的地"，误杀用户自己的备份操作。宁可漏判一个
    /tmp/x 式的 Unix 单段路径，也不误杀。
    """
    if _ABS_WIN.match(tok):
        return True
    return bool(_ABS_POSIX_ROOTED.match(tok))

PS_UTF8 = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"

ACTION_WARN = "warn"
ACTION_EXPLODE = "explode"

DEFAULT_SETTINGS = {
    "upload_monitor": False,
    "action": ACTION_EXPLODE,
    "daemon_enabled": False,
}

# 绝对不可击杀的 PID：System / Idle 以及过小的系统 PID。
# 名称保护靠 SYSTEM_PROTECTED，这里再兜一层底，两者都不依赖对方正确。
PROTECTED_PIDS = {0, 4}


# ---------------------------------------------------------------- 基础工具

def norm_path(p):
    """统一为小写、反斜杠、无尾部分隔符的形式，用于前缀比较。"""
    return os.path.abspath(p).replace("/", "\\").rstrip("\\").lower()


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def log(kind, **kw):
    rec = {"ts": datetime.now().isoformat(timespec="milliseconds"),
           "kind": kind}
    rec.update(kw)
    line = json.dumps(rec, ensure_ascii=False)
    with open(LOG_JSONL, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    if kind in ("KILL", "KILL_DRYRUN", "ARM", "DISARM", "START", "STOP"):
        with open(LOG_KILL, "a", encoding="utf-8") as f:
            f.write(f"[{rec['ts']}] {kind}: "
                    f"{json.dumps(kw, ensure_ascii=False)}\n")
    print(line, flush=True)


def ps_run(cmd, timeout=60):
    r = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-Command", PS_UTF8 + cmd],
        capture_output=True, timeout=timeout,
        encoding="utf-8", errors="replace")
    return r.returncode, r.stdout or "", r.stderr or ""


def load_config():
    try:
        with open(WATCH_CONFIG, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except Exception:
        return {}


def save_config(cfg):
    tmp = WATCH_CONFIG + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=1)
    os.replace(tmp, WATCH_CONFIG)


def load_host_apps(cfg=None):
    """宿主应用：在其中分析这些文件的程序（IDE/被观察应用/远控）。"""
    cfg = cfg if cfg is not None else load_config()
    try:
        return {str(x).lower() for x in cfg.get("host_apps", [])}
    except Exception:
        return set()


# ---------------------------------------------------------------- 布雷 / 排雷

def sacl_present(target):
    rc, out, _ = ps_run(
        f"(Get-Acl -Audit '{target}').GetAuditRules($true,$true,"
        f"[System.Security.Principal.SecurityIdentifier]) | ForEach-Object "
        f"{{ $_.IdentityReference.Value + ':' + $_.FileSystemRights.ToString() }}")
    return (EVERYONE_SID in out
            and "ReadData" in out.replace(" ", "")), out.strip()


def arm_sacl(target):
    """给目录加 Everyone:ReadData(成功) 审计 ACE。幂等。

    坑（真实踩过）：FileSystemAuditRule 的 identity 不能传 SID 字符串。
    传到 .NET 时会尝试把 "S-1-1-0" 当 NTAccount 翻译，抛
    「未能转换部分或所有标识引用」；而这只是语句级终止错误——后面的
    'ADDED' 仍会打印、exit code 仍是 0，于是布雷失败会被完全掩盖。
    必须显式构造 SecurityIdentifier 对象，并对结果做一次回读校验。
    """
    ps = (
        f"$sid = New-Object System.Security.Principal.SecurityIdentifier("
        f"'{EVERYONE_SID}'); "
        f"$r = New-Object System.Security.AccessControl.FileSystemAuditRule("
        f"$sid,'ReadData','ObjectInherit,ContainerInherit','None','Success'); "
        f"$a = Get-Acl -Audit '{target}'; "
        f"if (-not ($a.GetAuditRules($true,$true,"
        f"[System.Security.Principal.SecurityIdentifier]) | Where-Object "
        f"{{ $_.IdentityReference.Value -eq '{EVERYONE_SID}' -and "
        f"($_.FileSystemRights -band "
        f"[System.Security.AccessControl.FileSystemRights]::ReadData) }})) "
        f"{{ $a.AddAuditRule($r); Set-Acl -Path '{target}' "
        f"-AclObject $a; 'ADDED' }} "
        f"else {{ 'PRESENT' }}"
    )
    rc, out, err = ps_run(ps)
    if rc != 0 or not ("ADDED" in out or "PRESENT" in out):
        return False, f"SACL 失败: rc={rc} out={out.strip()!r} err={err.strip()!r}"
    ok, detail = sacl_present(target)
    return ok, ("ADDED(已校验)" if ok else f"ADDED 但回读未生效: {detail[:80]}")


def disarm_sacl(target):
    ps = (
        f"$a = Get-Acl -Audit '{target}'; "
        f"$rules = @($a.GetAuditRules($true,$true,"
        f"[System.Security.Principal.SecurityIdentifier]) | Where-Object "
        f"{{ $_.IdentityReference.Value -eq '{EVERYONE_SID}' -and "
        f"($_.FileSystemRights -band "
        f"[System.Security.AccessControl.FileSystemRights]::ReadData) }}); "
        f"foreach ($r in $rules) {{ [void]$a.RemoveAuditRuleSpecific($r) }}; "
        f"if ($rules.Count) {{ Set-Acl -Path '{target}' -AclObject $a }}; "
        f"'REMOVED=' + $rules.Count"
    )
    rc, out, err = ps_run(ps)
    return rc == 0, f"rc={rc} {out.strip()} {err.strip()}"


def propagate_sacl(target):
    """向既有子项显式传播审计 ACE（程序化 Set-Acl 不会自动传播到已存在
    的子文件；新建文件会自动继承）。跳过 pristine/ 等厂商载荷副本目录。"""
    ps = (
        f"$root='{target}'; $n=0; $dirs=0; $fail=0; "
        f"$sid=New-Object System.Security.Principal.SecurityIdentifier("
        f"'{EVERYONE_SID}'); "
        f"$r1=New-Object System.Security.AccessControl.FileSystemAuditRule("
        f"$sid,'ReadData','None','None','Success'); "
        f"$r2=New-Object System.Security.AccessControl.FileSystemAuditRule("
        f"$sid,'ReadData','ObjectInherit,ContainerInherit',"
        f"'None','Success'); "
        f"Get-ChildItem -LiteralPath $root -Recurse -Force | ForEach-Object {{ "
        f"  if ($_.FullName -match '\\\\pristine\\\\') {{ return }} "
        f"  try {{ "
        f"    $a = Get-Acl -Audit -LiteralPath $_.FullName; "
        f"    $has = $a.GetAuditRules($true,$true,"
        f"[System.Security.Principal.SecurityIdentifier]) | Where-Object "
        f"{{ $_.IdentityReference.Value -eq '{EVERYONE_SID}' -and "
        f"($_.FileSystemRights -band 1) }}; "
        f"    if (-not $has) {{ "
        f"      if ($_.PSIsContainer) {{ $a.AddAuditRule($r2); $dirs++ }} "
        f"      else {{ $a.AddAuditRule($r1); $n++ }}; "
        f"      Set-Acl -LiteralPath $_.FullName -AclObject $a }} "
        f"  }} catch {{ $fail++ }} "
        f"}}; "
        f"'PROPAGATED files=' + $n + ' dirs=' + $dirs + ' fail=' + $fail"
    )
    rc, out, err = ps_run(ps, timeout=300)
    return rc == 0, f"{out.strip()} {err.strip()[:120]}".strip()


def sync_arm(mines):
    """按每个地雷的 enabled 拉齐系统布雷状态：启用→布雷，停用→排雷。

    刻意做成模块级函数：布雷/排雷是纯系统操作，不该依赖守护进程是否
    在跑。控制台停了守护、只改配置的场景同样要立刻生效。
    返回 {id: armed}。
    """
    out = {}
    for m in list(mines):
        if m.enabled and m.exists:
            ok, msg = arm_sacl(m.path)
            if ok:
                propagate_sacl(m.path)
            present, detail = sacl_present(m.path)
            m.armed = present
            m.note = "" if present else f"布雷未生效：{detail[:80]}"
        else:
            if m.armed or sacl_present(m.path)[0]:
                disarm_sacl(m.path)
            m.armed = False
            if not m.exists:
                m.note = "目录不存在"
        out[m.id] = m.armed
    return out


def disarm_all(mines):
    """移除这些地雷的审计 ACE（不改 enabled 标志）。"""
    for m in list(mines):
        try:
            if m.armed or sacl_present(m.path)[0]:
                disarm_sacl(m.path)
        except Exception:
            pass
        m.armed = False


def read_cmd_policy():
    """读 4688 命令行记录策略当前值；缺失返回 None。"""
    rc, out, _ = ps_run(
        f"$p='{CMD_POLICY_KEY}'; "
        f"if (Test-Path $p) {{ (Get-ItemProperty -Path $p "
        f"-Name {CMD_POLICY_VAL} -ErrorAction SilentlyContinue)."
        f"{CMD_POLICY_VAL} }} else {{ 'MISSING' }}")
    return out.strip() or "MISSING"


def set_cmd_policy(value):
    rc, out, _ = ps_run(
        f"New-Item -Path '{CMD_POLICY_KEY}' -Force | Out-Null; "
        f"Set-ItemProperty -Path '{CMD_POLICY_KEY}' "
        f"-Name {CMD_POLICY_VAL} -Value {int(value)} -Type DWord; 'OK'")
    return "OK" in out


def auditpol_get():
    """读文件系统审计子类别（/r = CSV）。auditpol 按系统 ANSI 代码页输出，
    必须按 mbcs 解码，否则中文状态会变成乱码。"""
    r = subprocess.run(["auditpol", "/get", "/subcategory:" + FS_SUBCAT,
                        "/r"], capture_output=True)
    enc = "mbcs"
    return (r.returncode,
            (r.stdout or b"").decode(enc, "replace"),
            (r.stderr or b"").decode(enc, "replace"))


def auditpol_fs_enabled():
    """(是否启用, 说明)。"""
    rc, out, err = auditpol_get()
    if rc != 0:
        return False, "auditpol 不可读 — " + (err or out).strip()[:80]
    tail = out.strip().splitlines()[-1] if out.strip() else ""
    on = ("成功" in tail) or ("success" in tail.lower())
    return on, ("已启用（Success）" if on else "未启用（需 --arm）")


def ensure_audit_policy():
    """启用审计子类别与 4688 命令行记录（幂等；记录原值以便排雷时还原）。"""
    rc, out, _ = auditpol_get()
    if rc != 0:
        return False, "auditpol 读取失败：" + out
    if not os.path.exists(AUDIT_STATE):
        with open(AUDIT_STATE, "w", encoding="utf-8") as f:
            json.dump({"fs_audit_before_raw": out.strip()},
                      f, ensure_ascii=False)
    r = subprocess.run(["auditpol", "/set", "/subcategory:" + FS_SUBCAT,
                        "/success:enable"], capture_output=True,
                       errors="replace")
    if r.returncode != 0:
        return False, "auditpol 启用失败：" + (r.stderr or "")
    r = subprocess.run(["auditpol", "/set", "/subcategory:" + PROC_SUBCAT,
                        "/success:enable"], capture_output=True,
                       errors="replace")
    if r.returncode != 0:
        return False, "进程创建审计启用失败：" + (r.stderr or "")
    prev = read_cmd_policy()
    state = {}
    if os.path.exists(AUDIT_STATE):
        try:
            with open(AUDIT_STATE, encoding="utf-8") as f:
                state = json.load(f)
        except Exception:
            state = {}
    if "cmd_policy_before" not in state and prev in ("0", "1"):
        state["cmd_policy_before"] = int(prev)
        with open(AUDIT_STATE, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False)
    set_cmd_policy(1)
    return True, f"cmdline policy {prev} -> 1"


def restore_cmd_policy():
    """排雷时把 4688 命令行策略还原为布雷前的值。"""
    state = {}
    if os.path.exists(AUDIT_STATE):
        try:
            with open(AUDIT_STATE, encoding="utf-8") as f:
                state = json.load(f)
        except Exception:
            state = {}
    before = state.get("cmd_policy_before")
    restored = "unchanged"
    if before in (0, 1):
        set_cmd_policy(before)
        restored = f"restored to {before}"
    return restored


# ---------------------------------------------------------------- 实例管理

def read_pid():
    try:
        with open(PID_FILE, encoding="utf-8") as f:
            v = int(f.read().strip())
        r = subprocess.run(["tasklist", "/fi", f"PID eq {v}"],
                           capture_output=True, errors="replace")
        return v if str(v) in (r.stdout or "") else None
    except Exception:
        return None


def write_pid(pid):
    with open(PID_FILE, "w", encoding="utf-8") as f:
        f.write(str(pid))


def clear_pid(pid=None):
    """只在 pid 文件里记的是自己时才删除，避免误删别人的占位。"""
    try:
        with open(PID_FILE, encoding="utf-8") as f:
            cur = int(f.read().strip())
    except Exception:
        return
    if pid is None or cur == pid:
        try:
            os.remove(PID_FILE)
        except OSError:
            pass


def find_other_instances():
    """找出本脚本的其它运行实例（pid 文件会被后来者覆盖，不能只信它）。"""
    rc, out, _ = ps_run(
        "Get-CimInstance Win32_Process -Filter \"Name='python.exe' or "
        "Name='pythonw.exe' or Name='py.exe'\" | Where-Object { "
        "$_.CommandLine -like '*potato_mine.py*' -and "
        "$_.CommandLine -like '*--run*' } | "
        "Select-Object -ExpandProperty ProcessId", timeout=30)
    pids = []
    for tok in out.split():
        tok = tok.strip()
        if tok.isdigit() and int(tok) != os.getpid():
            pids.append(int(tok))
    return pids


# ---------------------------------------------------------------- 事件日志读取
# 直接调用 wevtapi.dll（进程内读），不用 wevtutil 子进程：
# 每 spawn 一个 wevtutil 都会产生新的 4688 事件（自身 + conhost），
# 轮询越快日志被填得越快，最终 Security 日志在容量上循环覆盖，
# 事件还没读到就被冲掉——一个自我加剧的反馈环。进程内读取没有这个代价。

_EVT_QUERY_CHANNEL = 0x1
_EVT_QUERY_REVERSE = 0x200
_EVT_QUERY_TOLERATE = 0x1000
_EVT_RENDER_XML = 1

_wevtapi = ctypes.WinDLL("wevtapi")
_wevtapi.EvtQuery.restype = wintypes.HANDLE
_wevtapi.EvtQuery.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR,
                              wintypes.LPCWSTR, wintypes.DWORD]
_wevtapi.EvtNext.restype = wintypes.BOOL
_wevtapi.EvtNext.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                             ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
                             wintypes.BOOL, ctypes.POINTER(wintypes.DWORD)]
_wevtapi.EvtRender.restype = wintypes.BOOL
_wevtapi.EvtRender.argtypes = [wintypes.HANDLE, wintypes.HANDLE,
                               wintypes.DWORD, wintypes.DWORD,
                               ctypes.c_void_p,
                               ctypes.POINTER(wintypes.DWORD),
                               ctypes.POINTER(wintypes.DWORD)]
_wevtapi.EvtClose.restype = wintypes.BOOL
_wevtapi.EvtClose.argtypes = [wintypes.HANDLE]


def _render_event(ev):
    used = wintypes.DWORD(0)
    props = wintypes.DWORD(0)
    _wevtapi.EvtRender(None, ev, _EVT_RENDER_XML, 0, None,
                       ctypes.byref(used), ctypes.byref(props))
    if not used.value:
        return ""
    buf = ctypes.create_unicode_buffer(used.value)
    if not _wevtapi.EvtRender(None, ev, _EVT_RENDER_XML, used.value, buf,
                              ctypes.byref(used), ctypes.byref(props)):
        return ""
    return buf.value


def read_new_events(xpath, last_rid, limit=512, channel="Security"):
    """按记录号增量读取（反向读取，遇到已知记录号即停）。"""
    hq = _wevtapi.EvtQuery(None, channel, xpath,
                           _EVT_QUERY_CHANNEL | _EVT_QUERY_REVERSE
                           | _EVT_QUERY_TOLERATE)
    if not hq:
        return []
    out = []
    try:
        batch = 64
        arr = (wintypes.HANDLE * batch)()
        done = False
        while not done and len(out) < limit:
            returned = wintypes.DWORD(0)
            if not _wevtapi.EvtNext(hq, batch, arr, 0, False,
                                    ctypes.byref(returned)):
                break
            if not returned.value:
                break
            for i in range(returned.value):
                ev = arr[i]
                try:
                    xml = _render_event(ev)
                finally:
                    _wevtapi.EvtClose(ev)
                if not xml:
                    continue
                m = re.search(r"<EventRecordID>(\d+)</EventRecordID>", xml)
                if not m:
                    continue
                rid = int(m.group(1))
                if rid <= last_rid:
                    done = True
                    continue
                out.append((rid, xml))
    finally:
        _wevtapi.EvtClose(hq)
    return out


def parse_4688(xml):
    def field(name):
        m = re.search("<Data Name=[\"']" + name + "[\"']>([^<]*)</Data>",
                      xml)
        return m.group(1) if m else ""

    def num(v):
        v = (v or "").strip()
        try:
            return int(v, 16) if v.lower().startswith("0x") else int(v)
        except ValueError:
            return 0

    exe = field("NewProcessName")
    return {
        "pid": num(field("NewProcessId")),
        "ppid": num(field("ProcessId")),
        "name": os.path.basename(exe).lower() if exe else "",
        "exe": exe,
        "cmdline": field("CommandLine"),
        "parent_exe": field("ParentProcessName"),
    }


def field_of(xml, name):
    m = re.search("<Data Name=[\"']" + name + "[\"']>([^<]*)</Data>", xml)
    return m.group(1) if m else ""


# ---------------------------------------------------------------- 地雷注册表

class Mine:
    """一个守护目录。判定逻辑由 MineSupervisor 统一驱动。"""

    def __init__(self, mine_id, path, action=ACTION_EXPLODE, enabled=True,
                 note=""):
        self.id = mine_id
        self.path = path
        self.action = action if action in (ACTION_WARN, ACTION_EXPLODE) \
            else ACTION_EXPLODE
        self.enabled = bool(enabled)
        self.note = note
        # 运行时状态（不落盘）
        self.armed = False
        self.triggers = 0

    @property
    def key(self):
        return norm_path(self.path)

    @property
    def exists(self):
        return os.path.isdir(self.path)

    def owns_path(self, p):
        """p（已归一化小写）是否在本守护目录内。"""
        k = self.key
        return p == k or p.startswith(k + "\\")

    def owns_cmd(self, cmd):
        """命令行是否引用了本守护目录。要求路径后接分隔符/引号/行尾，
        避免 a\\dir 误配 a\\dir2。"""
        norm = cmd.lower().replace("/", "\\")
        k = self.key
        i = norm.find(k)
        while i != -1:
            j = i + len(k)
            if j >= len(norm) or norm[j] in '\\/\"\'`:,;)]} \t\n':
                return True
            i = norm.find(k, i + 1)
        return False

    def to_dict(self):
        return {
            "id": self.id,
            "path": self.path,
            "action": self.action,
            "enabled": self.enabled,
            "armed": self.armed,
            "exists": self.exists,
            "note": self.note,
            "triggers": self.triggers,
        }


def _new_id(key):
    import hashlib
    return "m-" + hashlib.sha1(key.encode("utf-8")).hexdigest()[:8]


class MineRegistry:
    """mines.json —— 地雷清单与全局设置。

    watch-config.json 仍是「监视的主进程 / 宿主应用」的唯一来源（netwatch.py
    也读它），这里只存与地雷本身有关的东西：清单、上传监视开关、默认动作。
    """

    def __init__(self, path=MINES_JSON):
        self.path = path
        self.settings = dict(DEFAULT_SETTINGS)
        self.mines = []
        self.load()

    def load(self):
        data = {}
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            data = {}
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}
        st = data.get("settings")
        if isinstance(st, dict):
            for k in DEFAULT_SETTINGS:
                if k in st:
                    self.settings[k] = st[k]
        self.mines = []
        for item in data.get("mines", []) or []:
            if not isinstance(item, dict):
                continue
            p = str(item.get("path") or "").strip()
            if not p:
                continue
            key = norm_path(p)
            self.mines.append(
                Mine(item.get("id") or _new_id(key), p,
                     item.get("action") or self.settings.get("action",
                                                             ACTION_EXPLODE),
                     bool(item.get("enabled", True)), item.get("note") or ""))
        self.ensure_default()

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({
                "settings": self.settings,
                "mines": [{"id": m.id, "path": m.path, "action": m.action,
                           "enabled": m.enabled, "note": m.note}
                          for m in self.mines],
            }, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.path)

    def ensure_default(self):
        """旧版行为：没有配置时守护脚本自己所在的目录。"""
        if not self.mines:
            self.mines.append(Mine(_new_id(norm_path(HERE)), HERE))

    def get(self, mine_id):
        for m in self.mines:
            if m.id == mine_id:
                return m
        return None

    def add(self, path, action=None, enabled=True):
        p = os.path.abspath(os.path.expanduser(str(path)).strip())
        key = norm_path(p)
        for m in self.mines:
            if m.key == key:
                return m, False
        m = Mine(_new_id(key), p, action or self.settings.get(
            "action", ACTION_EXPLODE), enabled)
        self.mines.append(m)
        return m, True

    def remove(self, mine_id):
        m = self.get(mine_id)
        if m is None:
            return None
        self.mines = [x for x in self.mines if x.id != mine_id]
        return m

    def update_settings(self, **kw):
        for k, v in kw.items():
            if k in DEFAULT_SETTINGS:
                self.settings[k] = v


# ---------------------------------------------------------------- 上传监视

class UploadMonitor:
    """托管 netwatch.py record —— 可疑上传行为的长期观察者。

    它累积出站目标、上传字节数，并把「非已知服务」的新目标写进
    watch-candidates.txt / watch-blockable.txt。抓包（SNI 补全）只在管理员
    下自动开启。
    """

    def __init__(self, outdir=HERE, interval=3.0, sni_every=None):
        self.outdir = outdir
        self.interval = interval
        self.sni_every = sni_every
        self.proc = None
        self.log_handle = None
        self.started_at = None
        self.last_error = ""

    @property
    def running(self):
        return self.proc is not None and self.proc.poll() is None

    def start(self):
        if self.running:
            return True, "已在运行"
        if not os.path.exists(NETWATCH):
            self.last_error = f"未找到 {NETWATCH}"
            return False, self.last_error
        cfg = load_config()
        if not cfg.get("monitor_processes"):
            self.last_error = "未配置「监视的主进程」，无法监视上传行为"
            return False, self.last_error
        cmd = [sys.executable, "-u", NETWATCH, "record",
               "--outdir", self.outdir, "--interval", str(self.interval)]
        if self.sni_every and is_admin():
            cmd += ["--sni-every", str(self.sni_every), "--sni-seconds", "15"]
        try:
            self.log_handle = open(UPLOAD_LOG, "a", encoding="utf-8")
            self.proc = subprocess.Popen(
                cmd, stdout=self.log_handle, stderr=subprocess.STDOUT,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except Exception as ex:
            self.last_error = f"启动失败: {ex}"
            return False, self.last_error
        self.started_at = datetime.now()
        log("UPLOAD_START", pid=self.proc.pid, outdir=self.outdir)
        return True, f"PID {self.proc.pid}"

    def stop(self):
        p, self.proc = self.proc, None
        if p is None:
            return
        try:
            p.terminate()
        except Exception:
            pass
        try:
            p.wait(timeout=5)
        except Exception:
            try:
                p.kill()
                p.wait(timeout=5)
            except Exception:
                pass
        if self.log_handle:
            try:
                self.log_handle.close()
            except Exception:
                pass
            self.log_handle = None
        self.started_at = None
        log("UPLOAD_STOP")

    def watchdog(self):
        """进程意外退出就拉起来（镜像 record-forever.cmd 的行为）。"""
        if self.running or not self._wanted():
            return
        self.start()

    def _wanted(self):
        try:
            return bool(MineRegistry().settings.get("upload_monitor"))
        except Exception:
            return False


# ---------------------------------------------------------------- 监督进程

class MineSupervisor(threading.Thread):
    """在单个进程内托管全部地雷。

    Security 日志全局只跑一份轮询（两个线程），事件按守护目录分发给对应
    地雷；这样 N 个地雷不会因为 N 个进程各自轮询而把日志读出竞态。
    """

    def __init__(self, registry=None, strict_orphans=False, force_warn=False):
        super().__init__(daemon=True)
        self.registry = registry or MineRegistry()
        self.strict_orphans = strict_orphans
        self.force_warn = force_warn
        self.self_pid = os.getpid()
        self.proc = {}                 # pid -> {ppid,name,cmdline,exe,created}
        self._rate = {}                # (mine,layer,pid[,file]) -> last ts
        self._lookup_missed = set()    # 已尝试补查仍缺失的 pid
        self.event_q = queue.Queue()
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self.mines = []
        self.host_apps = set()
        self.tree_warn_roots = set()
        self.protected = set()
        self.self_ancestors = {self.self_pid}
        self.running = False
        self.started_at = None
        self.last_error = ""
        self.phase = "未启动"
        # 先灌一次配置：保护名单与地雷清单必须在任何判定之前就位
        # （进程快照很慢，留给 run() 去做）
        self.reload()

    # ---- 配置同步 ----
    def reload(self):
        """重新读取设置与地雷清单。

        与注册表共用同一批 Mine 对象：sync_arm() 写下的布雷状态对外部
        （Web UI）立即可见，不需要再各自查一遍系统。
        """
        self.registry.load()
        cfg = load_config()
        self.host_apps = load_host_apps(cfg)
        self.tree_warn_roots = BASE_TREE_WARN_ROOTS | self.host_apps
        self.protected = SYSTEM_PROTECTED | self.host_apps
        with self._lock:
            self.mines = list(self.registry.mines)
        return self.mines

    def sync_arm(self):
        """已启用 → 布雷；已停用 → 排雷。返回 {id: armed}。"""
        return sync_arm(self.mines)

    def disarm_all(self):
        disarm_all(self.mines)

    def active(self):
        with self._lock:
            return [m for m in self.mines
                    if m.enabled and m.exists and m.armed]

    # ---- 进程表 ----
    def seed_snapshot(self):
        rc, out, _ = ps_run(
            "Get-CimInstance Win32_Process | Select-Object ProcessId,"
            "ParentProcessId,Name,CommandLine,ExecutablePath,CreationDate | "
            "ConvertTo-Json -Compress", timeout=90)
        if rc != 0 or not out.strip():
            print("[WARN] 初始进程快照失败，祖先判定退化为 origin 规则",
                  flush=True)
            return False
        try:
            arr = json.loads(out)
        except json.JSONDecodeError:
            print("[WARN] 进程快照解析失败", flush=True)
            return False
        if isinstance(arr, dict):
            arr = [arr]
        for p in arr:
            pid = p.get("ProcessId")
            if not pid:
                continue
            self.proc[int(pid)] = {
                "ppid": int(p.get("ParentProcessId") or 0),
                "name": (p.get("Name") or "").lower(),
                "cmdline": p.get("CommandLine") or "",
                "exe": p.get("ExecutablePath") or "",
                "created": str(p.get("CreationDate") or ""),
            }
        return True

    def cim_lookup(self, pids, force=False):
        """对进程表里**缺失或不完整**的 pid 做实时 CIM 补查。

        不完整的条目（有名字但查不到命令行/映像路径，常见于刚出生就被
        查询的短命进程）也要补——否则祖先分类与命令行取证的输入会一直是空的。
        """
        def _incomplete(p):
            info = self.proc.get(p)
            return info is None or not (info.get("cmdline") or info.get("exe"))

        todo = [p for p in pids if p and p > 4 and _incomplete(p)
                and (force or p not in self._lookup_missed)]
        if not todo:
            return
        for p in todo:
            self._lookup_missed.add(p)
            if force:
                self._lookup_missed.discard(p)
        flt = " OR ".join(f"ProcessId={p}" for p in todo[:8])
        rc, out, _ = ps_run(
            f"Get-CimInstance Win32_Process -Filter '{flt}' | Select-Object "
            "ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath | "
            "ConvertTo-Json -Compress", timeout=15)
        if rc != 0 or not out.strip():
            return
        try:
            arr = json.loads(out)
        except json.JSONDecodeError:
            return
        if isinstance(arr, dict):
            arr = [arr]
        for p in arr:
            pid = p.get("ProcessId")
            if not pid:
                continue
            self._lookup_missed.discard(int(pid))
            self.proc[int(pid)] = {
                "ppid": int(p.get("ParentProcessId") or 0),
                "name": (p.get("Name") or "").lower(),
                "cmdline": p.get("CommandLine") or "",
                "exe": p.get("ExecutablePath") or "",
                "created": str(p.get("CreationDate") or ""),
            }

    def ancestry(self, pid):
        """返回 (链, 根类别)：session/headless/unknown/self。
        遇到表里没有的中间父进程时实时补查一次（WmiPrvSE 这类按需启动
        的进程不在初始快照里，否则无头树会被误判成孤儿）。"""
        chain = []
        cur = pid
        seen = set()
        while cur and cur not in seen and len(chain) < 16:
            seen.add(cur)
            if cur == self.self_pid:
                return chain, "self"
            if cur not in self.proc:
                self.cim_lookup([cur])
            info = self.proc.get(cur)
            if info is None:
                break
            chain.append((cur, info["name"]))
            if info["name"] in self.tree_warn_roots:
                return chain, "session"
            if info["name"] in TREE_HEADLESS_ROOTS:
                return chain, "headless"
            nxt = info["ppid"]
            if nxt not in self.proc and info.get("ppid_name"):
                # 父进程已退出：用出生事件记录的父映像名兜底分类
                pname = info["ppid_name"]
                chain.append((nxt, pname + "(已退出)"))
                if pname in self.tree_warn_roots:
                    return chain, "session"
                if pname in TREE_HEADLESS_ROOTS:
                    return chain, "headless"
                break
            cur = nxt
        return chain, "unknown"

    # ---- 触发 ----
    def fire(self, mine, pid, why, evidence):
        """地雷炸响：按地雷配置的动作决定是「警告」还是「爆炸」。

        取证一律全量落盘，与动作无关。爆炸只终止执行操作的那一个进程
        （taskkill /F /PID，不带 /T）：不向上杀父进程，也不向下带子进程。
        """
        info = self.proc.get(pid, {})
        name = info.get("name") or "?"
        if pid == self.self_pid or name in self.protected \
                or pid in PROTECTED_PIDS or pid < 8:
            log("WARN", mine=mine.id, pid=pid, name=name,
                note="protected/self，拒绝击杀", why=why, **evidence)
            return "refused"
        if pid in self.self_ancestors:
            log("WARN", mine=mine.id, pid=pid, name=name,
                note="自身祖先链，拒绝击杀", why=why, **evidence)
            return "refused"
        chain, root = self.ancestry(pid)
        mine.triggers += 1
        forensics = {
            "mine": mine.id,
            "path": mine.path,
            "pid": pid,
            "name": name,
            "ppid": info.get("ppid"),
            "parent": info.get("ppid_name") or
                      (self.proc.get(info.get("ppid") or 0, {})
                       .get("name") or ""),
            "exe": info.get("exe"),
            "cmdline": (info.get("cmdline") or "")[:2000],
            "created": info.get("created"),
            "ancestry": " <- ".join(f"{p}:{n}" for p, n in chain) or "(未知)",
            "file": evidence.get("file") or evidence.get("path") or "",
            "reason": why,
            "evidence": evidence,
        }
        if self.force_warn or mine.action == ACTION_WARN:
            log("KILL_DRYRUN", action=ACTION_WARN, tree_root=root,
                **forensics)
            return "warn"
        r = subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                           capture_output=True, errors="replace")
        log("KILL", taskkill_rc=r.returncode, action=ACTION_EXPLODE,
            tree_root=root, **forensics)
        return "explode"

    # ---- Layer B：出生检查 ----
    def register_birth(self, ev):
        """出生事件只登记一次：进程表是全局的，与守护目录无关。"""
        pid = int(ev.get("pid") or 0)
        parent_exe = ev.get("parent_exe") or ""
        self.proc[pid] = {
            "ppid": int(ev.get("ppid") or 0),
            "name": (ev.get("name") or "").lower(),
            "cmdline": ev.get("cmdline") or "",
            "exe": ev.get("exe") or "",
            "created": "",
            # 父进程映像名：父进程可能早已退出，这是唯一还能拿到的来源线索
            "ppid_name": os.path.basename(parent_exe).lower(),
        }
        # 刻意不做同步查询：消费循环是单线程的，一次 PowerShell/CIM 调用
        # （最坏 15 秒超时）会把后续所有事件堵死。4688 已带齐需要的字段。
        info = self.proc[pid]
        if os.environ.get("POTATO_DEBUG_BIRTH"):
            log("PROC_BORN", pid=pid, ppid=info["ppid"], name=info["name"],
                has_cmd=bool(info["cmdline"]))
        # 预热祖先链：新进程出生时父进程通常还活着，此刻解析最可靠。
        # 否则短命进程在 4663 事件到达时已退出，来源会退化成"未知"。
        self.ancestry(pid)

    def check_birth(self, mine, ev):
        pid = int(ev.get("pid") or 0)
        info = self.proc.get(pid)
        if not info:
            return
        name, cmd = info["name"], info["cmdline"]
        if not cmd or pid == self.self_pid or name in WARN_SET:
            return                    # 资源管理器等 GUI 复制=用户亲手操作
        if not mine.owns_cmd(cmd):
            return                    # 不涉及本守护目录
        if not COPY_VERBS.search(cmd.lower()):
            return                    # 无复制/上传语义
        dests = []
        exelow = (info.get("exe") or "").lower()
        key = mine.key
        for m in PATHISH.finditer(cmd):
            tok = (m.group(1) or m.group(2) or "").strip('"')
            if not tok:
                continue
            tnorm = tok.lower().replace("/", "\\")
            if tnorm == key or tnorm.startswith(key + "\\"):
                continue              # 目录内=源或中间产物
            if tok.lower() == exelow or tok.lower().endswith("\\" + name):
                continue              # 进程自身映像路径
            if re.match(r"(?i)^(https?|ftp|sftp)://", tok) or \
                    re.match(r"(?i)^[a-z0-9._-]+@[a-z0-9.-]+:", tok) or \
                    is_abs_path(tok):
                dests.append(tok)
        if not dests:
            return
        if name in SHELL_NAMES:
            chain, root = self.ancestry(pid)
            if root in ("session", "self"):
                # 命令行里"提到"搬运 ≠ 执行搬运：会话树内的 shell 只告警，
                # 真正的执行者（robocopy/cmd 子进程等）会以自身出生事件被击杀
                log("WARN", mine=mine.id, pid=pid, name=name, tree_root=root,
                    note="会话树内 shell 命令含搬运语义",
                    dest=dests[:4], cmdline_head=cmd[:300])
                return
        self.fire(mine, pid,
                  "LayerB 出生搬运：守护目录源 + 目录外目的地",
                  {"dest": dests[:4], "cmdline_head": cmd[:300]})

    # ---- Layer A：读绊网 ----
    def check_read(self, mine, xml):
        objname = field_of(xml, "ObjectName")
        pid_s = field_of(xml, "ProcessId")
        pname = field_of(xml, "ProcessName").lower()
        access = field_of(xml, "AccessList")
        # 实测 %%4416 = ReadData/ListDirectory（%%4417 是 WriteData）
        if not pid_s or "4416" not in (access or ""):
            return                     # 只要内容读(ReadData/ListDirectory)
        pid = int(pid_s, 16) if pid_s.lower().startswith("0x") else int(pid_s)
        if pid == self.self_pid:
            return
        objlow = objname.lower().replace("/", "\\")
        if not mine.owns_path(objlow):
            return                     # 不属于本守护目录
        key = (mine.id, "A", pid, objlow)
        t = time.time()
        if t - self._rate.get(key, 0) < 10:
            return
        self._rate[key] = t
        info = self.proc.get(pid, {})
        name = info.get("name") or (pname or "?").split("\\")[-1]
        chain, root = self.ancestry(pid)
        evidence = {
            "file": objname, "access": "ReadData/ListDirectory",
            "cmdline": (info.get("cmdline") or "")[:600],
            "ancestry": " <- ".join(f"{p}:{n}" for p, n in chain) or "(未知)",
        }
        if name in WARN_SET or root == "self":
            log("WARN", mine=mine.id, pid=pid, name=name, tree_root=root,
                **evidence)
            return
        if root == "session":
            log("WARN", mine=mine.id, pid=pid, name=name, tree_root=root,
                note="会话树内读取（其搬运由 LayerB 击杀）", **evidence)
            return
        if (name in DANGEROUS or name in SHELL_NAMES) and root == "headless":
            self.fire(mine, pid, "LayerA 高危进程无头树读取守护目录", evidence)
            return
        if name in DANGEROUS and root == "unknown" and self.strict_orphans:
            self.fire(mine, pid,
                      "LayerA 高危孤儿进程读取守护目录(strict-orphans)",
                      evidence)
            return
        # 其余一律只告警。**信息缺失绝不击杀**：无法确定来源/映像路径时
        # "不知道"不等于"可疑"，宁漏杀不误杀（威力上限约束）。
        log("WARN", mine=mine.id, pid=pid, name=name, tree_root=root,
            note=("证据不足（未能确定进程来源），仅告警"
                  if (not chain or root == "unknown") else ""),
            **evidence)

    # ---- 轮询线程 ----
    def poll_4688_forever(self):
        """进程创建事件（含命令行与父子映像路径）。"""
        last = 0
        for rid, _ in read_new_events("*[System[(EventID=4688)]]", 0,
                                      limit=1):
            last = max(last, rid)
        while not self._stop.is_set():
            try:
                for rid, xml in read_new_events("*[System[(EventID=4688)]]",
                                                last):
                    last = max(last, rid)
                    self.event_q.put(("BIRTH", xml))
            except Exception as ex:
                log("POLL_ERR", error=str(ex), source="4688")
            time.sleep(0.4)

    def poll_4663_forever(self):
        """文件读审计事件（只关心任一守护目录内的读）。"""
        last = 0
        for rid, _ in read_new_events("*[System[(EventID=4663)]]", 0,
                                      limit=1):
            last = max(last, rid)
        while not self._stop.is_set():
            try:
                for rid, ev in read_new_events("*[System[(EventID=4663)]]",
                                               last):
                    last = max(last, rid)
                    dm = re.search(
                        "<Data Name=[\"']ObjectName[\"']>([^<]*)</Data>", ev)
                    if not dm:
                        continue
                    objlow = dm.group(1).lower().replace("/", "\\")
                    if not any(m.owns_path(objlow) for m in self.active()):
                        continue
                    am = re.search(
                        "<Data Name=[\"']AccessList[\"']>([^<]*)</Data>", ev)
                    if not am or "4416" not in am.group(1):
                        continue
                    self.event_q.put(("4663", ev))
            except Exception as ex:
                log("POLL_ERR", error=str(ex), source="4663")
            time.sleep(0.6)

    # ---- 主循环 ----
    def run(self):
        if not is_admin():
            self.last_error = "需要管理员权限（Security 日志 / SACL）"
            self.phase = "启动失败：需要管理员权限"
            log("START_FAILED", error=self.last_error)
            return
        self.phase = "读取配置"
        self.reload()
        self.phase = "启用审计策略"
        ok, msg = ensure_audit_policy()
        if not ok:
            self.last_error = msg
            self.phase = "启动失败：" + msg
            log("START_FAILED", error=msg)
            return
        self.phase = "布雷（首次较慢）"
        self.sync_arm()
        write_pid(self.self_pid)
        self.running = True
        self.started_at = datetime.now()
        self.phase = "运行中"
        log("START", pid=self.self_pid, force_warn=self.force_warn,
            mines=[{"id": m.id, "path": m.path, "action": m.action,
                    "armed": m.armed} for m in self.mines])
        threading.Thread(target=self.poll_4688_forever, daemon=True).start()
        threading.Thread(target=self.poll_4663_forever, daemon=True).start()
        try:
            # 单线程消费：出生与读绊网事件严格串行处理，不并发改进程表
            while not self._stop.is_set():
                try:
                    kind, payload = self.event_q.get(timeout=1.0)
                except queue.Empty:
                    continue
                try:
                    if kind == "BIRTH":
                        ev = parse_4688(payload)
                        self.register_birth(ev)
                        for m in self.active():
                            self.check_birth(m, ev)
                    elif kind == "4663":
                        for m in self.active():
                            self.check_read(m, payload)
                except Exception as ex:  # 单条事件失败不倒地雷
                    log("EVENT_ERR", error=str(ex), head=str(payload)[:200])
        finally:
            self.running = False
            self.disarm_all()
            clear_pid(self.self_pid)
            log("STOP", pid=self.self_pid)

    def stop(self, timeout=10):
        self._stop.set()
        if self.is_alive():
            self.join(timeout=timeout)


# ---------------------------------------------------------------- 体检

def run_checks(registry=None):
    """体检：权限 / 审计策略 / 事件日志 / 各地雷的布雷状态。

    返回 [{"name","ok","detail","mine"?}]，命令行与 Web UI 共用。
    注意：会真实查询 SACL（每个地雷一次 PowerShell 调用），较慢。
    """
    reg = registry or MineRegistry()
    cfg = load_config()
    hosts = load_host_apps(cfg)
    mons = cfg.get("monitor_processes") or []
    checks = [
        {"name": "管理员权限", "ok": is_admin(),
         "detail": "已具备" if is_admin() else "缺少（--arm/--run/守护需要）"},
        {"name": "监视的主进程", "ok": bool(mons),
         "detail": ", ".join(str(x) for x in mons) or "未配置（netwatch 无法归因）"},
        {"name": "宿主应用", "ok": bool(hosts),
         "detail": ", ".join(sorted(hosts)) or "未配置（其读取只告警）"},
    ]

    rc, out, err = auditpol_get()
    checks.append({"name": "auditpol 文件系统审计", "ok": rc == 0,
                   "detail": (out.strip().splitlines()[-1][:100] if out.strip()
                              else (err or "不可读").strip()[:100])})
    on, detail = auditpol_fs_enabled()
    checks[-1]["ok"] = rc == 0 and on
    checks[-1]["detail"] = detail

    pol = read_cmd_policy()
    checks.append({"name": "4688 命令行记录", "ok": pol == "1",
                   "detail": f"当前值 {pol}（布雷后应为 1）"})

    rc, out, err = ps_run(
        "Get-WinEvent -LogName Security -MaxEvents 1 | Out-Null")
    checks.append({"name": "Security 日志", "ok": rc == 0,
                   "detail": "可读" if rc == 0
                             else "不可读 — " + err.strip()[:80]})

    for m in reg.mines:
        if not m.exists:
            m.armed = False
            checks.append({"name": f"守护目录 {m.path}", "ok": False,
                           "detail": "目录不存在", "mine": m.id})
            continue
        present, detail = sacl_present(m.path)
        m.armed = present
        if present:
            state = "已布雷"
        elif not m.enabled:
            state = "未布雷（地雷已停用）"
        else:
            state = f"未布雷 — 未检测到 ACE [{detail[:60]}]"
        checks.append({
            "name": f"守护目录 {m.path}",
            "ok": present,
            "detail": state,
            "mine": m.id,
        })

    pid = read_pid()
    others = find_other_instances()
    checks.append({
        "name": "地雷进程",
        "ok": bool(pid),
        "detail": f"运行中 PID {pid}" if pid else
                  ("未运行" + (f"（另有命令行实例 {others}）" if others else "")),
    })
    return checks
