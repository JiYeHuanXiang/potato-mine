#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Potato Mine（土豆地雷）—— 监视工具自保护地雷（2026-09-22）

威胁模型：
  流量监视工具本身就是"谁在偷数据"的证据。若本机进程被驱动去搬运这套
  工具（复制/打包到工作区外目录 = 外传准备），地雷在搬运途中击杀目标
  进程并留全档（进程名/PID/父进程链/命令行/触碰的文件）。

双层探测：
  Layer A 读绊网（SACL 审计）：
    对工具目录设 Everyone:ReadData/ListDirectory(成功) 审计 ACE，
    监听 Security 日志 4663 —— 任何内容读取（含程序化 fs.copyFile、
    打包器枚举目录）都会留痕，不依赖命令行。
  Layer B 出生检查（Win32_ProcessStartTrace）：
    新进程出生时分析命令行：引用了工具目录路径 + 复制/打包/上传动词 +
    存在目录外的目的地（绝对路径或 URL）→ 击杀（无论祖先是谁）。

击杀策略（防误伤自己的工作会话，刻意保守）：
  Layer B（有目的地铁证）          ：一律击杀（资源管理器 GUI 复制除外）。
  Layer A（仅读证据）：
    自己/自己的子孙                 ：忽略
    已知良性（资源管理器/杀软/索引/网盘/系统进程）：告警
    宿主应用/编辑器/终端/远控通道树（会话内分析、用户亲手操作）：告警
    无头树（services/svchost/wmiprvse 下）且高危名称：击杀
    祖先链断裂（中间父进程已退出）  ：告警（orphan 标记，
                                      --strict-orphans 可改击杀）
    非系统目录来源的未知进程        ：击杀
高危名称：python/pythonw/py/node/tar/7z/zip/rar/xcopy/robocopy/scp/rsync/
          curl/wget/pwsh/powershell/cmd/mshta/wscript/cscript/bash

威力上限（硬边界）：击杀只作用于"正在读取守护目录的目标进程"本身及其
子树（taskkill /T），绝不向上杀父进程；系统命脉/宿主应用/资源管理器
（explorer）在任何路径下都不可被本工具击杀；地雷自身的祖先链同样拒绝。
因此即使用户亲手复制搬运被误判，最坏结果也只是某个工具进程被终止
（含至多 explorer 意外重启），不存在数据不可逆破坏路径。

配置：同目录 watch-config.json（可选）：
  {"host_apps": ["yourapp.exe"], ...}
宿主应用（你日常在其中分析这些文件的程序，如 IDE/AI 助手/远控）加入
host_apps 后，其进程树内的"读"只告警不击杀；"搬运"仍由 Layer B 击杀。

用法（管理员）：
  python potato_mine.py --check            体检：权限/SACL/日志/运行状态
  python potato_mine.py --arm              布雷：auditpol + SACL（幂等）
  python potato_mine.py --run [--dry-run]  运行地雷（dry-run 只记录不击杀）
  python potato_mine.py --disarm           排雷：移除 SACL
  python potato_mine.py --status           查看运行状态
  python potato_mine.py --stop             停止运行中的地雷

日志：potato-mine.log（JSONL 全事件）/ potato-mine-kills.txt（击杀档案）
"""

import argparse
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
WATCH_ROOT = HERE                      # 默认守护脚本所在目录
PID_FILE = os.path.join(HERE, "potato-mine.pid")
LOG_JSONL = os.path.join(HERE, "potato-mine.log")
LOG_KILL = os.path.join(HERE, "potato-mine-kills.txt")
AUDIT_STATE = os.path.join(HERE, "potato-mine-auditpol-state.json")
WATCH_CONFIG = os.path.join(HERE, "watch-config.json")

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
ABS_PATH = re.compile(r"^[A-Za-z]:[\\/]|^\\\\|^/")

PS_UTF8 = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"


def load_host_apps():
    """从 watch-config.json 读宿主应用名（不点名任何具体软件）。"""
    try:
        with open(WATCH_CONFIG, encoding="utf-8") as f:
            cfg = json.load(f)
        return {str(x).lower() for x in cfg.get("host_apps", [])}
    except FileNotFoundError:
        return set()
    except Exception:
        return set()


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


# ---------------------------------------------------------------- SACL 布雷/排雷

def sacl_present():
    rc, out, _ = ps_run(
        f"(Get-Acl -Audit '{WATCH_ROOT}').GetAuditRules($true,$true,"
        f"[System.Security.Principal.SecurityIdentifier]) | ForEach-Object "
        f"{{ $_.IdentityReference.Value + ':' + $_.FileSystemRights.ToString() }}")
    return (EVERYONE_SID in out
            and "ReadData" in out.replace(" ", "")), out.strip()


def arm_sacl():
    ps = (
        f"$r = New-Object System.Security.AccessControl.FileSystemAuditRule("
        f"'{EVERYONE_SID}','ReadData','ObjectInherit,ContainerInherit',"
        f"'None','Success'); "
        f"$a = Get-Acl -Audit '{WATCH_ROOT}'; "
        f"if (-not ($a.GetAuditRules($true,$true,"
        f"[System.Security.Principal.SecurityIdentifier]) | Where-Object "
        f"{{ $_.IdentityReference.Value -eq '{EVERYONE_SID}' -and "
        f"($_.FileSystemRights -band "
        f"[System.Security.AccessControl.FileSystemRights]::ReadData) }})) "
        f"{{ $a.AddAuditRule($r); Set-Acl -Path '{WATCH_ROOT}' "
        f"-AclObject $a; 'ADDED' }} "
        f"else {{ 'PRESENT' }}"
    )
    rc, out, err = ps_run(ps)
    if rc != 0 or not ("ADDED" in out or "PRESENT" in out):
        return False, f"SACL 失败: rc={rc} out={out.strip()!r} err={err.strip()!r}"
    return True, out.strip()


def disarm_sacl():
    ps = (
        f"$a = Get-Acl -Audit '{WATCH_ROOT}'; "
        f"$rules = @($a.GetAuditRules($true,$true,"
        f"[System.Security.Principal.SecurityIdentifier]) | Where-Object "
        f"{{ $_.IdentityReference.Value -eq '{EVERYONE_SID}' -and "
        f"($_.FileSystemRights -band "
        f"[System.Security.AccessControl.FileSystemRights]::ReadData) }}); "
        f"foreach ($r in $rules) {{ [void]$a.RemoveAuditRuleSpecific($r) }}; "
        f"if ($rules.Count) {{ Set-Acl -Path '{WATCH_ROOT}' -AclObject $a }}; "
        f"'REMOVED=' + $rules.Count"
    )
    rc, out, err = ps_run(ps)
    return rc == 0, f"rc={rc} {out.strip()} {err.strip()}"


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
    r = subprocess.run(["auditpol", "/get", "/subcategory:" + FS_SUBCAT,
                        "/r"], capture_output=True, errors="replace")
    return r.returncode, (r.stdout or ""), (r.stderr or "")


def propagate_sacl():
    """向既有子项显式传播审计 ACE（程序化 Set-Acl 不会自动传播到已存在
    的子文件；新建文件会自动继承）。跳过 pristine/ 等厂商载荷副本目录。"""
    ps = (
        f"$root='{WATCH_ROOT}'; $n=0; $dirs=0; $fail=0; "
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


def cmd_arm():
    if not is_admin():
        sys.exit("需要管理员权限（SACL/auditpol/Security 日志）。")
    rc, out, _ = auditpol_get()
    if rc != 0:
        sys.exit("auditpol 读取失败：" + out)
    if not os.path.exists(AUDIT_STATE):
        with open(AUDIT_STATE, "w", encoding="utf-8") as f:
            json.dump({"fs_audit_before_raw": out.strip()},
                      f, ensure_ascii=False)
    r = subprocess.run(["auditpol", "/set", "/subcategory:" + FS_SUBCAT,
                        "/success:enable"],
                       capture_output=True, errors="replace")
    if r.returncode != 0:
        sys.exit("auditpol 启用失败：" + (r.stderr or ""))
    r = subprocess.run(["auditpol", "/set", "/subcategory:" + PROC_SUBCAT,
                        "/success:enable"],
                       capture_output=True, errors="replace")
    if r.returncode != 0:
        sys.exit("进程创建审计启用失败：" + (r.stderr or "").decode("utf-8", "replace"))
    # 命令行记录策略（4688 才有 CommandLine 字段）；记录原值以便排雷时还原
    prev_cmd_policy = read_cmd_policy()
    state = {}
    if os.path.exists(AUDIT_STATE):
        try:
            with open(AUDIT_STATE, encoding="utf-8") as f:
                state = json.load(f)
        except Exception:
            state = {}
    if "cmd_policy_before" not in state and prev_cmd_policy in ("0", "1"):
        state["cmd_policy_before"] = int(prev_cmd_policy)
        with open(AUDIT_STATE, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False)
    set_cmd_policy(1)
    ok, msg = arm_sacl()
    ok2, msg2 = propagate_sacl()
    present, detail = sacl_present()
    log("ARM", auditpol="FileSystem+ProcessCreation enabled(idempotent)",
        sacl=msg, propagate=msg2, sacl_present=present,
        cmdline_policy={"before": prev_cmd_policy, "after": 1})
    print(f"[ARM] 审计已启用：File System + Process Creation；"
          f"SACL: {msg}；传播: {msg2}（校验: {present}）")
    print(f"[ARM] 4688 命令行记录策略: {prev_cmd_policy} -> 1")


def cmd_disarm():
    if not is_admin():
        sys.exit("需要管理员权限。")
    ok, msg = disarm_sacl()
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
    log("DISARM", sacl=msg,
        auditpol="FileSystem/ProcessCreation kept-enabled(无SACL时系统级无效果)",
        cmdline_policy=restored)
    print(f"[DISARM] SACL: {msg}")
    print("[DISARM] auditpol File System/Success 保留启用（无任何 SACL 时"
          "不产生事件；如需关闭手动执行:)")
    print(f"        auditpol /set /subcategory:{FS_SUBCAT} /success:disable")


def cmd_check():
    print(f"守护目录     : {WATCH_ROOT}")
    print(f"管理员权限   : {'是' if is_admin() else '否（--arm/--run 需要）'}")
    present, detail = sacl_present()
    print(f"SACL 审计 ACE: {'已布雷' if present else '未布雷'}  [{detail[:120]}]")
    rc, out, _ = auditpol_get()
    print(f"auditpol FS  : {'可读' if rc == 0 else '不可读'}")
    print(f"4688命令行记录: {read_cmd_policy()}")
    rc, out, err = ps_run(
        "Get-WinEvent -LogName Security -MaxEvents 1 | Out-Null")
    print(f"Security 日志: "
          f"{'可读' if rc == 0 else '不可读 — ' + err.strip()[:80]}")
    hosts = load_host_apps()
    print(f"宿主应用配置 : {sorted(hosts) if hosts else '（未配置）'}")
    v = read_pid()
    print(f"地雷进程    : {'PID ' + str(v) if v else '未运行'}")


def read_pid():
    try:
        with open(PID_FILE, encoding="utf-8") as f:
            v = int(f.read().strip())
        r = subprocess.run(["tasklist", "/fi", f"PID eq {v}"],
                           capture_output=True, errors="replace")
        return v if str(v) in (r.stdout or "") else None
    except Exception:
        return None


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


def cmd_stop():
    v = read_pid()
    if not v:
        print("地雷未在运行。")
        try:
            os.remove(PID_FILE)
        except OSError:
            pass
        return
    victims = sorted(set([v] + find_other_instances()))
    for pid in victims:
        subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                       capture_output=True, errors="replace")
    log("STOP", pids=victims)
    print(f"[STOP] 已终止 PID {victims}（SACL 仍在，可用 --disarm 排雷）")


# ---------------------------------------------------------------- 判定核心

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


class PotatoMine:
    def __init__(self, dry_run=False, strict_orphans=False):
        self.dry_run = dry_run
        self.strict_orphans = strict_orphans
        self.self_pid = os.getpid()
        self.proc = {}                 # pid -> {ppid,name,cmdline,exe,created}
        self._rate = {}                # (layer,pid[,file]) -> last ts
        self._lookup_missed = set()    # 已尝试补查仍缺失的 pid
        self.event_q = queue.Queue()   # 出生/4663 事件的单一消费队列
        self.sensor = None
        self.host_apps = load_host_apps()
        self.tree_warn_roots = BASE_TREE_WARN_ROOTS | self.host_apps
        self.protected = SYSTEM_PROTECTED | self.host_apps
        self.seed_snapshot()
        chain, _ = self.ancestry(self.self_pid)
        self.self_ancestors = {p for p, _ in chain} | {self.self_pid}

    # ---- 进程表 ----
    def seed_snapshot(self):
        rc, out, _ = ps_run(
            "Get-CimInstance Win32_Process | Select-Object ProcessId,"
            "ParentProcessId,Name,CommandLine,ExecutablePath,CreationDate | "
            "ConvertTo-Json -Compress", timeout=90)
        if rc != 0 or not out.strip():
            print("[WARN] 初始进程快照失败，祖先判定退化为 origin 规则",
                  flush=True)
            return
        try:
            arr = json.loads(out)
        except json.JSONDecodeError:
            print("[WARN] 进程快照解析失败", flush=True)
            return
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

    # ---- 击杀 ----
    def kill(self, pid, why, evidence):
        """威力上限（硬边界）：只终止目标进程及其子树（taskkill /T），
        绝不碰目标的任何父进程；系统命脉/宿主应用/资源管理器在
        PROTECTED/WARN_SET 中永不被杀；自身祖先链拒绝击杀。
        因此最坏情况 = 某个用户态工具进程被终止（可重开），
        不存在不可逆破坏路径。"""
        info = self.proc.get(pid, {})
        if pid == self.self_pid or info.get("name") in self.protected:
            log("WARN", pid=pid, note="protected/self，拒绝击杀", why=why)
            return
        if pid in self.self_ancestors:
            log("WARN", pid=pid, note="自身祖先链，拒绝击杀", why=why)
            return
        chain, root = self.ancestry(pid)
        forensics = {
            "pid": pid, "name": info.get("name"), "exe": info.get("exe"),
            "cmdline": (info.get("cmdline") or "")[:2000],
            "created": info.get("created"),
            "ancestry": " <- ".join(f"{p}:{n}" for p, n in chain) or "(未知)",
            "tree_root": root, "reason": why, "evidence": evidence,
        }
        if self.dry_run:
            log("KILL_DRYRUN", **forensics)
            print(f"[DRYRUN] 将击杀 PID {pid} ({info.get('name')}): {why}",
                  flush=True)
            return
        r = subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                           capture_output=True, errors="replace")
        log("KILL", taskkill_rc=r.returncode, **forensics)
        print(f"[KILL] PID {pid} ({info.get('name')}): {why} "
              f"(taskkill rc={r.returncode})", flush=True)

    # ---- Layer B：出生检查 ----
    def on_birth(self, ev):
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
        # 这里刻意不做任何同步查询：消费循环是单线程的，一次 PowerShell/CIM
        # 调用（最坏 15 秒超时）会把后续所有事件堵死。4688 已经把需要的
        # 字段都带齐了。
        info = self.proc[pid]
        if os.environ.get("POTATO_DEBUG_BIRTH"):
            log("PROC_BORN", pid=pid, ppid=info["ppid"], name=info["name"],
                has_cmd=bool(info["cmdline"]))
        # 预热祖先链：新进程出生时其父进程通常还活着，此刻解析最可靠。
        # 否则短命进程在 4663 事件到达时已退出，来源会退化成"未知"。
        self.ancestry(pid)
        name, cmd = info["name"], info["cmdline"]
        if not cmd or pid == self.self_pid or name in WARN_SET:
            return                    # 资源管理器等 GUI 复制=用户亲手操作
        low = cmd.lower()
        norm = low.replace("/", "\\")
        rootlow = WATCH_ROOT.lower().replace("/", "\\")
        if rootlow not in norm:
            return                    # 不涉及守护目录
        if not COPY_VERBS.search(low):
            return                    # 无复制/上传语义
        dests = []
        exelow = (info.get("exe") or "").lower()
        for m in PATHISH.finditer(cmd):
            tok = (m.group(1) or m.group(2) or "").strip('"')
            if not tok:
                continue
            tnorm = tok.lower().replace("/", "\\")
            if tnorm.startswith(rootlow):
                continue              # 目录内=源或中间产物
            if tok.lower() == exelow or tok.lower().endswith("\\" + name):
                continue              # 进程自身映像路径
            if re.match(r"(?i)^(https?|ftp|sftp)://", tok) or \
                    re.match(r"(?i)^[a-z0-9._-]+@[a-z0-9.-]+:", tok) or \
                    ABS_PATH.match(tok):
                dests.append(tok)
        if not dests:
            return
        if name in SHELL_NAMES:
            chain, root = self.ancestry(pid)
            if root in ("session", "self"):
                # 命令行里"提到"搬运 ≠ 执行搬运：会话树内的 shell 只告警，
                # 真正的执行者（robocopy/cmd 子进程等）会以自身出生事件被击杀
                log("WARN", pid=pid, name=name, tree_root=root,
                    note="会话树内 shell 命令含搬运语义",
                    dest=dests[:4], cmdline_head=cmd[:300])
                return
        self.kill(pid, "LayerB 出生搬运：守护目录源 + 目录外目的地",
                  {"dest": dests[:4], "cmdline_head": cmd[:300]})

    # ---- Layer A：读绊网 ----
    def on_read(self, xml):
        def field(name):
            m = re.search(
                "<Data Name=[\"']" + name + "[\"']>([^<]*)</Data>", xml)
            return m.group(1) if m else ""
        objname = field("ObjectName")
        pid_s = field("ProcessId")
        pname = field("ProcessName").lower()
        access = field("AccessList")
        # 实测 %%4416 = ReadData/ListDirectory（%%4417 是 WriteData）
        if not pid_s or "4416" not in (access or ""):
            return                     # 只要内容读(ReadData/ListDirectory)
        pid = int(pid_s, 16) if pid_s.lower().startswith("0x") else int(pid_s)
        if pid == self.self_pid:
            return
        key = ("A", pid, objname.lower())
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
            log("WARN", pid=pid, name=name, tree_root=root, **evidence)
            return
        if root == "session":
            log("WARN", pid=pid, name=name, tree_root=root,
                note="会话树内读取（其搬运由 LayerB 击杀）", **evidence)
            return
        if (name in DANGEROUS or name in SHELL_NAMES) and root == "headless":
            self.kill(pid, "LayerA 高危进程无头树读取守护目录", evidence)
            return
        if name in DANGEROUS and root == "unknown" and self.strict_orphans:
            self.kill(pid, "LayerA 高危孤儿进程读取守护目录(strict-orphans)",
                      evidence)
            return
        # 其余一律只告警。**信息缺失绝不击杀**：无法确定来源/映像路径时
        # "不知道"不等于"可疑"，宁漏杀不误杀（威力上限约束）。
        log("WARN", pid=pid, name=name, tree_root=root,
            note=("证据不足（未能确定进程来源），仅告警"
                  if (not chain or root == "unknown") else ""),
            **evidence)

    def poll_4688_forever(self):
        """进程创建事件（含命令行与父子映像路径）。"""
        last = 0
        for rid, _ in read_new_events("*[System[(EventID=4688)]]", 0,
                                      limit=1):
            last = max(last, rid)
        while True:
            try:
                for rid, xml in read_new_events("*[System[(EventID=4688)]]",
                                                last):
                    last = max(last, rid)
                    self.event_q.put(("BIRTH", xml))
            except Exception as ex:
                log("POLL_ERR", error=str(ex), source="4688")
            time.sleep(0.4)

    def poll_4663_forever(self):
        """文件读审计事件（只关心守护目录内的读）。"""
        rootlow = WATCH_ROOT.lower()
        last = 0
        for rid, _ in read_new_events("*[System[(EventID=4663)]]", 0,
                                      limit=1):
            last = max(last, rid)
        while True:
            try:
                for rid, ev in read_new_events("*[System[(EventID=4663)]]",
                                               last):
                    last = max(last, rid)
                    dm = re.search(
                        "<Data Name=[\"']ObjectName[\"']>([^<]*)</Data>", ev)
                    if not dm or not dm.group(1).lower().startswith(rootlow):
                        continue
                    am = re.search(
                        "<Data Name=[\"']AccessList[\"']>([^<]*)</Data>", ev)
                    if not am or "4416" not in am.group(1):
                        continue
                    self.event_q.put(("4663", ev))
            except Exception as ex:
                log("POLL_ERR", error=str(ex), source="4663")
            time.sleep(0.6)

    @staticmethod
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

    def run(self):
        if not is_admin():
            sys.exit("需要管理员权限运行地雷（4688/4663 事件在 Security 日志）。")
        others = find_other_instances()
        if others:
            sys.exit(f"已有地雷实例在运行（PID {others}）。"
                     f"先 python potato_mine.py --stop，或手动结束这些进程。")
        with open(PID_FILE, "w", encoding="utf-8") as f:
            f.write(str(self.self_pid))
        log("START", pid=self.self_pid, dry_run=self.dry_run,
            watch=WATCH_ROOT)
        print(f"[START] potato-mine PID {self.self_pid} "
              f"dry_run={self.dry_run} watch={WATCH_ROOT}", flush=True)
        threading.Thread(target=self.poll_4688_forever,
                         daemon=True).start()
        threading.Thread(target=self.poll_4663_forever,
                         daemon=True).start()
        # 单线程消费：出生与读绊网事件严格串行处理，不并发改进程表
        while True:
            try:
                kind, payload = self.event_q.get(timeout=5.0)
            except queue.Empty:
                continue
            try:
                if kind == "BIRTH":
                    self.on_birth(self.parse_4688(payload))
                elif kind == "4663":
                    self.on_read(payload)
            except Exception as ex:       # 单条事件失败不倒地雷
                log("EVENT_ERR", error=str(ex), head=str(payload)[:200])


def main():
    ap = argparse.ArgumentParser(description="Potato Mine（土豆地雷）")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--arm", action="store_true")
    ap.add_argument("--disarm", action="store_true")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--strict-orphans", action="store_true")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--stop", action="store_true")
    a = ap.parse_args()
    if a.check:
        cmd_check()
    elif a.arm:
        cmd_arm()
    elif a.disarm:
        cmd_disarm()
    elif a.status:
        v = read_pid()
        print("运行中 PID:", v) if v else print("未运行")
        print("SACL:", sacl_present()[0])
    elif a.stop:
        cmd_stop()
    elif a.run:
        PotatoMine(dry_run=a.dry_run,
                   strict_orphans=a.strict_orphans).run()
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
