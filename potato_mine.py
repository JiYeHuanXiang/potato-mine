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
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
WATCH_ROOT = HERE                      # 默认守护脚本所在目录
PID_FILE = os.path.join(HERE, "potato-mine.pid")
LOG_JSONL = os.path.join(HERE, "potato-mine.log")
LOG_KILL = os.path.join(HERE, "potato-mine-kills.txt")
SENSOR_PS1 = os.path.join(HERE, "potato-mine-sensor.ps1")
AUDIT_STATE = os.path.join(HERE, "potato-mine-auditpol-state.json")
WATCH_CONFIG = os.path.join(HERE, "watch-config.json")

# File System 审计子类别 GUID（locale 无关）
FS_SUBCAT = "{0CCE921D-69AE-11D9-BED3-505054503030}"
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

SENSOR_TEMPLATE = r"""
param([string]$WatchRoot)
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding=[System.Text.Encoding]::UTF8
$root = $WatchRoot.TrimEnd('\') + '\'
$q = [System.Collections.Queue]::Synchronized((New-Object System.Collections.Queue))

Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" `
    -SourceIdentifier LMPROC -Action {
    try {
        $e = $Event.SourceEventArgs.NewEvent
        $npid = [uint32]$e.ProcessID
        $cl = $null; $exe = $null; $ppid2 = [uint32]$e.ParentProcessID; $cd = $null
        foreach ($tryN in 1..4) {
            try {
                $p = Get-CimInstance Win32_Process -Filter ("ProcessId=" + $npid)
                if ($p -and $p.CommandLine) {
                    $cl = [string]$p.CommandLine
                    $exe = [string]$p.ExecutablePath
                    $ppid2 = [uint32]$p.ParentProcessId
                    if ($p.CreationDate) { $cd = $p.CreationDate.ToString('o') }
                    break
                }
            } catch {}
            Start-Sleep -Milliseconds 120
        }
        $o = [ordered]@{ pid=$npid; ppid=$ppid2; name=[string]$e.ProcessName;
                         cmdline=$cl; exe=$exe; created=$cd }
        $q.Enqueue('PROC|' + ($o | ConvertTo-Json -Compress))
    } catch { $q.Enqueue('ERR|PROC:' + $_.Exception.Message) }
} | Out-Null
$q.Enqueue('DIAG|procstart-registered')

Write-Output 'SENSOR|READY'
while ($true) {
    while ($q.Count -gt 0) { Write-Output ([string]$q.Dequeue()) }
    Start-Sleep -Milliseconds 200
}
"""

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
    if kind in ("KILL", "KILL_DRYRUN", "ARM", "DISARM", "START", "STOP",
                "SENSOR_ERR"):
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
    ok, msg = arm_sacl()
    ok2, msg2 = propagate_sacl()
    present, detail = sacl_present()
    log("ARM", auditpol="enabled(idempotent)", sacl=msg,
        propagate=msg2, sacl_present=present)
    print(f"[ARM] auditpol File System/Success 已启用；"
          f"SACL: {msg}；传播: {msg2}（校验: {present}）")


def cmd_disarm():
    if not is_admin():
        sys.exit("需要管理员权限。")
    ok, msg = disarm_sacl()
    log("DISARM", sacl=msg,
        auditpol="kept-enabled(无SACL时系统级无效果)")
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


def cmd_stop():
    v = read_pid()
    if not v:
        print("地雷未在运行。")
        try:
            os.remove(PID_FILE)
        except OSError:
            pass
        return
    subprocess.run(["taskkill", "/F", "/PID", str(v)],
                   capture_output=True, errors="replace")
    log("STOP", pid=v)
    print(f"[STOP] 已终止 PID {v}（SACL 仍在，可用 --disarm 排雷）")


# ---------------------------------------------------------------- 判定核心

class PotatoMine:
    def __init__(self, dry_run=False, strict_orphans=False):
        self.dry_run = dry_run
        self.strict_orphans = strict_orphans
        self.self_pid = os.getpid()
        self.proc = {}                 # pid -> {ppid,name,cmdline,exe,created}
        self._rate = {}                # (layer,pid[,file]) -> last ts
        self._lookup_missed = set()    # 已尝试补查仍缺失的 pid
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

    def cim_lookup(self, pids):
        """对不在进程表里的 pid 做一次实时 CIM 补查并并入（治祖先链断裂）。"""
        todo = [p for p in pids if p and p > 4 and
                p not in self.proc and p not in self._lookup_missed]
        if not todo:
            return
        for p in todo:
            self._lookup_missed.add(p)
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
            cur = info["ppid"]
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
        self.proc[pid] = {
            "ppid": int(ev.get("ppid") or 0),
            "name": (ev.get("name") or "").lower(),
            "cmdline": ev.get("cmdline") or "",
            "exe": ev.get("exe") or "",
            "created": ev.get("created") or "",
        }
        info = self.proc[pid]
        if not info.get("cmdline"):
            self.cim_lookup([pid])     # 传感器偶发取空命令行时实时补查
            info = self.proc[pid]
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
        exe = info.get("exe") or ""
        if root == "unknown" and name not in DANGEROUS and \
                not exe.lower().startswith("c:\\windows"):
            self.kill(pid, "LayerA 未知来源进程读取守护目录", evidence)
            return
        log("WARN", pid=pid, name=name, tree_root=root, **evidence)

    # ---- 4663 读绊网：wevtutil 书签轮询（PS 事件订阅不稳，改为主进程轮询） ----
    def poll_4663_forever(self):
        rootlow = WATCH_ROOT.lower()
        r = subprocess.run(["wevtutil", "qe", "Security",
                            "/q:*[System[(EventID=4663)]]", "/c:1",
                            "/rd:true", "/f:xml"], capture_output=True)
        m = re.search(r"<EventRecordID>(\d+)</EventRecordID>",
                      r.stdout.decode("utf-8", "replace"))
        last = int(m.group(1)) if m else 0
        while True:
            time.sleep(1.5)
            try:
                r = subprocess.run(["wevtutil", "qe", "Security",
                                    "/q:*[System[(EventID=4663)]]",
                                    "/c:64", "/rd:true", "/f:xml"],
                                   capture_output=True)
                out = r.stdout.decode("utf-8", "replace")
                events = re.findall(r"<Event[ >].*?</Event>", out, re.S)
                fresh = []
                for ev in events:
                    m = re.search(r"<EventRecordID>(\d+)</EventRecordID>", ev)
                    if not m:
                        continue
                    rid = int(m.group(1))
                    if rid <= last:
                        continue
                    dm = re.search(
                        "<Data Name=[\"']ObjectName[\"']>([^<]*)</Data>", ev)
                    if not dm or not dm.group(1).lower().startswith(rootlow):
                        continue
                    am = re.search(
                        "<Data Name=[\"']AccessList[\"']>([^<]*)</Data>", ev)
                    if not am or "4416" not in am.group(1):
                        continue
                    fresh.append((rid, ev))
                for rid, ev in reversed(fresh):   # 时间正序处理
                    last = max(last, rid)
                    try:
                        self.on_read(ev)
                    except Exception as ex:
                        log("EVENT_ERR", error=str(ex), head=ev[:200])
            except Exception as ex:
                log("POLL_ERR", error=str(ex))

    # ---- 传感器 ----
    def start_sensor(self):
        with open(SENSOR_PS1, "w", encoding="utf-8") as f:
            f.write(SENSOR_TEMPLATE)
        self.sensor = subprocess.Popen(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-File", SENSOR_PS1, "-WatchRoot", WATCH_ROOT],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", errors="replace", bufsize=1)

    def run(self):
        if not is_admin():
            sys.exit("需要管理员权限运行地雷（传感器与 Security 日志）。")
        with open(PID_FILE, "w", encoding="utf-8") as f:
            f.write(str(self.self_pid))
        log("START", pid=self.self_pid, dry_run=self.dry_run,
            watch=WATCH_ROOT)
        print(f"[START] potato-mine PID {self.self_pid} "
              f"dry_run={self.dry_run} watch={WATCH_ROOT}", flush=True)
        import threading
        threading.Thread(target=self.poll_4663_forever,
                         daemon=True).start()
        restarts = 0
        while True:
            self.start_sensor()
            try:
                for line in self.sensor.stdout:
                    line = line.strip()
                    if not line:
                        continue
                    if line == "SENSOR|READY":
                        print("[SENSOR] ready", flush=True)
                        continue
                    tag, _, payload = line.partition("|")
                    try:
                        if tag == "PROC":
                            self.on_birth(json.loads(payload))
                        elif tag == "4663":
                            self.on_read(payload)
                        elif tag in ("DIAG", "ERR", "SENSOR"):
                            log("SENSOR_DIAG", line=line[:300])
                    except Exception as ex:   # 单条事件失败不倒地雷
                        log("EVENT_ERR", error=str(ex), head=line[:200])
            except KeyboardInterrupt:
                break
            restarts += 1
            if restarts > 5:
                log("SENSOR_ERR", note="传感器反复退出，地雷终止")
                sys.exit("传感器反复退出")
            log("SENSOR_ERR", note=f"传感器退出，第 {restarts} 次重启",
                rc=self.sensor.poll())
            time.sleep(2)


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
