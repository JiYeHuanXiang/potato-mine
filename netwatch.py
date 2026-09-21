#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netwatch —— 目标应用出站流量监视器（Potato Mine 组件）

用途：独立核实目标应用是否只连接其文档所述服务；对配置的云厂商网段
      （cloud_cidrs / cloud_domain_markers）做专项审查，对象存储/日志服务高亮
      目标，防止本地文件被静默上传。

设计原则（为避免误伤本机其它服务）：
  1. 只统计【出站】连接 —— 由 目标应用 主动发起的连接。入站的 RDP(3389) 天然不计入。
  2. 严格【按进程归因】—— 只有被监控应用进程树（含 Electron 子进程）的连接算数。
     其他进程（svchost、系统服务等）与云厂商的连接单独列出并标注"已排除"。
  3. 【SNI 铁证】—— 从 TLS ClientHello 中提取真实域名，不依赖 DNS，无法被伪造。
  4. 【上传字节数】—— 按目标域名统计 目标应用 实际上传了多少数据。

模式：
  watch    免管理员。轮询连接表 + DNS 缓存，实时打印新出现的目的地。
  deep     需管理员。pktmon 抓包，提取 SNI 并统计上传字节，出完整归因报告。
  report   读取已有的 jsonl 日志做汇总。

示例：
  python netwatch.py watch
  python netwatch.py deep --seconds 120
  python netwatch.py deep --seconds 300 --flag-upload-over 256
"""

import argparse
import bisect
import ctypes
import fnmatch
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
from collections import defaultdict, OrderedDict
from datetime import datetime

# ---------------------------------------------------------------- 基础工具

# 良性类别：属于这些类别的目标不算异常，其余一律需要核实。
# 注意「遥测/日志」「对象存储」刻意不在其中——它们正是要盯的对象。
BENIGN_CATEGORIES = {
    "模型提供商", "厂商基础设施", "更新/镜像/CDN",
    "本机开发", "已知排除", "本地环回", "私有网络",
}

# 只标注、不处置的类别：广告与统计/追踪域名。它们在报告里单独成节，
# 既不进"待查证"清单，也不进"可封禁"清单——广告流量本身不是外传证据，
# 把它混进去只会淹没真正需要盯的目标。
LABEL_ONLY_CATEGORIES = {"广告/统计"}
AD_CATEGORY = "广告/统计"


IS_WIN = sys.platform == "win32"
CREATE_NO_WINDOW = 0x08000000 if IS_WIN else 0

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_RULES = os.path.join(HERE, "rules.txt")
DEFAULT_EXCLUSIONS = os.path.join(HERE, "exclusions.txt")

# ---- watch-config.json：本仓库不内置任何具体软件/厂商特征 ----
WATCH_CONFIG_PATH = os.path.join(HERE, "watch-config.json")


def _load_watch_config():
    try:
        with open(WATCH_CONFIG_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


_WATCH_CFG = _load_watch_config()
MONITOR_PROCESSES = [p.lower() for p in _WATCH_CFG.get("monitor_processes", [])]
_MONI_NAMES = [p[:-4] if p.endswith(".exe") else p for p in MONITOR_PROCESSES]
_CLOUD_CIDRS = list(_WATCH_CFG.get("cloud_cidrs", []))
# 大块网段（几万条）放单独文件里，别把 watch-config.json 撑成不可读：
#   "cloud_cidr_files": ["vendor-ranges.json"]
_CLOUD_CIDR_FILES = [str(x) for x in _WATCH_CFG.get("cloud_cidr_files", [])]
_CLOUD_MARKERS = list(_WATCH_CFG.get("cloud_domain_markers", []))
_MARKER_GROUPS = [g for g in (_WATCH_CFG.get("marker_groups") or [])
                  if isinstance(g, dict)]
_SERVICE_KINDS = [(str(a), str(b)) for a, b in
                  _WATCH_CFG.get("service_kinds", [])]


def make_console_utf8():
    """让中文在 cmd/PowerShell 里正常显示。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def run(cmd, timeout=30):
    """执行外部命令，返回 (returncode, stdout, stderr)，统一按 UTF-8 容错解码。"""
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
        return (
            p.returncode,
            p.stdout.decode("utf-8", "replace"),
            p.stderr.decode("utf-8", "replace"),
        )
    except subprocess.TimeoutExpired:
        return (-1, "", "timeout")
    except FileNotFoundError:
        return (-2, "", "not found")


def is_admin():
    if not IS_WIN:
        return os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def ts():
    return datetime.now().strftime("%H:%M:%S")


def human_bytes(n):
    if n < 1024:
        return f"{n} B"
    for unit in ("KB", "MB", "GB"):
        n /= 1024.0
        if n < 1024:
            return f"{n:.1f} {unit}"
    return f"{n:.1f} TB"


# ------------------------------------------------- 厂商识别（配置驱动）

def _as_pair(item):
    """标记项可以是 "a.com" 或 ["a.com", "某厂商"]，统一成 (标记, 标签)。"""
    if isinstance(item, (list, tuple)) and len(item) >= 2:
        return str(item[0]).lower(), str(item[1])
    return str(item).lower(), ""


def _load_cidr_files(names):
    """从独立文件读大块网段。文件可以是 ["1.2.3.0/24", ...]，
    也可以是 {"cidrs": [...]}。"""
    out = []
    for nm in names:
        path = nm if os.path.isabs(nm) else os.path.join(HERE, nm)
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception as ex:
            # 静默跳过会让"网段一条没生效"变成看不见的坑
            print(f"[WARN] 网段文件读不到，已跳过：{path}（{type(ex).__name__}）")
            continue
        if isinstance(data, dict):
            data = data.get("cidrs", [])
        if isinstance(data, list):
            out.extend(str(x) for x in data)
    return out


# 可疑标记（进待查清单）与仅标注标记（广告/统计，单独成节）。
# 兼容旧配置：没有 marker_groups 时，cloud_domain_markers 一律按"可疑"处理。
_SUSPICIOUS_MARKERS = [_as_pair(x) for x in _CLOUD_MARKERS]
_AD_MARKERS = []
for _g in _MARKER_GROUPS:
    _glabel = str(_g.get("label") or "")
    _bucket = _SUSPICIOUS_MARKERS if _g.get("suspicious", True) else _AD_MARKERS
    for _item in (_g.get("markers") or []):
        _mk, _lb = _as_pair(_item)
        if _mk:
            _bucket.append((_mk, _lb or _glabel))

SUSPICIOUS_MARKERS_LIST = tuple(_SUSPICIOUS_MARKERS)
AD_MARKERS_LIST = tuple(_AD_MARKERS)


def classify_vendor(name):
    """给域名定性：返回 ("suspicious"|"ad"|None, 标签)。

    两组标记都命中时取【更长的那个】——这样 pos.baidu.com 会按广告标记
    定性，而不是被更宽泛的 baidu.com 吞成"云厂商"。
    """
    if not name:
        return None, None
    n = name.lower()
    best_len, best_kind, best_label = -1, None, None
    for pairs, kind in ((SUSPICIOUS_MARKERS_LIST, "suspicious"),
                        (AD_MARKERS_LIST, "ad")):
        for marker, label in pairs:
            if marker in n and len(marker) > best_len:
                best_len, best_kind, best_label = len(marker), kind, \
                    (label or marker)
    return best_kind, best_label


def ad_kind(name):
    """广告/统计/追踪域名 → 返回标签；不是则 None。只标注，不处置。"""
    kind, label = classify_vendor(name)
    return label if kind == "ad" else None


# ---- 网段（兜底判据）----
# 只作兜底：拿不到域名时才用 IP 判定（域名/SNI 侧优先）。
# 大清单可达数万条，因此合并重叠区间后按上界二分，而不是逐条 in 判断。
CLOUD_CIDRS_LIST = _CLOUD_CIDRS + _load_cidr_files(_CLOUD_CIDR_FILES)


def _build_ranges(cidrs):
    v4 = []
    for c in cidrs:
        try:
            n = ipaddress.ip_network(str(c).strip(), strict=False)
        except ValueError:
            continue
        if n.version != 4:
            continue
        v4.append((int(n.network_address), int(n.broadcast_address)))
    v4.sort()
    merged = []
    for lo, hi in v4:
        if merged and lo <= merged[-1][1] + 1:
            if hi > merged[-1][1]:
                merged[-1][1] = hi
        else:
            merged.append([lo, hi])
    return merged


_CLOUD_RANGES = _build_ranges(CLOUD_CIDRS_LIST)
_CLOUD_STARTS = [r[0] for r in _CLOUD_RANGES]


def is_cloud_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.version != 4:
        return False
    i = int(a)
    idx = bisect.bisect_right(_CLOUD_STARTS, i) - 1
    return idx >= 0 and i <= _CLOUD_RANGES[idx][1]


def is_cloud_name(name):
    return classify_vendor(name)[0] == "suspicious"


# 产品类型关键词：刻意只描述"这是什么服务"，不写任何厂商名，
# 这样换一家云、换一个存储产品名，判定依然成立。
_STORAGE_HINTS = (
    "oss", "cos.", "obs", "bos", "s3", "blob", "gcs", "storage", "bucket",
    "ufile", "ks3", "nos", "qiniu", "bcebos", "oss-", "cos-", "imgix",
)
_LOG_HINTS = (
    "log", "trace", "sls", "arms", "metric", "monitor", "analytics", "stat",
    "collect", "beacon", "report", "sentry", "datadog", "newrelic", "umeng",
    "crashlytics", "bugsnag", "telemetry",
)
_CDN_HINTS = ("cdn", "static", "img", "pic", "photo", "video", "vod",
              "media", "edge", "cache")
_UPDATE_HINTS = ("update", "upgrade", "download", "patch", "mirror",
                 "maven", "npm", "pypi", "crates", "docker", "repo")


def cloud_service_kind(name):
    """给可疑域名进一步定性——对象存储是文件上传最可能的落点，必须高亮。"""
    if not name:
        return None
    n = name.lower()
    for marker, note in _SERVICE_KINDS:       # 配置里的已知服务优先
        if marker in n:
            return note
    if any(h in n for h in _STORAGE_HINTS):
        return "对象存储"
    if any(h in n for h in _LOG_HINTS):
        return "日志/链路遥测"
    if any(h in n for h in _UPDATE_HINTS):
        return "软件源镜像"
    if any(h in n for h in _CDN_HINTS):
        return "CDN/静态资源"
    return "云厂商服务（未细分）"


# ---------------------------------------------------------------- 分类规则


class Rules:
    """规则文件格式：  类别 | 域名模式 | 备注
    域名模式支持 * 通配；不含 * 时同时匹配该域名及其所有子域。
    """

    def __init__(self, path):
        self.entries = []  # (category, pattern, note)
        self.load(path)

    def load(self, path):
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.split("|")]
                if len(parts) < 2:
                    continue
                cat, pat = parts[0], parts[1].lower()
                note = parts[2] if len(parts) > 2 else ""
                self.entries.append((cat, pat, note))

    def match(self, host):
        """返回 (category, note)；未命中返回 (None, '')。"""
        if not host:
            return (None, "")
        h = host.lower().rstrip(".")
        for cat, pat, note in self.entries:
            if "*" in pat:
                if fnmatch.fnmatch(h, pat):
                    return (cat, note)
            else:
                if h == pat or h.endswith("." + pat):
                    return (cat, note)
        return (None, "")


# ---------------------------------------------------------------- 厂商 IP 确证


class ModelProviderMap:
    """把「模型提供商 / 厂商基础设施」的域名主动解析成 IP 映射。

    DNS 缓存是**全系统共享**的：别的程序查过一个域名，也会出现在我们给 目标应用 的
    记录里。共享 CDN 的 IP 上常挂着多个不相干域名，于是会冒出"api.deepseek.com
    的 IP 被判成未知域名"这种误报——而这类误报的代价是把模型 API 拉黑、目标应用 报废。

    所以这里不看缓存，直接自己解析，拿到权威的 ip -> (域名, 类别) 映射。
    """

    def __init__(self, rules, interval=300):
        self.rules = rules
        self.interval = interval
        self.map = {}
        self.last = 0.0

    def refresh(self, force=False):
        if not force and time.time() - self.last < self.interval:
            return
        m = {}
        for cat, pat, _note in self.rules.entries:
            if cat not in ("模型提供商", "厂商基础设施"):
                continue
            host = pat[2:] if pat.startswith("*.") else pat
            try:
                for info in socket.getaddrinfo(host, None):
                    m.setdefault(info[4][0], (host, cat))
            except Exception:
                continue
        if m:
            self.map = m
        self.last = time.time()

    def lookup(self, ip):
        """返回 (域名, 类别)；不是厂商 IP 则 None。"""
        return self.map.get(ip)


# ---------------------------------------------------------------- 排除表


class Exclusions:
    """已知非 目标应用 的良性目标，显式排除，避免误伤。

    典型：本机自己的 frp 服务端 203.0.113.7。
    格式：  IP 或 CIDR 或 域名 | 说明
            proc:<进程名>   | 说明      ← 按进程排除（如 frpc.exe）
    """

    def __init__(self, path):
        self.entries = []  # (kind, value, note); kind = 'net' | 'name'
        self.load(path)

    def load(self, path):
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.split("|")]
                if not parts or not parts[0]:
                    continue
                val = parts[0]
                note = parts[1] if len(parts) > 1 else "已排除"
                if val.lower().startswith("proc:"):
                    self.entries.append(("proc", val[5:].strip().lower(), note))
                    continue
                try:
                    self.entries.append(("net", ipaddress.ip_network(val, strict=False), note))
                    continue
                except ValueError:
                    pass
                self.entries.append(("name", val.lower(), note))

    def check_proc(self, proc=None):
        """按进程名判断是否属于已知排除项。命中返回说明文字。"""
        if not proc:
            return None
        # 注意：Get-Process 给出的 ProcessName 不带 .exe（如 "frpc"），
        # 而配置里人习惯写 "frpc.exe"，两侧都归一化后再比较，否则会静默失效。
        p = proc.lower()
        pn = p[:-4] if p.endswith(".exe") else p
        for kind, val, note in self.entries:
            if kind != "proc":
                continue
            if "*" in val:
                if fnmatch.fnmatch(p, val) or fnmatch.fnmatch(pn, val):
                    return note
                continue
            vn = val[:-4] if val.endswith(".exe") else val
            if pn == vn:
                return note
        return None

    def check(self, ip=None, name=None):
        """命中返回说明文字，否则 None。"""
        if ip:
            try:
                a = ipaddress.ip_address(ip)
                for kind, val, note in self.entries:
                    if kind == "net" and a.version == val.version and a in val:
                        return note
            except ValueError:
                pass
        if name:
            h = name.lower().rstrip(".")
            for kind, val, note in self.entries:
                if kind != "name":
                    continue
                if "*" in val:
                    if fnmatch.fnmatch(h, val):
                        return note
                elif h == val or h.endswith("." + val):
                    return note
        return None


# ---------------------------------------------------------------- 进程发现


class TargetProcesses:
    """发现被监控应用的进程树（名称来自 watch-config.json）。"""

    def __init__(self):
        self.install_dir = None
        self.pids = set()
        self.info = {}
        self.last_refresh = 0.0

    def _detect_install_dir(self):
        code, out, _ = run([
            "powershell", "-NoProfile", "-Command",
            ("Get-Process -Name " + ",".join(_MONI_NAMES) +
             " -ErrorAction SilentlyContinue | " if _MONI_NAMES else
             "Get-Process -ErrorAction SilentlyContinue | ") +
            "Select-Object -First 1 -ExpandProperty Path",
        ])
        p = out.strip()
        if p and os.path.exists(p):
            self.install_dir = os.path.dirname(p)
        else:
            self.install_dir = None

    def refresh(self, force=False):
        now = time.time()
        if not force and now - self.last_refresh < 8:
            return
        if self.install_dir is None:
            self._detect_install_dir()
        d = (self.install_dir or "").replace("'", "''")
        ps = (
            "$d = '" + d + "'; "
            "Get-Process -ErrorAction SilentlyContinue | ForEach-Object { "
            "  $p = $null; try { $p = $_.Path } catch {}; "
            "  if ($_.ProcessName -in @('" + "','".join(_MONI_NAMES) + "') -or ($p -and $d -and $p.StartsWith($d))) { "
            "    Write-Output ($_.Id.ToString() + '\t' + $_.ProcessName + '\t' + $p) } "
            "}"
        )
        code, out, _ = run(["powershell", "-NoProfile", "-Command", ps], timeout=40)
        pids, info = set(), {}
        for line in out.splitlines():
            f = line.split("\t")
            if len(f) >= 2 and f[0].strip().isdigit():
                pid = int(f[0].strip())
                pids.add(pid)
                info[pid] = (f[1].strip(), f[2].strip() if len(f) > 2 else "")
        self.pids, self.info, self.last_refresh = pids, info, now


# ---------------------------------------------------------------- 连接表


ADDR_RE = re.compile(r"^(?P<host>.+):(?P<port>\d+)$")


def split_addr(s):
    """拆 'ip:port' / '[v6]:port'。"""
    s = s.strip()
    if s.startswith("["):
        i = s.rfind("]")
        if i < 0:
            return (s, None)
        return (s[1:i], int(s[i + 2:]) if s[i + 2:].isdigit() else None)
    m = ADDR_RE.match(s)
    if not m:
        return (s, None)
    return (m.group("host"), int(m.group("port")))


def netstat_connections():
    """返回所有 TCP 连接 [(proto, local_host, local_port, remote_host, remote_port, state, pid)]。
    结构化解析，不依赖本地化后的状态词。"""
    code, out, err = run(["netstat", "-ano", "-p", "tcp"], timeout=20)
    if code != 0:
        return []
    rows = []
    for raw in out.splitlines():
        f = raw.split()
        if len(f) < 4:
            continue
        if not f[-1].isdigit():
            continue  # 末列必须是 PID
        lh, lp = split_addr(f[1])
        rh, rp = split_addr(f[2])
        if lp is None:
            continue
        state = f[3] if len(f) >= 5 else ""
        rows.append(("TCP", lh, lp, rh, rp, state, int(f[-1])))
    return rows


def dns_cache_map():
    """系统 DNS 缓存 -> {ip: [names]}，作为 SNI 之外的名字来源。"""
    ps = (
        "Get-DnsClientCache -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Type -eq 1 -or $_.Type -eq 28 } | "
        "ForEach-Object { Write-Output ($_.Data + ' ' + $_.Entry) }"
    )
    code, out, _ = run(["powershell", "-NoProfile", "-Command", ps], timeout=40)
    m = defaultdict(list)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            ip, name = parts[0], parts[1]
            if ip and ip[0].isdigit() or ":" in ip:
                if name not in m[ip]:
                    m[ip].append(name)
    return dict(m)


def classify_dest(host_ip, names, rules, excl=None, port=None, prov=None):
    """对一个目的地址定性。返回 (display_name, category, note, flags)。"""
    flags = []
    name = None
    # 优先挑非泛域名候选：优先带厂商特征的（云/存储或广告标注）、再取最短
    if names:
        al = [n for n in names if is_cloud_name(n) or ad_kind(n)]
        pool = al or names
        name = sorted(pool, key=lambda s: (len(s), s))[0]

    # 内网 / 回环 / 本地
    try:
        a = ipaddress.ip_address(host_ip)
        if a.is_loopback:
            return (host_ip, "本地环回", "", ["本地"])
        if a.is_private or a.is_link_local:
            return (name or host_ip, "私有网络", "", ["内网"])
    except ValueError:
        pass

    # 显式排除表优先于一切——例如本机自建的 frp 服务端
    if excl:
        note = excl.check(ip=host_ip) or excl.check(name=name)
        if note:
            return (name or host_ip, "已知排除", note, ["已排除"])

    # 厂商 IP 确证：命中就直接定案，压过一切基于域名的猜测。
    # 这是防止"共享 CDN 干扰导致模型 API 被误判"的关键一环。
    if prov:
        hit = prov.lookup(host_ip)
        if hit:
            pdom, pcat = hit
            extra = [n for n in ([name] if name else []) + list(names or [])
                     if n and n != pdom]
            fl = list(flags) + ["厂商IP确证"]
            if extra:
                fl.append("另有域名:" + ",".join(sorted(set(extra))[:3]))
            return (pdom, pcat, f"{pdom}（由厂商域名解析确证）", fl)

    # 规避特征：正规云服务几乎都走 443/80。用非标端口、或根本不带域名
    # 直接连裸 IP，都是"不想被看出来"的信号，值得单独标出。
    if port and port not in (443, 80, 8080, 8443):
        flags.append(f"非标端口{port}")

    # 云厂商特征先算出来当"标记"，但白名单优先——官方 API 域名属于已登记服务，
    # 即便部署在该云上，仍应归为已登记类别。
    cloud_ip = is_cloud_ip(host_ip)
    cloud_nm = is_cloud_name(name)
    kind = cloud_service_kind(name) if (cloud_ip or cloud_nm) else None
    if cloud_ip or cloud_nm:
        flags.append("云厂商")
        if kind:
            flags.append(kind)
        if kind and "对象存储" in kind:
            flags.append("上传高危")

    cat, note = rules.match(name) if name else (None, "")
    if cat:
        return (name or host_ip, cat, note, flags)
    if cloud_ip or cloud_nm:
        return (name or host_ip, "云厂商-未在白名单", kind or "", flags)
    # 广告/统计/追踪域名：单独成类、只标注。放在云厂商之后，免得把
    # "跑在云上的广告服务"降级成只标注。
    ad = ad_kind(name)
    if ad:
        return (name or host_ip, AD_CATEGORY, ad, flags + ["广告/统计"])
    if name:
        return (name, "未知", "", flags + ["未分类"])
    return (host_ip, "未知(无域名)", "", flags + ["未分类"])


# ---------------------------------------------------------------- pcapng / pcap 解析

LINKTYPE_ETHERNET = 1


def read_capture(path):
    """读取 pcap 或 pcapng，产出 (ts, frame_bytes, orig_len)。自动识别格式。"""
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 4:
        return []
    magic = data[:4]
    out = []
    if magic == b"\x0a\x0d\x0d\x0a":  # pcapng
        endian = "<"
        pos = 0
        while pos + 12 <= len(data):
            btype, blen = struct.unpack(endian + "II", data[pos : pos + 8])
            if btype == 0x0A0D0D0A:
                bom = struct.unpack("<I", data[pos + 8 : pos + 12])[0]
                endian = "<" if bom == 0x1A2B3C4D else ">"
                btype, blen = struct.unpack(endian + "II", data[pos : pos + 8])
            if blen < 12 or pos + blen > len(data):
                break
            body = data[pos + 8 : pos + blen - 4]
            if btype == 0x00000006:  # EPB
                _iid, th, tl, caplen, pktlen = struct.unpack(endian + "IIIII", body[:20])
                out.append((((th << 32) | tl) / 1e6, body[20 : 20 + caplen], pktlen))
            elif btype == 0x00000003:  # SPB
                pktlen = struct.unpack(endian + "I", body[:4])[0]
                out.append((0.0, body[4:], pktlen))
            pos += blen
        return out
    # 经典 pcap
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        return []
    _maj, _min, _tz, _sf, _snap, _net = struct.unpack(endian + "HHiIII", data[4:24])
    pos = 24
    while pos + 16 <= len(data):
        _s, _u, incl, orig = struct.unpack(endian + "IIII", data[pos : pos + 16])
        pos += 16
        out.append((_s + _u / 1e6, data[pos : pos + incl], orig))
        pos += incl
    return out


def parse_tls_sni(payload):
    """从 TLS ClientHello 记录里提取 SNI。"""
    if len(payload) < 44 or payload[0] != 0x16 or payload[1] != 0x03:
        return None
    hs = payload[5:]
    if not hs or hs[0] != 0x01:
        return None
    hs_len = int.from_bytes(hs[1:4], "big")
    body = hs[4 : 4 + hs_len]
    if len(body) < 38:
        return None
    off = 34  # legacy_version(2) + random(32)
    sid_len = body[off]
    off += 1 + sid_len
    if off + 2 > len(body):
        return None
    cs_len = struct.unpack(">H", body[off : off + 2])[0]
    off += 2 + cs_len
    if off + 1 > len(body):
        return None
    comp_len = body[off]
    off += 1 + comp_len
    if off + 2 > len(body):
        return None
    ext_total = struct.unpack(">H", body[off : off + 2])[0]
    off += 2
    end = min(off + ext_total, len(body))
    while off + 4 <= end:
        etype, elen = struct.unpack(">HH", body[off : off + 4])
        off += 4
        edata = body[off : off + elen]
        off += elen
        if etype == 0x0000 and len(edata) >= 5 and edata[2] == 0:
            nlen = struct.unpack(">H", edata[3:5])[0]
            return edata[5 : 5 + nlen].decode("ascii", "replace")
    return None


def parse_http_host(payload):
    if payload[:4] not in (b"GET ", b"POST", b"HEAD", b"PUT ", b"OPTI", b"DELE", b"PATC"):
        return None
    head = payload[:2048]
    i = head.lower().find(b"\r\nhost:")
    if i < 0:
        return None
    return head[i + 7 :].split(b"\r\n", 1)[0].strip().decode("ascii", "replace")


def parse_dns_qname(payload):
    """普通 DNS 查询名（可能因 DoH 而缺失）。"""
    if len(payload) < 13:
        return None
    qname, i = [], 12
    while i < len(payload) and payload[i] != 0:
        ln = payload[i]
        if ln > 63:
            return None
        qname.append(payload[i + 1 : i + 1 + ln].decode("ascii", "replace"))
        i += 1 + ln
    return ".".join(qname) if qname else None


def l4_extract(frame, orig_len):
    """解析以太网帧，返回 (src, dst, sport, dport, proto, payload, payload_bytes)。
    payload_bytes 依据原始帧长计算，不受 --pkt-size 截断影响。"""
    if len(frame) < 14:
        return None
    eth_type = struct.unpack(">H", frame[12:14])[0]
    off = 14
    while eth_type in (0x8100, 0x88A8):
        if off + 4 > len(frame):
            return None
        eth_type = struct.unpack(">H", frame[off + 2 : off + 4])[0]
        off += 4
    if eth_type == 0x0800:
        ihl = (frame[off] & 0x0F) * 4
        proto = frame[off + 9]
        src = ".".join(str(b) for b in frame[off + 12 : off + 16])
        dst = ".".join(str(b) for b in frame[off + 16 : off + 20])
        off += ihl
    elif eth_type == 0x86DD:
        if len(frame) < off + 40:
            return None
        proto = frame[off + 6]
        src = ":".join(f"{frame[off + 8 + i * 2]:02x}{frame[off + 9 + i * 2]:02x}" for i in range(8))
        dst = ":".join(f"{frame[off + 24 + i * 2]:02x}{frame[off + 25 + i * 2]:02x}" for i in range(8))
        off += 40
        while proto in (0, 43, 60):
            if off + 8 > len(frame):
                return None
            nxt = frame[off]
            hlen = (frame[off + 1] + 1) * 8
            proto, off = nxt, off + hlen
    else:
        return None
    if proto == 6:  # TCP
        if off + 20 > len(frame):
            return None
        sport, dport = struct.unpack(">HH", frame[off : off + 4])
        doff = (frame[off + 12] >> 4) * 4
        pstart = off + doff
        pbytes = max(0, orig_len - pstart)
        return (src, dst, sport, dport, "TCP", frame[pstart:], pbytes)
    if proto == 17:  # UDP
        if off + 8 > len(frame):
            return None
        sport, dport = struct.unpack(">HH", frame[off : off + 4])
        pstart = off + 8
        pbytes = max(0, orig_len - pstart)
        return (src, dst, sport, dport, "UDP", frame[pstart:], pbytes)
    return None


def local_ip_set():
    """本机所有 IP。用于判定数据包方向（源为本机 → 出站，即"上传"）。"""
    ips = {"127.0.0.1", "::1"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(info[4][0])
    except Exception:
        pass
    code, out, _ = run([
        "powershell", "-NoProfile", "-Command",
        "Get-NetIPAddress -ErrorAction SilentlyContinue | "
        "ForEach-Object { $_.IPAddress }",
    ], timeout=40)
    for line in out.splitlines():
        s = line.strip()
        if s:
            ips.add(s)
    return ips


# ---------------------------------------------------------------- 深度抓包


class PktmonCapture:
    """用系统自带 pktmon 抓包。需管理员。截断 1024 字节/包——足够覆盖 TLS 握手与 SNI。"""

    def __init__(self, etl_path, pkt_size=1024):
        self.etl = etl_path
        self.pcap = os.path.splitext(etl_path)[0] + ".pcapng"
        self.pkt_size = pkt_size
        self.started = False

    def start(self):
        run(["pktmon", "stop"])  # 清理可能残留的会话
        code, out, err = run([
            "pktmon", "start", "--capture",
            "--pkt-size", str(self.pkt_size),
            "--file-name", self.etl,
        ])
        if code != 0:
            raise RuntimeError(
                "pktmon 启动失败（通常是没有管理员权限）：\n" + (out + err).strip()
            )
        self.started = True

    def stop(self):
        if self.started:
            run(["pktmon", "stop"], timeout=60)
            self.started = False

    def convert(self):
        run(["pktmon", "etl2pcap", self.etl, "--out", self.pcap], timeout=180)
        return self.pcap if os.path.exists(self.pcap) else None


# ---------------------------------------------------------------- 监视核心


class Monitor:
    def __init__(self, rules, excl, outdir, flag_upload_over_kb=0):
        self.rules = rules
        self.excl = excl
        self.outdir = outdir
        self.flag_upload = flag_upload_over_kb * 1024
        self.procs = TargetProcesses()
        self.dns = {}
        self.known_names = defaultdict(set)   # IP -> 累积到的所有域名（跨轮次累积，防缓存过期）
        self.prov = ModelProviderMap(rules)
        self.last_dns = 0.0
        self.seen = OrderedDict()      # (ip, port) -> 记录
        self.target_flows = set()       # (local_port, remote_ip, remote_port)
        self.port_owner = {}           # local_port -> pid
        self.other_cloud = OrderedDict()
        self.log_path = os.path.join(
            outdir, f"netwatch-{datetime.now():%Y%m%d-%H%M%S}.jsonl"
        )
        self._log = open(self.log_path, "a", encoding="utf-8")

    def refresh_dns(self, force=False, interval=5):
        self.prov.refresh(force=force)
        if force or time.time() - self.last_dns > interval:
            try:
                self.dns = dns_cache_map()
            except Exception:
                pass
            for ip, names in self.dns.items():
                self.known_names[ip].update(names)
            self.last_dns = time.time()

    def _reenrich(self):
        """DNS 缓存有 5 秒节流且会过期，域名可能是连接建立之后才学到的。
        每轮把新学到的域名回填到已记录的目标上，并重新定性。"""
        for (ip, port), rec in self.seen.items():
            names = self._names_for(ip)
            if set(names) - set(rec.get("names") or []):
                disp, cat, note, flags = classify_dest(ip, names, self.rules, self.excl)
                rec.update(name=disp, category=cat, note=note, flags=flags,
                           names=list(names))
                self._log.write(json.dumps({"type": "target_dest_updated", **rec},
                                           ensure_ascii=False) + "\n")
                self._log.flush()

    def close(self):
        try:
            self._log.close()
        except Exception:
            pass

    def trim(self):
        """长期运行时防止内存无限增长。

        target_flows 只为 deep 模式的抓包归因服务，record 模式长期累积它会变成
        内存泄漏；定期清空即可，不影响任何持久化记录（那些在 Store 里）。
        """
        if len(self.target_flows) > 200000:
            self.target_flows.clear()
        if len(self.other_cloud) > 20000:
            self.other_cloud.clear()

    def rotate_log_if_big(self, limit=64 * 1024 * 1024):
        """明细日志单文件超过 limit 就换新文件，避免长期跑出巨型日志。"""
        try:
            if os.path.getsize(self.log_path) < limit:
                return
        except OSError:
            return
        try:
            self._log.close()
        except Exception:
            pass
        self.log_path = os.path.join(
            self.outdir, f"netwatch-{datetime.now():%Y%m%d-%H%M%S}.jsonl")
        self._log = open(self.log_path, "a", encoding="utf-8")

    def _names_for(self, ip):
        names = list(self.known_names.get(ip, []))
        for rec in self.seen.values():
            if rec.get("ip") == ip:
                for n in rec.get("sni", []):
                    if n not in names:
                        names.append(n)
        return names

    def poll_once(self, heartbeat=False):
        """一轮采样。返回本轮新发现的目的地列表。"""
        self.procs.refresh()
        self.refresh_dns(interval=getattr(self, "dns_interval", 5))
        self._reenrich()
        rows = netstat_connections()
        new = []

        for _proto, lh, lp, rh, rp, state, pid in rows:
            if rh in ("0.0.0.0", "::", "*", ""):
                continue
            if state.upper().startswith("LISTEN"):
                continue
            is_z = pid in self.procs.pids

            if is_z:
                self.target_flows.add((lp, rh, rp))
                self.port_owner[lp] = pid
                key = (rh, rp)
                est = state.upper().startswith("ESTABLISH")
                if key not in self.seen:
                    names = self._names_for(rh)
                    disp, cat, note, flags = classify_dest(
                        rh, names, self.rules, self.excl, rp, self.prov)
                    rec = {
                        "first_seen": datetime.now().isoformat(timespec="seconds"),
                        "ip": rh, "port": rp, "name": disp,
                        "category": cat, "note": note, "flags": flags,
                        "pid": pid, "proc": self.procs.info.get(pid, ("", ""))[0],
                        "local_port": lp, "names": list(names), "sni": [],
                        "established": est, "last_state": state,
                    }
                    self.seen[key] = rec
                    new.append(rec)
                    self._log.write(json.dumps(
                        {"type": "target_dest", **rec}, ensure_ascii=False) + "\n")
                    self._log.flush()
                elif est and not self.seen[key].get("established"):
                    # 之前只是尝试、现在真连上了——通道打通，必须记下来
                    self.seen[key]["established"] = True
                    new.append(self.seen[key])
                    self._log.write(json.dumps(
                        {"type": "target_dest_connected", **self.seen[key]},
                        ensure_ascii=False) + "\n")
                    self._log.flush()
                if key in self.seen:
                    self.seen[key]["last_state"] = state
            else:
                if pid == 0:
                    continue  # netstat 中 PID 0 = 进程已退出的残留套接字，非真实进程
                # 非目标进程的云厂商出站连接：单独记录，明确排除，避免误伤本机自用服务
                if is_cloud_ip(rh) or is_cloud_name(
                    (self.dns.get(rh) or [""])[0]
                ):
                    key = (rh, rp, pid)
                    if key not in self.other_cloud:
                        pname = ""
                        try:
                            pname = self.procs.info.get(pid, ("",))[0]
                            if not pname:
                                c2, o2, _ = run([
                                    "powershell", "-NoProfile", "-Command",
                                    f"(Get-Process -Id {pid} -ErrorAction SilentlyContinue).ProcessName",
                                ], timeout=20)
                                pname = o2.strip()
                        except Exception:
                            pass
                        if self.excl.check_proc(pname):
                            self.other_cloud[key] = {
                                "ip": rh, "port": rp, "pid": pid,
                                "proc": pname or "?", "excluded": True,
                            }
                            continue
                        self.other_cloud[key] = {
                            "ip": rh, "port": rp, "pid": pid, "proc": pname or "?",
                        }
                        self._log.write(json.dumps(
                            {"type": "other_cloud", **self.other_cloud[key]},
                            ensure_ascii=False) + "\n")
                        self._log.flush()

        if heartbeat:
            z = len(self.target_flows)
            print(f"[{ts()}] 采样中… 目标进程 {len(self.procs.pids)} 个 / "
                  f"已记录目的地址 {len(self.seen)} 个 / 连接 {z} 条", flush=True)
        return new

    def print_new(self, new):
        for r in new:
            mark = "⚠" if (r["category"] not in BENIGN_CATEGORIES
                           or "上传高危" in r["flags"]) else " "
            fl = ("  [" + "/".join(r["flags"]) + "]") if r["flags"] else ""
            print(f"[{ts()}] {mark} 目标(pid {r['pid']}) → {r['ip']}:{r['port']}  "
                  f"{r['name']}  <{r['category']}>{fl}", flush=True)


# ---------------------------------------------------------------- 报告


def deep_report(m, packets):
    """解析抓包，按 目标应用 出站流精确归因，输出报告。"""
    local_ips = local_ip_set()
    # 流键统一为 (本地端口, 远端IP, 远端端口)——出站/入站归到同一条流，
    # 以便对每条流算出"上传了多少、下载了多少"。
    flows = defaultdict(lambda: {"up": 0, "down": 0, "up_pkts": 0, "dn_pkts": 0})
    sni_by_ip = defaultdict(set)
    dns_ip = defaultdict(set)
    unattributed = defaultdict(set)

    for _tsec, frame, orig_len in packets:
        r = l4_extract(frame, orig_len)
        if not r:
            continue
        src, dst, sport, dport, proto, payload, pbytes = r

        if proto == "UDP" and (dport == 53 or sport == 53):
            q = parse_dns_qname(payload)
            if q:
                dns_ip[q].add(dst if dport == 53 else src)
            continue

        name = parse_tls_sni(payload) or parse_http_host(payload)
        src_local, dst_local = src in local_ips, dst in local_ips

        if src_local and not dst_local:          # 出站 = 上传
            key = (sport, dst, dport)
            flows[key]["up"] += pbytes
            flows[key]["up_pkts"] += 1
            if name:
                sni_by_ip[dst].add(name)
                if key not in m.target_flows:
                    unattributed[(dst, dport)].add(name)
        elif dst_local and not src_local:        # 入站 = 下载
            key = (dport, src, sport)
            flows[key]["down"] += pbytes
            flows[key]["dn_pkts"] += 1
            if name:
                sni_by_ip[src].add(name)

    # ---- 归因：流键必须精确命中 目标应用 的连接三元组
    targets = {}
    for key, v in flows.items():
        if key not in m.target_flows:
            continue
        _lp, ip, dport = key
        names = set(sni_by_ip.get(ip, ())) | set(m.dns.get(ip, ()))
        names |= {n for n, ips in dns_ip.items() if ip in ips}
        targets[(ip, dport)] = {"up": v["up"], "down": v["down"],
                              "names": names or {ip}}

    # ---- 报告
    print()
    print("=" * 100)
    print(f"  目标应用 出站流量报告    {datetime.now():%Y-%m-%d %H:%M:%S}")
    print("=" * 100)
    print(f"  抓包 {len(packets)} 包 | 目标进程 {len(m.procs.pids)} 个 | "
          f"观察到 目标应用 出站连接 {len(m.target_flows)} 条")
    if m.procs.install_dir:
        print(f"  安装目录 {m.procs.install_dir}")
    print()

    findings = []      # (级别, 文本)
    total_up = sum(v["up"] for v in targets.values())

    if not targets:
        print("  ⚠ 本次窗口内未捕获到 目标应用 的上传流量，无法判定。")
        print("    请在抓包期间于 目标应用 中发消息、让它读写工作区，再重跑。")
    else:
        print(f"  ── 目标应用 上传去向（合计上传 {human_bytes(total_up)}，按上传量排序）")
        print(f"  {'上传':>10}  {'下载':>10}  {'端口':>5}  {'目标':<50} 分类")
        print("  " + "-" * 96)
        for (ip, dport), v in sorted(targets.items(), key=lambda kv: -kv[1]["up"]):
            disp, cat, note, flags = classify_dest(ip, list(v["names"]), m.rules, m.excl)
            tag = cat + (f" [{note}]" if note and cat != "已知排除" else "")
            if flags:
                tag += " · " + "/".join(flags)
            bad = cat not in BENIGN_CATEGORIES
            mark = "  " if cat == "已知排除" else ("⚠ " if (bad or "上传高危" in flags) else "✅ ")
            print(f" {mark}{human_bytes(v['up']):>9}  {human_bytes(v['down']):>9}  "
                  f"{dport:>5}  {disp[:50]:<50} {tag}")

            if cat == "已知排除":
                continue
            over = m.flag_upload and v["up"] > m.flag_upload
            if "OSS 对象存储" in flags:
                findings.append(("❗高危", f"{disp} 是 OSS/对象存储端点，上传 "
                                          f"{human_bytes(v['up'])} —— 文件外传最可能的落点，务必核实"))
            elif cat not in BENIGN_CATEGORIES:
                findings.append(("⚠", f"{disp} <{cat}> 不是模型提供商，上传 {human_bytes(v['up'])}"))
            # 模型提供商不参与阈值告警：正常对话的上下文本身就很大，必然超阈值，
            # 每次都报等于把告警变成噪音。它的上传量在表格里本来就看得到。
            if over and cat in BENIGN_CATEGORIES and cat != "模型提供商":
                findings.append(("⚠", f"{disp} 上传 {human_bytes(v['up'])}，"
                                      f"超过告警阈值 {m.flag_upload // 1024} KB"))

    # ---- 云厂商专项
    print()
    print("  ── 云厂商专项审查" + "─" * 78)
    ali = []
    for (ip, dport), v in targets.items():
        names = list(v["names"]) + m.dns.get(ip, [])
        if is_cloud_ip(ip) or any(is_cloud_name(n) for n in names):
            nm = next((n for n in names if is_cloud_name(n)), ip)
            ex = m.excl.check(ip=ip, name=nm)
            ali.append((nm, ip, dport, v["up"], cloud_service_kind(nm), ex))
    if ali:
        for nm, ip, dport, up, kind, ex in sorted(ali, key=lambda x: -x[3]):
            if ex:
                print(f"  ✅ 目标应用 → {nm} ({ip}:{dport}) 上传 {human_bytes(up)}"
                      f" —— 命中排除表：{ex}（不计为异常）")
            else:
                print(f"  {'❗' if kind == 'OSS 对象存储' else '⚠'} 目标应用 → {nm} "
                      f"({ip}:{dport}) 上传 {human_bytes(up)}  定性：{kind or '云厂商服务'}")
    else:
        print("  ✅ 目标应用未观察到任何云厂商出站连接")

    # ---- 其他进程的云厂商连接（对照，明确排除，避免误伤本机服务）
    print()
    print("  ── 非目标进程的云厂商出站连接（对照，已排除）" + "─" * 55)
    if m.other_cloud:
        for (ip, port, pid), v in m.other_cloud.items():
            ex = m.excl.check(ip=ip)
            print(f"     · {v['proc']}(pid {pid}) → {ip}:{port}"
                  + (f"   [{ex}]" if ex else ""))
    else:
        print("     （无）")
    print("     · 本机自用服务（frp 203.0.113.7 等）已在 exclusions.txt 登记，不会误伤。")

    # ---- 其他程序的 TLS 目标（透明说明，便于排除）
    if unattributed:
        print()
        print("  ── 未归因到目标应用的 TLS 目标（本机其他程序，供排除参考）")
        shown = 0
        for (ip, dport), names in sorted(unattributed.items()):
            if m.excl.check(ip=ip):
                continue
            joined = ", ".join(sorted(names))
            print(f"     · {ip}:{dport}  {joined[:78]}")
            shown += 1
            if shown >= 15:
                print("     · …")
                break
        if shown == 0:
            print("     （无）")

    # ---- 未归因但仍指向云厂商的流量：可能是采样间隙漏掉的短连接，必须提示
    for (ip, dport), names in sorted(unattributed.items()):
        nm = next((n for n in names if is_cloud_name(n)), None)
        if nm is None and not is_cloud_ip(ip):
            continue
        if m.excl.check(ip=ip, name=nm):
            continue
        kind = cloud_service_kind(nm)
        findings.append(("⚠", f"有流量指向云厂商目标 {nm or ip}:{dport}"
                              f"（{kind or '未细分'}）但未归因到具体进程，"
                              f"可能是连完即断的短连接落在了采样间隙，建议复核"))

    # ---- 结论
    print()
    print("  ── 结论" + "─" * 90)
    if not targets:
        print("  ⚪ 未捕获到 目标应用 上传流量，本次无法判定。请重跑并制造流量。")
    elif not findings:
        print("  ✅ 所有 目标应用 出站目标均落在白名单内，未发现未知、云厂商或 OSS 外传行为。")
    else:
        hi = [f for f in findings if f[0] == "❗高危"]
        lo = [f for f in findings if f[0] != "❗高危"]
        if hi:
            print(f"  ❗ 发现 {len(hi)} 项高危：")
            for _l, t in hi:
                print(f"     · {t}")
        if lo:
            print(f"  ⚠ 发现 {len(lo)} 项需注意：")
            for _l, t in lo:
                print(f"     · {t}")
    print("=" * 100)
    return targets


# ---------------------------------------------------------------- 长期记录


class Store:
    """跨次运行累积的落地记录。

    长期监听的要点：进程随时可能被重启（关机、崩溃、手动结束），
    记录必须落盘并且原子写入，否则重启就丢数据、白监听一场。
    """

    VERSION = 1

    def __init__(self, path):
        self.path = path
        self.data = {
            "version": self.VERSION,
            "created": datetime.now().isoformat(timespec="seconds"),
            "destinations": {},
        }
        self.load()

    def load(self):
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                d = json.load(f)
            if isinstance(d, dict) and "destinations" in d:
                self.data = d
        except Exception:
            # 文件损坏时从空开始，绝不因为读不出而中断监听
            pass

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.path)          # 原子替换，防止写一半坏掉

    def touch(self, ip, port, name, pid, proc, rules, excl, established=False,
              prov=None):
        """记录一次观测。返回 (是否首次发现, 分类后的记录)。"""
        d = self.data["destinations"]
        now = datetime.now().isoformat(timespec="seconds")
        rec = d.get(ip)
        isnew = rec is None
        if isnew:
            rec = {
                "ip": ip, "ports": [], "names": [], "pids": [], "procs": [],
                "first_seen": now, "last_seen": now, "hits": 0,
                "category": "未知", "note": "", "flags": [],
                "established": False, "ever_connected": None,
            }
            d[ip] = rec
        if port and port not in rec["ports"]:
            rec["ports"].append(port)
        if name and name != ip and name not in rec["names"]:
            rec["names"].append(name)
        if pid and pid not in rec["pids"]:
            rec["pids"].append(pid)
        if proc and proc not in rec["procs"]:
            rec["procs"].append(proc)
        rec["last_seen"] = now
        rec["hits"] += 1
        if established:
            rec["established"] = True
            if not rec.get("ever_connected"):
                rec["ever_connected"] = now

        # 每次都按"当前累积到的全部域名"重新定性。
        # 这样域名是后来才学到的情况下，分类会自动修正；而且
        # 一旦某 IP 被确认是模型提供商，就会立刻降级为良性、不再进封禁名单。
        disp, cat, note, flags = classify_dest(
            ip, list(rec["names"]), rules, excl, port, prov)
        rec["category"], rec["note"], rec["flags"] = cat, note, flags
        if disp and disp != ip:
            rec["display"] = disp
        return isnew, rec

    def destinations(self):
        return self.data["destinations"]


def model_provider_ips(rules, prov=None):
    if prov is not None:
        prov.refresh(force=True)
        return set(prov.map.keys())
    """解析规则表里所有「模型提供商」域名，返回其当前 IP 集合。

    这是导出封禁名单前的最后一道安全闸：封禁列表以 IP 形式交给防火墙/杀软，
    一旦把模型 API 的 IP 写进去，目标应用 就彻底不能用了。所以导出时
    必须拿实时的解析结果做一次交叉核对，命中即剔除。
    """
    ips = set()
    for cat, pat, _note in rules.entries:
        if cat != "模型提供商":
            continue
        host = pat[2:] if pat.startswith("*.") else pat
        try:
            for info in socket.getaddrinfo(host, None):
                ips.add(info[4][0])
        except Exception:
            continue
    return ips


def probe_tcp(ip, port=443, timeout=1.2):
    """快速探测目标是否可达。

    已封禁的 IP 表现为超时（数据包被丢弃），因此"不可达"通常意味着
    已经被封住了。但也可能是对端自身故障，所以措辞上只说"当前不可达"。
    """
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.settimeout(timeout)
    try:
        c.connect((ip, port))
        return True
    except Exception:
        return False
    finally:
        try:
            c.close()
        except Exception:
            pass


def write_exports(store, rules, excl, outdir, probe=True):
    """导出两份清单：给人查证的、可直接粘贴进黑名单的。"""
    prov_ips = model_provider_ips(rules)

    candidates, blockable, skipped = [], [], []
    cloud_rows, other_rows, ad_rows = [], [], []
    for ip, rec in sorted(store.destinations().items(),
                          key=lambda kv: kv[1].get("first_seen", "")):
        cat = rec.get("category", "未知")
        if cat in BENIGN_CATEGORIES:
            continue
        # 广告/统计只标注：既不进待查证清单，也不进可封禁清单。
        if cat in LABEL_ONLY_CATEGORIES:
            ad_rows.append((ip, rec))
            continue
        names = rec.get("names") or []
        disp = rec.get("display") or (names[0] if names else ip)

        # 安全闸：解析层面确认属于模型提供商的，一律不封
        if ip in prov_ips:
            skipped.append((ip, disp, "当前 DNS 解析证实属于模型提供商"))
            continue
        if excl.check(ip=ip):
            skipped.append((ip, disp, "命中排除表"))
            continue

        port = (rec.get("ports") or [443])[0]
        if probe:
            reachable = probe_tcp(ip, port)
        else:
            reachable = None
        full_name = names[0] if names else ip
        block = [
            f"{ip}:{port}   <{cat}>"
            + (("  [" + "/".join(rec["flags"]) + "]") if rec.get("flags") else ""),
            f"    域名: {full_name}",
        ]
        if full_name != ip and len(names) > 1:
            block.append(f"    其它: {', '.join(names[1:])}")
        if rec.get("established"):
            block.append("    ★ 状态: 曾成功建立连接（通道确实可用）——优先处置")
            if rec.get("ever_connected"):
                block.append(f"      首次连上: {rec['ever_connected']}")
        elif reachable is True:
            block.append("    状态: 当前可达，但未见成功建连")
        else:
            block.append("    状态: 仅见到连接尝试，从未建连（大概率已被封禁）")
        block.append(f"    进程: {', '.join(rec.get('procs') or ['?'])}   "
                     f"首见: {rec.get('first_seen')}   末见: {rec.get('last_seen')}   "
                     f"命中: {rec.get('hits')} 次")
        block_text = "\n".join(block)
        candidates.append(block_text)
        if "云厂商" in (rec.get("flags") or []) or is_cloud_ip(ip):
            cloud_rows.append(block_text)
        else:
            other_rows.append(block_text)
        # 全部候选都进清单：重复添加已封 IP 无害，漏掉一个新的备用通道代价很大。
        # 排序：曾建连的 → 当前可达的 → 其余
        rank = 0 if rec.get("established") else (1 if reachable is True else 2)
        blockable.append((rank, ip))

    # 给人查证的完整版
    with open(os.path.join(outdir, "watch-candidates.txt"), "w", encoding="utf-8") as f:
        f.write("# 目标应用 非模型提供商出站目标（关注点）\n")
        f.write(f"# 生成时间 {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        f.write("# 良性类别（模型提供商/厂商基础设施/更新CDN/本机/已排除）已过滤。\n")
        f.write("# 云厂商通道被封后，若对方改用备用通道，会以'其它非模型提供商'的\n")
        f.write("# 新域名/新 IP 形式出现——这一节是最需要盯的。\n")
        f.write(f"# 共 {len(candidates)} 条\n\n")
        conn_rows = [t for t in candidates if "★ 状态: 曾成功建立连接" in t]
        f.write("=" * 78 + "\n")
        f.write(f" 零、曾成功建立连接的目标（{len(conn_rows)} 个）★★★ 这些通道是通的\n")
        f.write("=" * 78 + "\n")
        if conn_rows:
            for t in conn_rows:
                f.write(t + "\n\n")
        else:
            f.write("（无）——目前所有非模型提供商目标都只见到连接尝试、从未建连。\n\n")
        f.write("=" * 78 + "\n")
        f.write(f" 一、其它非模型提供商目标（{len(other_rows)} 个）★ 备用通道会出现在这里\n")
        f.write("=" * 78 + "\n")
        if other_rows:
            for t in other_rows:
                f.write(t + "\n\n")
        else:
            f.write("（无）——除云厂商外，目标应用 没有联系任何其它非模型提供商目标。\n\n")
        f.write("=" * 78 + "\n")
        f.write(f" 二、云厂商目标（{len(cloud_rows)} 个，已知遥测通道）\n")
        f.write("=" * 78 + "\n")
        for t in cloud_rows:
            f.write(t + "\n\n")
        f.write("=" * 78 + "\n")
        f.write(f" 三、广告/统计目标（{len(ad_rows)} 个）——仅标注，不列入处置\n")
        f.write("=" * 78 + "\n")
        f.write("# 这些域名属于广告/统计/追踪基础设施，不算外传证据，也不会进入\n")
        f.write("# watch-blockable.txt。列在这里只是让你看清应用都在跟谁打交道，\n")
        f.write("# 想知道某条链路到底传了什么，还是要看上传字节数与抓包结果。\n")
        if ad_rows:
            for ip, rec in ad_rows:
                names = rec.get("names") or []
                disp = rec.get("display") or (names[0] if names else ip)
                note = rec.get("note") or ""
                f.write(f"  {ip:<18} {disp[:52]:<52} {note}\n")
        else:
            f.write("（无）\n")
        f.write("\n")
        if skipped:
            f.write("\n# 以下目标经核验后【拒绝列入封禁名单】\n")
            for ip, disp, why in skipped:
                f.write(f"#   {ip:<18} {disp[:50]:<50} {why}\n")

    # 纯 IP 版（可直接粘贴进防火墙/杀软黑名单）
    with open(os.path.join(outdir, "watch-blockable.txt"), "w", encoding="utf-8") as f:
        f.write("# 目标应用 非模型提供商目标 IP，可整份粘贴进防火墙/杀软 IP 黑名单。\n")
        f.write("# 重复添加已封 IP 无害，故此处为完整清单；当前可达（疑似未封）的排在前面。\n")
        f.write("# 逐个目标的详细说明见 watch-candidates.txt\n")
        if not blockable:
            f.write("# 目前没有任何非模型提供商目标\n")
        for _rank, ip in sorted(blockable, key=lambda t: (t[0], t[1])):
            f.write(ip + "\n")

    return candidates, blockable, skipped


def sni_enrich(m, store, seconds, outdir, pkt_size=1024):
    """短时抓包，只为把 IP 对应到真实域名（SNI），抓完即删文件。

    长期监听如果一直抓包会把磁盘写满，所以这里只在需要时开一个几秒的窗口，
    用完立刻删除，既拿到铁证又不留负担。
    """
    etl = os.path.join(outdir, "_sni.etl")
    pcap = os.path.join(outdir, "_sni.pcapng")
    cap = PktmonCapture(etl, pkt_size)
    learned = 0
    try:
        cap.start()
        end = time.time() + seconds
        while time.time() < end:
            time.sleep(0.5)
            try:
                m.poll_once()
            except Exception:
                pass
        cap.stop()
        if not cap.convert():
            return 0
        dests = store.destinations()
        for _t, frame, orig in read_capture(pcap):
            r = l4_extract(frame, orig)
            if not r:
                continue
            _s, dst, _sp, _dp, _proto, payload, _pb = r
            nm = parse_tls_sni(payload) or parse_http_host(payload)
            rec = dests.get(dst)
            if nm and rec and nm not in rec["names"]:
                rec["names"].append(nm)
                learned += 1
        if learned:
            store.save()
    except Exception as e:
        print(f"[{ts()}] SNI 补全失败（不影响监听）：{type(e).__name__}: {e}", flush=True)
    finally:
        try:
            cap.stop()
        except Exception:
            pass
        for f in (etl, pcap):
            try:
                os.remove(f)
            except OSError:
                pass
    return learned


# ---------------------------------------------------------------- 模式实现


def cmd_watch(args, rules, excl):
    print("=" * 100)
    print("  目标应用 出站流量监视器 · watch 模式（免管理员）")
    print("  提示：想要 SNI 铁证与上传字节数，请用 deep 模式（需管理员）")
    print("=" * 100)
    m = Monitor(rules, excl, args.outdir, args.flag_upload_over)
    m.procs.refresh(force=True)
    m.refresh_dns(force=True)
    print(f"  监视目录 {os.path.abspath(args.outdir)}")
    print(f"  目标应用 安装目录 {m.procs.install_dir}")
    print(f"  已发现 目标进程 {len(m.procs.pids)} 个：{sorted(m.procs.pids)[:12]}"
          f"{' …' if len(m.procs.pids) > 12 else ''}")
    print("-" * 100)
    try:
        first = True
        deadline = time.time() + args.seconds if args.seconds else None
        last_hb = 0.0
        while True:
            try:
                new = m.poll_once()
            except Exception as e:
                print(f"[{ts()}] ! 本轮采样出错，已跳过：{type(e).__name__}: {e}", flush=True)
                new = []
            if first:
                new = list(m.seen.values())
            m.print_new(new)
            first = False
            if args.seconds and time.time() >= deadline:
                break
            if time.time() - last_hb > 30:
                print(f"[{ts()}] …监视中，已记录 {len(m.seen)} 个 目标应用 目的地址 "
                      f"（Ctrl+C 结束）", flush=True)
                last_hb = time.time()
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print()
    finally:
        summarize_watch(m)
        m.close()


def summarize_watch(m):
    print()
    print("=" * 100)
    print("  汇总")
    print("=" * 100)
    if not m.seen:
        print("  本次未观察到 目标应用 的出站连接。")
    bycat = defaultdict(list)
    for r in m.seen.values():
        bycat[r["category"]].append(r)
    for cat, items in sorted(bycat.items()):
        print(f"  <{cat}>  {len(items)} 个")
        for r in items:
            fl = ("  [" + "/".join(r["flags"]) + "]") if r["flags"] else ""
            print(f"     · {r['name']}  ({r['ip']}:{r['port']}){fl}")
    if m.other_cloud:
        print()
        print("  非 目标进程的云厂商出站连接（对照，已排除）：")
        for (ip, port, pid), v in m.other_cloud.items():
            print(f"     · {v['proc']}(pid {pid}) → {ip}:{port}")
    print()
    print(f"  日志：{m.log_path}")
    print("=" * 100)


def cmd_deep(args, rules, excl):
    if not is_admin():
        print("deep 模式需要管理员权限（pktmon 抓包）。")
        print("请右键以管理员身份运行，或使用 netwatch.cmd")
        print("（也可以先用免管理员的 watch 模式：python netwatch.py watch）")
        return 2

    # 带时间戳，避免重复运行互相覆盖——抓包是取证材料，不能被冲掉
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    etl = os.path.join(args.outdir, f"targets-capture-{stamp}.etl")
    cap = PktmonCapture(etl, args.pkt_size)
    m = Monitor(rules, excl, args.outdir, args.flag_upload_over)
    m.procs.refresh(force=True)
    m.refresh_dns(force=True)

    print("=" * 100)
    print("  目标应用 出站流量监视器 · deep 模式（pktmon 抓包 + SNI + 上传字节归因）")
    print("=" * 100)
    m.procs.refresh(force=True)
    print(f"  目标进程 {len(m.procs.pids)} 个 / 安装目录 {m.procs.install_dir}")
    print(f"  抓包时长 {args.seconds}s，单包截断 {args.pkt_size} 字节（足够覆盖 TLS 握手）")
    print("  抓包期间请在 目标应用 里正常使用，好让它产生上传流量。")
    print("-" * 100)
    try:
        cap.start()
        deadline = time.time() + args.seconds
        last_hb = 0.0
        while time.time() < deadline:
            try:
                new = m.poll_once()
            except Exception as e:
                print(f"[{ts()}] ! 本轮采样出错，已跳过：{type(e).__name__}: {e}", flush=True)
                new = []
            if new:
                m.print_new(new)
            if time.time() - last_hb > 15:
                left = int(deadline - time.time())
                print(f"[{ts()}] …抓包中，剩余 {left}s，"
                      f"已记录目标连接 {len(m.target_flows)} 条", flush=True)
                last_hb = time.time()
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n提前结束抓包…")
    except RuntimeError as e:
        print(f"错误：{e}")
        return 3
    finally:
        cap.stop()
        m.close()

    print(f"[{ts()}] 抓包结束，正在转换与解析…")
    pcap = cap.convert()
    if not pcap:
        print("etl2pcap 转换失败。可用 Wireshark 手动打开：" + etl)
        return 4
    packets = read_capture(pcap)
    if not packets:
        print("解析到 0 个数据包。")
        return 5
    deep_report(m, packets)
    print(f"  原始抓包：{pcap}")
    print(f"  转换前的原始 ETL：{etl}")
    print(f"  （抓包文件含本机全部流量头部，核实完可自行删除）")
    return 0


def cmd_record(args, rules, excl):
    """长期监听：持续记录 目标应用 的全部出站目标，累积落盘，随时可导出封禁清单。"""
    state_path = os.path.join(args.outdir, "watch-ips.json")
    store = Store(state_path)
    m = Monitor(rules, excl, args.outdir, args.flag_upload_over)

    m.dns_interval = 20          # 长期跑，DNS 刷新放宽以降低开销
    alerts_path = os.path.join(args.outdir, "targets-alerts.txt")

    print("=" * 100)
    print("  目标应用 出站 IP 记录器 · record 模式（长期监听）")
    print("  关注点：所有【非模型提供商】目标——云厂商通道被封后，")
    print("          若对方改用备用通道，会以新域名/新 IP 的形式出现在这里。")
    print("=" * 100)
    print(f"  状态文件   {state_path}")
    print(f"  待查证清单 {os.path.join(args.outdir, 'watch-candidates.txt')}")
    print(f"  封禁清单   {os.path.join(args.outdir, 'watch-blockable.txt')}")
    print(f"  实时告警   {alerts_path}")
    print(f"  采样间隔   {args.interval}s    "
          f"时长 {'不限（Ctrl+C 结束）' if not args.seconds else str(args.seconds) + 's'}")
    if args.sni_every:
        if is_admin():
            print(f"  SNI 补全   每 {args.sni_every} 分钟抓 {args.sni_seconds}s，"
                  f"把 IP 对应到真实域名（用完即删）")
        else:
            print(f"  SNI 补全   已请求但当前非管理员，将跳过（域名只能靠 DNS 缓存）")
    else:
        print(f"  SNI 补全   未启用（加 --sni-every 1 可让 IP 对应到真实域名，需管理员）")

    m.procs.refresh(force=True)
    m.refresh_dns(force=True)
    print(f"  目标进程 {len(m.procs.pids)} 个 / 安装目录 {m.procs.install_dir}")
    hist = store.destinations()
    print(f"  已有历史记录 {len(hist)} 个目标（来自之前的运行，继续累积）")
    print("-" * 100)

    next_sni = (time.time() + args.sni_every * 60) if args.sni_every else None
    next_export = time.time() + 60
    last_save = last_hb = time.time()
    deadline = (time.time() + args.seconds) if args.seconds else None

    try:
        while True:
            try:
                m.poll_once()
            except Exception as e:
                print(f"[{ts()}] ! 采样出错已跳过：{type(e).__name__}: {e}", flush=True)

            # 同一 IP 可能有多条连接，按 IP 去重后再落盘
            per_ip = {}
            for rec in m.seen.values():
                per_ip.setdefault(rec["ip"], rec)

            fresh = []
            for rec in per_ip.values():
                isnew, srec = store.touch(rec["ip"], rec["port"], rec["name"],
                                          rec["pid"], rec["proc"], rules, excl,
                                          established=rec.get("established", False),
                                          prov=m.prov)
                if isnew:
                    fresh.append(srec)

            for r in sorted(fresh, key=lambda x: x.get("first_seen", "")):
                names = r.get("names") or []
                disp = r.get("display") or (names[0] if names else r["ip"])
                port = r["ports"][0] if r["ports"] else 0
                bad = r["category"] not in BENIGN_CATEGORIES
                if bad:
                    al = "云厂商" in (r["flags"] or [])
                    tag = "云厂商" if al else "非模型提供商"
                    conn = r.get("established")
                    # 通道是否真正打通，是这里最重要的一条信息
                    state_txt = "★已建连(通道可用)" if conn else "仅尝试(未建连)"
                    head = "★" if conn else "⚠"
                    print(f"[{ts()}] {head} 新目标({tag}) {r['ip']}:{port}  {disp}\n"
                          f"          {state_txt}  类别 <{r['category']}>"
                          + (("  [" + "/".join(r["flags"]) + "]") if r["flags"] else "")
                          + f"  进程 {', '.join(r.get('procs') or ['?'])}", flush=True)
                    with open(alerts_path, "a", encoding="utf-8") as af:
                        af.write(f"{datetime.now():%Y-%m-%d %H:%M:%S}  {state_txt}  "
                                 f"{r['ip']}:{port}  {disp}  <{r['category']}>"
                                 + (("  [" + "/".join(r["flags"]) + "]") if r["flags"] else "")
                                 + "\n")
                else:
                    print(f"[{ts()}]   新 {r['ip']}:{port}  {disp[:56]:<56} "
                          f"<{r['category']}>", flush=True)

            if fresh or time.time() - last_save > 30:
                store.save()
                last_save = time.time()

            if next_sni and time.time() >= next_sni:
                if is_admin():
                    print(f"[{ts()}] 开始 SNI 补全（{args.sni_seconds}s）…", flush=True)
                    n = sni_enrich(m, store, args.sni_seconds, args.outdir)
                    print(f"[{ts()}] SNI 补全完成，新增 {n} 条 IP→域名 映射", flush=True)
                next_sni = time.time() + args.sni_every * 60

            if time.time() >= next_export:
                write_exports(store, rules, excl, args.outdir, probe=False)
                next_export = time.time() + 60

            if time.time() - last_hb > 120:
                dst = store.destinations()
                need = [r for r in dst.values()
                        if r.get("category") not in BENIGN_CATEGORIES]
                other = [r for r in need if "云厂商" not in (r.get("flags") or [])]
                al = [r for r in need if "云厂商" in (r.get("flags") or [])]
                print(f"[{ts()}] …监听中：累计 {len(dst)} 个目标 | "
                      f"非模型提供商 {len(need)} 个（其中云厂商 {len(al)}、"
                      f"其它 {len(other)}）", flush=True)
                if other:
                    for r in other[:8]:
                        nm = (r.get("names") or [r["ip"]])[0]
                        print(f"            ★ 非云厂商可疑：{r['ip']}  {nm}  "
                              f"<{r['category']}>", flush=True)
                last_hb = time.time()

            # 长期运行加固：内存有界 + 日志轮转
            m.trim()
            m.rotate_log_if_big()

            if deadline and time.time() >= deadline:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\n[{ts()}] 收到中断，正在保存…")

    store.save()
    cand, blockable, skipped = write_exports(store, rules, excl, args.outdir)

    print()
    print("=" * 100)
    print("  监听结束 · 汇总")
    print("=" * 100)
    dst = store.destinations()
    bycat = defaultdict(list)
    for r in dst.values():
        bycat[r.get("category", "未知")].append(r)
    for cat, items in sorted(bycat.items()):
        tag = "需查证" if cat not in BENIGN_CATEGORIES else "良性"
        print(f"  <{cat}>  {len(items)} 个  [{tag}]")
    print()
    print(f"  需查证/封禁的目标 {len(cand)} 个：")
    for line in cand:
        print("    · " + line)
    if skipped:
        print()
        print(f"  已核验并【拒绝】列入封禁名单 {len(skipped)} 个（防止误伤模型 API）：")
        for ip, disp, why in skipped:
            print(f"    · {ip}  {disp[:44]}  — {why}")
    print()
    print(f"  可直接粘贴进 IP 黑名单的文件："
          f"{os.path.join(args.outdir, 'watch-blockable.txt')}")
    print(f"  详细查证清单：{os.path.join(args.outdir, 'watch-candidates.txt')}")
    print("=" * 100)
    return 0
# ------------------------------------------------- 安全软件日志（可选数据源）


AV_LOG_DIR_DEFAULT = _WATCH_CFG.get("av_log_dir", "")


def av_events(src_dir, tmp_dir):
    """把安全软件的 log.db 连同 WAL 一起复制出来再读。

    直接读会撞上该软件的写锁，而且不复制 WAL 会漏掉最新数据。
    返回事件列表 [(ts, module, detail_dict)]。
    """
    import shutil as _shutil

    if not os.path.isdir(src_dir):
        return None, f"找不到安全软件数据目录：{src_dir}"
    src_db = os.path.join(src_dir, "log.db")
    if not os.path.exists(src_db):
        return None, f"找不到 {src_db}"

    work = os.path.join(tmp_dir, "_avlog")
    os.makedirs(work, exist_ok=True)
    for suffix in ("", "-wal", "-shm"):
        src = src_db + suffix
        if os.path.exists(src):
            _shutil.copy2(src, os.path.join(work, "log.db" + suffix))

    import sqlite3
    con = sqlite3.connect(f"file:{os.path.join(work, 'log.db')}?mode=ro", uri=True)
    events = []
    # HrLogV3_60 是所支持日志格式（杀软事件库）的表名
    for ts, module, detail in con.execute(
            "select ts, fname, detail from HrLogV3_60 order by ts"):
        try:
            j = json.loads(detail)
        except Exception:
            continue
        d = j.get("detail")
        events.append((ts, module, d if isinstance(d, dict) else {}))
    con.close()
    return events, None


def av_facts(events, excl, extra_good_ips=None):
    """从事件里抽出「进程 → 远端地址」，并按进程归类。"""
    by_proc = defaultdict(lambda: defaultdict(int))
    for _ts, _mod, d in events:
        raddr = d.get("raddr")
        if not raddr:
            continue
        proc = d.get("procname") or d.get("cmdline") or "?"
        proc = proc.split('"')[0].strip()
        by_proc[proc][raddr] += 1
    return by_proc


def cmd_avlog(args, rules, excl):
    """读安全软件的拦截/网络事件日志——独立于抓包的第二数据源。"""
    print("=" * 100)
    print("  安全软件日志审查 · avlog 模式（独立于抓包的第二数据源）")
    print("=" * 100)

    if not is_admin():
        print("  提示：读取该数据库通常需要管理员权限。")

    events, err = av_events(args.av_dir, args.outdir)
    if err:
        print(f"  ❌ {err}")
        return 1

    ts_list = [e[0] for e in events]
    rng = (datetime.fromtimestamp(min(ts_list)), datetime.fromtimestamp(max(ts_list)))
    mods = defaultdict(int)
    for _ts, m, _d in events:
        mods[m] += 1
    print(f"  数据目录 {args.av_dir}")
    print(f"  事件 {len(events)} 条，覆盖 {rng[0]:%Y-%m-%d %H:%M} ~ {rng[1]:%Y-%m-%d %H:%M}")
    print(f"  模块分布 {dict(mods)}")
    print()

    # ---- 关键：先检验日志完整性，否则结论会被过度解读
    print("  ── 日志完整性自检" + "─" * 78)
    good_ips = set()
    for cat, pat, _n in rules.entries:
        if cat != "模型提供商":
            continue
        host = pat[2:] if pat.startswith("*.") else pat
        try:
            for info in socket.getaddrinfo(host, None):
                good_ips.add(info[4][0])
        except Exception:
            pass
    raw = "\n".join(json.dumps(d, ensure_ascii=False) for _t, _m, d in events)
    hit = [ip for ip in good_ips if ip in raw]
    print(f"  已登记域名解析出 {len(good_ips)} 个 IP，其中 {len(hit)} 个在安全软件日志里出现过。")
    if len(hit) < max(1, len(good_ips) // 3):
        print("  ⚠ 结论：该日志【不完整】——它只在拦截/询问等'事件'时才记，")
        print("     不记录全部连接。所以：")
        print("       ✅ 可以用它【确认】哪些目标被拦截了（额外的独立证据）")
        print("       ❌ 不能用它【反证】没有别的 IP（日志里没有 ≠ 没连过）")
    else:
        print("  ✅ 日志覆盖看起来较全，具备一定反证能力。")
    print()

    # ---- 目标应用相关的目的地址
    print("  ── 目标应用相关的目的地址（来自安全软件记录）" + "─" * 55)
    by_proc = av_facts(events, excl)

    def _is_target(proc):
        pl = proc.lower()
        if pl.endswith("\\targets.exe"):
            return True
        return "\\programs\\targets\\" in pl

    targets = {p: v for p, v in by_proc.items() if _is_target(p)}
    store = Store(os.path.join(args.outdir, "watch-ips.json"))
    known = set(store.destinations().keys())
    new_from_hr = []

    if not targets:
        print("     （该日志里没有目标应用的相关记录）")
    for proc, ips in sorted(targets.items(), key=lambda kv: -sum(kv[1].values())):
        total = sum(ips.values())
        print(f"\n     【{proc}】 命中 {total} 次 / {len(ips)} 个地址")
        for ip, n in sorted(ips.items(), key=lambda kv: -kv[1]):
            names = store.destinations().get(ip, {}).get("names") or []
            nm = names[0] if names else ip
            _d, cat, _n, flags = classify_dest(ip, names, rules, excl)
            mark = "  " if cat in BENIGN_CATEGORIES else "⚠ "
            seen_in_our = "已在本地记录" if ip in known else "★日志独有"
            if ip not in known:
                new_from_hr.append((ip, nm, cat, n))
            print(f"     {mark} {ip:<18} {n:>4} 次  <{cat}>  【{seen_in_our}】")
            if nm != ip:
                print(f"          域名: {nm}")

    # ---- 合并进本地记录
    if new_from_hr:
        print()
        print("  ── 日志独有、本地抓包没抓到的地址，已并入记录" + "─" * 45)
        for ip, nm, cat, n in new_from_hr:
            print(f"     ★ {ip:<18} {nm[:44]:<44} <{cat}>  {n} 次")
            for _ in range(min(n, 3)):
                store.touch(ip, 443, nm if nm != ip else "", 0, "（安全软件记录）",
                            rules, excl, established=True)
        store.save()
        write_exports(store, rules, excl, args.outdir, probe=False)
        print(f"     已写入 targets-ips.json 并刷新 watch-blockable.txt")
    else:
        print()
        print("  ✅ 日志里没有本地抓包未发现的目标")

    print()
    print("=" * 100)
    return 0

def cmd_report(args, rules):
    path = args.logfile
    if not path:
        cands = sorted(
            (os.path.join(args.outdir, f) for f in os.listdir(args.outdir)
             if f.endswith(".jsonl")),
            key=os.path.getmtime, reverse=True,
        )
        if not cands:
            print("找不到 jsonl 日志。")
            return 1
        path = cands[0]
    print(f"读取 {path}")
    seen, others = {}, {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if e.get("type") == "target_dest":
                seen[(e["ip"], e["port"])] = e
            elif e.get("type") == "other_cloud":
                others[(e["ip"], e["port"], e["pid"])] = e
    print(f"\n目标应用 目的地址 {len(seen)} 个：")
    for (ip, port), e in seen.items():
        fl = ("  [" + "/".join(e["flags"]) + "]") if e.get("flags") else ""
        print(f"  {e['name']}  ({ip}:{port})  <{e['category']}>{fl}  进程 {e.get('proc')}")
    if others:
        print(f"\n其他进程云厂商连接（已排除）{len(others)} 个：")
        for (ip, port, pid), e in others.items():
            print(f"  {e['proc']}(pid {pid}) → {ip}:{port}")
    return 0


# ---------------------------------------------------------------- 入口


def main():
    make_console_utf8()
    ap = argparse.ArgumentParser(
        description="目标应用 出站流量监视器（云厂商专项审查，按进程归因避免误伤本机服务）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("mode",
                    choices=["record", "watch", "deep", "avlog", "report"],
                    help="record=长期监听并累积记录IP(推荐); watch=短时轮询; "
                         "deep=管理员抓包出报告; avlog=读杀软日志查有无其它IP; "
                         "report=汇总日志")
    ap.add_argument("--seconds", type=int, default=0,
                    help="监视/抓包时长（秒）。watch 默认 0=一直跑；deep 默认 90")
    ap.add_argument("--interval", type=float, default=1.0, help="采样间隔秒，默认 1.0")
    ap.add_argument("--outdir", default=HERE, help="输出目录（日志/抓包）")
    ap.add_argument("--rules", default=DEFAULT_RULES, help="分类规则文件")
    ap.add_argument("--exclusions", default=DEFAULT_EXCLUSIONS,
                    help="排除表文件（本机自己的云厂商 RDP 等，避免误伤）")
    ap.add_argument("--pkt-size", type=int, default=1024,
                    help="pktmon 单包截断字节，默认 1024")
    ap.add_argument("--flag-upload-over", type=int, default=512,
                    help="上传超过该 KB 数即告警，默认 512")
    ap.add_argument("--logfile", help="report 模式指定 jsonl 文件")
    ap.add_argument("--av-dir", default=AV_LOG_DIR_DEFAULT,
                    help="安全软件数据目录（avlog 模式用）；默认取 "
                         "watch-config.json 的 av_log_dir")
    ap.add_argument("--sni-every", type=int, default=0,
                    help="record 模式：每 N 分钟做一次短抓包，把 IP 对应到真实域名"
                         "（需管理员，用完即删抓包文件）")
    ap.add_argument("--sni-seconds", type=int, default=15,
                    help="每次 SNI 补全的抓包时长（秒），默认 15")
    args = ap.parse_args()

    if not MONITOR_PROCESSES:
        print("未配置被监控进程。请复制 watch-config.example.json 为 "
              "watch-config.json，并在 monitor_processes 中填入要监视的"
              "可执行文件名（例如 [\"yourapp.exe\"]）。")
        return 2
    os.makedirs(args.outdir, exist_ok=True)
    rules = Rules(args.rules)
    if not rules.entries:
        print(f"警告：规则文件为空或不存在（{args.rules}），全部目标会被判为「未知」。")
    excl = Exclusions(args.exclusions)
    if excl.entries:
        print(f"排除表已加载 {len(excl.entries)} 条（本机自用服务如 frp，不会误报）")

    if args.mode == "deep" and not args.seconds:
        args.seconds = 90
    if args.mode == "deep" and args.interval == 1.0:
        args.interval = 0.5   # 短连接可能连完即断，采样要密一点
    if args.mode == "record" and args.interval == 1.0:
        args.interval = 3.0   # 长期跑，采样放宽以降低开销
    if args.mode == "watch" and not args.seconds:
        args.seconds = 0

    if args.mode == "record":
        return cmd_record(args, rules, excl)
    if args.mode == "avlog":
        return cmd_avlog(args, rules, excl)
    if args.mode == "watch":
        cmd_watch(args, rules, excl)
        return 0
    if args.mode == "deep":
        return cmd_deep(args, rules, excl)
    return cmd_report(args, rules)


if __name__ == "__main__":
    sys.exit(main())
