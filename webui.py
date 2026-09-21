#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
webui.py —— Potato Mine 网页控制台（仅标准库）

启动：
    python webui.py                 # http://127.0.0.1:8756
    python webui.py --port 9000 --open
    webui.cmd                       # 自提权版本（布雷/运行需要管理员）

只监听 127.0.0.1：控制台能引爆地雷（终止进程），不要绑到 0.0.0.0，
也不要暴露到局域网或公网。

接口：
    GET  /                        页面
    GET  /api/state               全部状态（地雷清单/设置/守护/事件）
    GET  /api/processes           运行中的进程（供"选择主进程"，带缓存）
    GET  /api/events?n=80&kind=   事件流
    GET  /api/checks              体检结果
    POST /api/settings            {monitor_processes?, host_apps?,
                                   upload_monitor?, action?, apply_action_all?}
    POST /api/mines               {path}             新增地雷
    POST /api/mines/<id>          {action?, enabled?, path?}
    DELETE /api/mines/<id>        移除地雷
    POST /api/daemon              {enabled: bool}    守护总开关
"""

import argparse
import json
import os
import sys
import threading
import time
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import mine_core as mc

HERE = mc.HERE
PAGE = os.path.join(HERE, "webui.html")
# 8787 常被本机其它小工具占用，这里挑一个不常用的默认端口
DEFAULT_PORT = 8756

REG = mc.MineRegistry()
UPLOAD = mc.UploadMonitor()
SUP = None                      # MineSupervisor 实例或 None
_LOCK = threading.RLock()

# PowerShell 调用是慢操作（每次近一秒起步），以下三处都带 TTL 缓存，
# 后台线程负责刷新，绝不挡住页面首屏。
_PROC_CACHE = {"ts": 0.0, "items": [], "error": ""}
_PROC_TTL = 45.0
_ARMED_CACHE = {"ts": 0.0, "map": {}, "error": ""}
_ARMED_TTL = 8.0
_EXT_CACHE = {"ts": 0.0, "pids": []}
_EXT_TTL = 10.0

VERBOSE = False


# ---------------------------------------------------------------- 进程列表

def list_processes(force=False):
    """列出运行中进程（按映像名聚合）。结果缓存 45 秒。"""
    global _PROC_CACHE
    now = time.time()
    if not force and _PROC_CACHE["items"] and \
            now - _PROC_CACHE["ts"] < _PROC_TTL:
        return _PROC_CACHE["items"], _PROC_CACHE["error"]
    rc, out, err = mc.ps_run(
        "Get-CimInstance Win32_Process | Select-Object Name,ProcessId,"
        "ExecutablePath | ConvertTo-Json -Compress", timeout=90)
    if rc != 0 or not out.strip():
        _PROC_CACHE["error"] = (err or out).strip()[:160] or "进程枚举失败"
        return _PROC_CACHE["items"], _PROC_CACHE["error"]
    try:
        arr = json.loads(out)
    except json.JSONDecodeError:
        _PROC_CACHE["error"] = "进程列表解析失败"
        return _PROC_CACHE["items"], _PROC_CACHE["error"]
    if isinstance(arr, dict):
        arr = [arr]
    sysroot = mc.norm_path(os.environ.get("SystemRoot", r"C:\Windows"))
    agg = {}
    for p in arr:
        name = (p.get("Name") or "").lower()
        if not name:
            continue
        e = agg.setdefault(name, {"name": name, "count": 0, "exe": "",
                                  "system": False})
        e["count"] += 1
        exe = p.get("ExecutablePath") or ""
        if exe and not e["exe"]:
            e["exe"] = exe
            e["system"] = mc.norm_path(exe) == sysroot or \
                mc.norm_path(exe).startswith(sysroot + "\\")
    items = sorted(agg.values(),
                   key=lambda x: (x["system"], -x["count"], x["name"]))
    _PROC_CACHE = {"ts": now, "items": items, "error": ""}
    return items, ""


def external_instances():
    """命令行启动的、不在本控制台托管下的地雷实例。缓存 10 秒。"""
    now = time.time()
    if now - _EXT_CACHE["ts"] < _EXT_TTL:
        return _EXT_CACHE["pids"]
    pids = mc.find_other_instances()
    _EXT_CACHE.update({"ts": now, "pids": pids})
    return pids


def refresh_armed(force=False):
    """向系统核实每个地雷是否真的布上了审计 ACE。只在后台线程调用。"""
    now = time.time()
    if not force and _ARMED_CACHE["map"] and \
            now - _ARMED_CACHE["ts"] < _ARMED_TTL:
        return _ARMED_CACHE["map"]
    amap, err = {}, ""
    for mine in REG.mines:
        if not mine.exists:
            amap[mine.id] = False
            continue
        try:
            present, _detail = mc.sacl_present(mine.path)
            amap[mine.id] = present
        except Exception as ex:
            amap[mine.id] = False
            err = f"{type(ex).__name__}: {ex}"
    _ARMED_CACHE.update({"ts": now, "map": amap, "error": err})
    return amap


# ---------------------------------------------------------------- 协调

def start_daemon():
    """启动守护。布雷要改 ACL，慢；这里立刻返回，进度由 phase 反映。"""
    global SUP
    with _LOCK:
        if SUP is not None and SUP.is_alive():
            return True, f"守护已在运行（PID {SUP.self_pid}）"
        if not mc.is_admin():
            return False, "需要管理员权限：请通过 webui.cmd 以管理员身份启动"
        others = mc.find_other_instances()
        if others:
            return False, (f"已有命令行地雷实例在运行（PID {others}）。"
                           f"请先执行 stop-potato.cmd，再回到控制台启动。")
        pid = mc.read_pid()
        if pid and pid != os.getpid():
            return False, f"已有守护进程占位于 PID {pid}"
        REG.load()
        sup = mc.MineSupervisor(REG, force_warn=False)
        SUP = sup
        sup.start()
        REG.settings["daemon_enabled"] = True
        REG.save()
        return True, "守护正在启动（首次布雷较慢，页面会自动刷新状态）"


def stop_daemon():
    global SUP
    with _LOCK:
        if SUP is None or not SUP.is_alive():
            SUP = None
            return True, "守护未在运行"
        sup, SUP = SUP, None
        sup.stop()                # run() 的 finally 会排雷并清 pid 文件
        try:
            REG.load()
            REG.settings["daemon_enabled"] = False
            REG.save()
        except Exception:
            pass
        for m in REG.mines:
            m.armed = False
        _ARMED_CACHE["map"] = {m.id: False for m in REG.mines}
        _ARMED_CACHE["ts"] = time.time()
        return True, "守护已停止并排雷"


def reconcile():
    """把系统状态拉齐到期望状态：布雷/排雷、上传监视起停。

    布雷与排雷是纯系统操作，与守护是否在运行无关，所以这里总是执行；
    守护只负责"盯梢"。
    """
    REG.load()
    if SUP is not None and SUP.is_alive():
        SUP.reload()
    sync_map = mc.sync_arm(REG.mines)          # 立即生效，不依赖守护
    wanted = bool(REG.settings.get("upload_monitor"))
    if wanted and not UPLOAD.running:
        UPLOAD.start()
    elif not wanted and UPLOAD.running:
        UPLOAD.stop()
    # 刚刚查过系统，直接对齐缓存，省掉轮询里再查一次 PowerShell
    _ARMED_CACHE["map"] = dict(sync_map)
    _ARMED_CACHE["ts"] = time.time()
    return wanted


def _norm_names(v):
    if v is None:
        return None
    if isinstance(v, str):
        v = [v]
    out, seen = [], set()
    for x in v:
        n = str(x).strip().lower()
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out


def apply_settings(payload):
    cfg = mc.load_config()
    changed_proc = False
    for key in ("monitor_processes", "host_apps"):
        vals = _norm_names(payload.get(key))
        if vals is not None:
            if key == "monitor_processes":
                changed_proc = (vals != _norm_names(cfg.get(key)))
            cfg[key] = vals
        mc.save_config(cfg)
    REG.load()                       # 外部可能直接改过 mines.json
    for key in ("upload_monitor", "action"):
        if payload.get(key) is not None:
            REG.settings[key] = payload[key]
    if payload.get("apply_action_all"):
        act = payload.get("action") or REG.settings.get("action")
        for m in REG.mines:
            m.action = act
    REG.save()
    if changed_proc and UPLOAD.running:
        UPLOAD.stop()               # 主进程变了，让上传监视重新加载配置
    reconcile()
    return collect_state()


# ---------------------------------------------------------------- 状态收集

EVENT_KINDS = ("WARN", "KILL", "KILL_DRYRUN", "ARM", "DISARM", "START",
               "STOP", "UPLOAD_START", "UPLOAD_STOP", "START_FAILED",
               "EVENT_ERR", "POLL_ERR", "PROC_BORN")


def tail_events(n=80, kind=None):
    """最新 n 条事件（时间倒序）。"""
    out = []
    try:
        with open(mc.LOG_JSONL, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()[-max(n * 4, 200):]
    except FileNotFoundError:
        return out
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if kind and rec.get("kind") != kind:
            continue
        out.append(rec)
        if len(out) >= n:
            break
    return out


def _daemon_view():
    """守护状态。启动/停止是慢操作，phase 用来把进度刷给页面。"""
    if SUP is None:
        return {"running": False, "pid": None, "since": None, "error": "",
                "phase": "未启动"}
    return {
        "running": bool(SUP.is_alive() and SUP.running),
        "pid": SUP.self_pid,
        "since": SUP.started_at.isoformat(timespec="seconds")
                 if SUP.started_at else None,
        "error": SUP.last_error,
        "phase": SUP.phase,
    }


def _upload_view():
    return {
        "running": UPLOAD.running,
        "pid": UPLOAD.proc.pid if UPLOAD.running else None,
        "since": UPLOAD.started_at.isoformat(timespec="seconds")
                 if UPLOAD.started_at else None,
        "error": UPLOAD.last_error,
    }


def _settings_view(cfg):
    return {
        "monitor_processes": cfg.get("monitor_processes") or [],
        "host_apps": cfg.get("host_apps") or [],
        "upload_monitor": bool(REG.settings.get("upload_monitor")),
        "action": REG.settings.get("action", mc.ACTION_EXPLODE),
    }


def _mines_view(watched):
    """「正在运行」= 已布雷，并且有人在盯：本控制台的守护或命令行实例。"""
    amap = _ARMED_CACHE["map"]
    mines = []
    for m in REG.mines:
        d = m.to_dict()
        d["armed"] = bool(amap.get(m.id, m.armed))
        m.armed = d["armed"]         # 与守护共享同一对象，保持一致
        d["live"] = bool(m.enabled and m.exists and d["armed"] and watched)
        mines.append(d)
    return mines


def collect_state(events_n=60):
    events = tail_events(events_n)
    ext = external_instances()
    sup_running = SUP is not None and SUP.is_alive() and SUP.running
    watched = sup_running or bool(ext)
    mines = _mines_view(watched)
    return {
        "ok": True,
        "admin": mc.is_admin(),
        "root": HERE,
        "python": sys.executable,
        "daemon": _daemon_view(),
        "external": ext,
        "settings": _settings_view(mc.load_config()),
        "upload": _upload_view(),
        "counts": {
            "total": len(mines),
            "running": sum(1 for d in mines if d["live"]),
            "armed": sum(1 for d in mines if d["armed"]),
        },
        "mines": mines,
        "events": events,
        "kills": [e for e in events
                  if e.get("kind") in ("KILL", "KILL_DRYRUN")][:20],
        "events_meta": {"file": mc.LOG_JSONL, "kinds": list(EVENT_KINDS)},
    }


# ---------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "PotatoMine/1.0"

    def log_message(self, fmt, *args):
        if VERBOSE:
            sys.stderr.write("%s - %s\n" % (self.address_string(),
                                            fmt % args))

    # ---- helpers ----
    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionAbortedError):
            pass

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False))

    def _err(self, msg, code=400):
        self._json({"ok": False, "error": msg}, code)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        raw = self.rfile.read(n)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    # ---- GET ----
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        qs = self.path.split("?", 1)[1] if "?" in self.path else ""
        if path in ("/", "/index.html"):
            try:
                with open(PAGE, encoding="utf-8") as f:
                    return self._send(200, f.read(),
                                      "text/html; charset=utf-8")
            except FileNotFoundError:
                return self._send(500, f"缺少界面文件 {PAGE}", "text/plain")
        if path == "/api/state":
            return self._json(collect_state())
        if path == "/api/processes":
            force = "refresh" in qs
            items, err = list_processes(force=force)
            return self._json({"ok": not err, "error": err, "items": items,
                          "cached_at": _PROC_CACHE["ts"]})
        if path == "/api/events":
            n, kind = 80, None
            for part in qs.split("&"):
                if part.startswith("n="):
                    try:
                        n = min(int(part[2:]), 500)
                    except ValueError:
                        pass
                elif part.startswith("kind=") and len(part) > 5:
                    kind = part[5:]
            return self._json({"ok": True, "items": tail_events(n, kind)})
        if path == "/api/checks":
            return self._json({"ok": True, "items": mc.run_checks(REG)})
        return self._err("not found", 404)

    # ---- POST ----
    def do_POST(self):
        path = self.path.split("?", 1)[0]
        try:
            if path == "/api/daemon":
                ok, msg = start_daemon() \
                    if bool(self._body().get("enabled")) else stop_daemon()
                return self._json({"ok": ok, "message": msg,
                                   "state": collect_state()})

            if path == "/api/settings":
                return self._json(apply_settings(self._body()))

            if path == "/api/mines":
                payload = self._body()
                p = str(payload.get("path") or "").strip()
                if not p:
                    return self._err("缺少目录路径")
                if not os.path.isabs(p):
                    p = os.path.abspath(os.path.join(HERE, p))
                mine, created = REG.add(p, payload.get("action"),
                                        bool(payload.get("enabled", True)))
                if not created:
                    return self._err("该目录已在守护清单中")
                REG.save()
                reconcile()
                mc.log("MINE_ADD", id=mine.id, path=mine.path,
                       action=mine.action)
                return self._json({"ok": True, "state": collect_state()})

            if path.startswith("/api/mines/"):
                mine_id = path[len("/api/mines/"):]
                mine = REG.get(mine_id)
                if mine is None:
                    return self._err("无此地雷", 404)
                payload = self._body()
                if payload.get("action") in (mc.ACTION_WARN,
                                             mc.ACTION_EXPLODE):
                    mine.action = payload["action"]
                if payload.get("enabled") is not None:
                    mine.enabled = bool(payload["enabled"])
                if payload.get("path"):
                    mine.path = os.path.abspath(str(payload["path"]))
                REG.save()
                reconcile()
                mc.log("MINE_UPDATE", id=mine.id, action=mine.action,
                       enabled=mine.enabled)
                return self._json({"ok": True, "state": collect_state()})

            return self._err("not found", 404)
        except Exception as ex:
            return self._err(f"{type(ex).__name__}: {ex}", 500)

    # ---- DELETE ----
    def do_DELETE(self):
        path = self.path.split("?", 1)[0]
        if path.startswith("/api/mines/"):
            try:
                mine = REG.remove(path[len("/api/mines/"):])
            except Exception as ex:
                return self._err(f"{type(ex).__name__}: {ex}", 500)
            if mine is None:
                return self._err("无此地雷", 404)
            # 移除 = 排雷：目录不再受守护，审计 ACE 必须一起摘掉
            try:
                if mc.sacl_present(mine.path)[0]:
                    mc.disarm_sacl(mine.path)
            except Exception:
                pass
            REG.save()
            mc.log("MINE_REMOVE", id=mine.id, path=mine.path)
            return self._json({"ok": True, "state": collect_state()})
        return self._err("not found", 404)


def main():
    global VERBOSE
    ap = argparse.ArgumentParser(description="Potato Mine 网页控制台")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--open", action="store_true", help="启动后打开浏览器")
    ap.add_argument("--verbose", action="store_true", help="打印每个请求")
    a = ap.parse_args()
    VERBOSE = a.verbose

    if a.host not in ("127.0.0.1", "localhost", "::1"):
        print(f"[WARN] 正在把控制台绑定到 {a.host}：它能终止进程，"
              f"请确保该地址只有你本人可达。", flush=True)

    mc.log("WEBUI_START", host=a.host, port=a.port, admin=mc.is_admin())
    if not mc.is_admin():
        print("[WARN] 当前非管理员：可以查看/改配置，但布雷与运行地雷会被拒绝。",
              flush=True)
        print("       请以管理员身份运行 webui.cmd。", flush=True)

    # 恢复上次保存的意愿（守护总开关 / 上传监视）
    try:
        if REG.settings.get("upload_monitor"):
            ok, msg = UPLOAD.start()
            print(f"[upload] {msg}", flush=True)
        if REG.settings.get("daemon_enabled") and mc.is_admin():
            ok, msg = start_daemon()
            print(f"[daemon] {msg}", flush=True)
    except Exception as ex:
        print(f"[WARN] 恢复上次状态失败: {ex}", flush=True)

    def watchdog():
        """后台核实：布雷状态（慢查询放在这里，别挡着首屏）。"""
        try:
            list_processes(force=True)       # 预热进程列表
        except Exception:
            pass
        while True:
            try:
                refresh_armed(force=True)
                if REG.settings.get("upload_monitor"):
                    UPLOAD.watchdog()
            except Exception:
                pass
            time.sleep(10)

    threading.Thread(target=watchdog, daemon=True).start()

    url = f"http://{a.host}:{a.port}/"
    print("=" * 72)
    print("  Potato Mine 控制台")
    print("=" * 72)
    print(f"  地址     {url}")
    print(f"  守护目录 {HERE}")
    print(f"  管理员   {'是' if mc.is_admin() else '否（布雷/运行会被拒绝）'}")
    print("  按 Ctrl+C 结束（结束时会自动排雷）")
    print("=" * 72, flush=True)

    if a.open:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n正在停止…", flush=True)
    finally:
        try:
            stop_daemon()
            UPLOAD.stop()
        finally:
            mc.log("WEBUI_STOP")
            srv.server_close()


if __name__ == "__main__":
    main()
