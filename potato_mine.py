#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Potato Mine（土豆地雷）—— 监视工具自保护地雷（2026-09-22）

威胁模型：
  流量监视工具本身就是"谁在偷数据"的证据。若本机进程被驱动去搬运这套
  工具（复制/打包到工作区外目录 = 外传准备），地雷在搬运途中触发并留全档
  （进程名/PID/父进程/命令行/触碰的文件）。

守护对象：
  任意多个「守护目录」= 多个地雷，登记在 mines.json，各自独立布雷与开关。
  没有 mines.json 时沿用旧行为：守护本脚本所在目录。

双层探测（判定逻辑见 mine_core.py，命令行与 Web UI 共用一份）：
  Layer A 读绊网：守护目录 Everyone:ReadData 审计 ACE → Security 4663，
                  任何内容读取（含程序化 fs.copyFile、打包器枚举）都留痕。
  Layer B 出生检查：4688 命令行 同时含 守护目录路径 + 复制/打包/上传动词
                    + 目录外目的地 → 立即触发，与其祖先是谁无关。

触发动作（每个地雷单独设置）：
  警告 (warn)    —— 只留全档，不终止任何进程（等价 --dry-run）
  爆炸 (explode) —— 终止执行搬运的那一个进程

击杀语义（硬边界）：
  只终止【执行操作的那个进程本身】：taskkill /F /PID <pid>，不带 /T。
      · 不向上杀父进程：父进程是会话的壳（终端/IDE/远控）；
      · 不向下连带子进程：子进程可能是用户自己的其它工作。
  系统命脉 / 宿主应用 / explorer 在任何路径下都不可被击杀；地雷自身的
  祖先链同样拒绝。信息不足（来源/映像路径未知）时一律只告警。

配置：
  watch-config.json  监视的主进程（monitor_processes）+ 宿主应用（host_apps）
  mines.json         地雷清单 + 上传监视开关 + 默认动作

用法（管理员）：
  python potato_mine.py --check            体检：权限/SACL/日志/运行状态
  python potato_mine.py --arm              布雷：auditpol + SACL（幂等）
  python potato_mine.py --run [--dry-run]  运行地雷（dry-run 只记录不击杀）
  python potato_mine.py --disarm           排雷：移除 SACL
  python potato_mine.py --status           查看运行状态
  python potato_mine.py --stop             停止运行中的地雷
  python potato_mine.py --list             列出地雷清单

图形界面：python webui.py（或 webui.cmd 自提权）

日志：potato-mine.log（JSONL 全事件）/ potato-mine-kills.txt（击杀档案）
"""

import argparse
import os
import subprocess
import sys
import time

import mine_core as mc


def cmd_check():
    print(f"守护根目录 : {mc.HERE}")
    checks = mc.run_checks()
    for c in checks:
        mark = "[OK]  " if c["ok"] else "[FAIL]"
        print(f"{mark} {c['name']:<40} {c['detail']}")
    return 0


def cmd_arm():
    if not mc.is_admin():
        sys.exit("需要管理员权限（SACL/auditpol/Security 日志）。")
    reg = mc.MineRegistry()
    ok, msg = mc.ensure_audit_policy()
    if not ok:
        sys.exit("布雷失败：" + msg)
    print(f"[ARM] 审计已启用：File System + Process Creation（{msg}）")
    for m in reg.mines:
        if not m.exists:
            print(f"[SKIP] 目录不存在：{m.path}")
            continue
        aok, amsg = mc.arm_sacl(m.path)
        pok, pmsg = mc.propagate_sacl(m.path) if aok else (False, "skipped")
        present, detail = mc.sacl_present(m.path)
        m.armed = present
        mc.log("ARM", mine=m.id, path=m.path, sacl=amsg, propagate=pmsg,
               sacl_present=present)
        print(f"[ARM] {'已布雷' if present else '未生效'}：{m.path} "
              f"（{amsg} / 传播 {pmsg}）")
    return 0


def cmd_disarm():
    if not mc.is_admin():
        sys.exit("需要管理员权限。")
    reg = mc.MineRegistry()
    for m in reg.mines:
        ok, msg = mc.disarm_sacl(m.path)
        m.armed = False
        mc.log("DISARM", mine=m.id, path=m.path, sacl=msg)
        print(f"[DISARM] {m.path}: {msg}")
    restored = mc.restore_cmd_policy()
    print(f"[DISARM] 4688 命令行策略: {restored}")
    print("[DISARM] auditpol 子类别保留启用（无 ACE 时不产生事件，属无害常态）")
    print(f"        如需关闭：auditpol /set /subcategory:{mc.FS_SUBCAT} "
          f"/success:disable")
    return 0


def cmd_status():
    reg = mc.MineRegistry()
    v = mc.read_pid()
    others = [p for p in mc.find_other_instances() if p != v]
    if v:
        print("运行中 PID :", v)
    elif others:
        print("运行中 PID : 未记录（但有命令行实例）")
    else:
        print("运行中 PID : 未运行")
    if others:
        print("命令行实例 :", others)
    for m in reg.mines:
        present, _ = mc.sacl_present(m.path)
        m.armed = present
        state = "缺失目录" if not m.exists else (
            "已布雷" if present else "未布雷")
        print(f"  地雷 {m.id} [{m.action}] "
              f"{'启用' if m.enabled else '停用'} {state}  {m.path}")
    print("上传监视   :", "启用" if reg.settings.get("upload_monitor")
          else "关闭")
    return 0


def cmd_stop():
    """停止地雷。不依赖 pid 文件——命令行实例同样会被收掉。"""
    v = mc.read_pid()
    victims = sorted(set(([v] if v else []) + mc.find_other_instances()))
    if not victims:
        print("地雷未在运行。")
        mc.clear_pid()
        return 0
    for pid in victims:
        subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                       capture_output=True, errors="replace")
    mc.log("STOP", pids=victims)
    print(f"[STOP] 已终止 PID {victims}（SACL 仍在，可用 --disarm 排雷）")
    return 0


def cmd_list():
    reg = mc.MineRegistry()
    print(f"清单文件：{reg.path}")
    print(f"默认动作：{reg.settings.get('action')}    上传监视："
          f"{'开' if reg.settings.get('upload_monitor') else '关'}")
    if not reg.mines:
        print("（空）")
    for m in reg.mines:
        print(f"  {m.id}  [{'启用' if m.enabled else '停用'}]  "
              f"{m.action:<7}  {m.path}")
    return 0


def cmd_run(dry_run=False, strict_orphans=False):
    if not mc.is_admin():
        sys.exit("需要管理员权限运行地雷（4688/4663 事件在 Security 日志）。")
    others = mc.find_other_instances()
    if others:
        sys.exit(f"已有地雷实例在运行（PID {others}）。"
                 f"先 python potato_mine.py --stop，或手动结束这些进程。")
    pid = mc.read_pid()
    if pid and pid != os.getpid():
        sys.exit(f"已有守护进程占位于 PID {pid}（可能是 webui.py 控制台）。")
    reg = mc.MineRegistry()
    sup = mc.MineSupervisor(reg, strict_orphans=strict_orphans,
                            force_warn=dry_run)
    sup.start()
    try:
        while sup.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[STOP] 收到中断，正在停止…", flush=True)
        sup.stop()
    return 0


def main():
    ap = argparse.ArgumentParser(description="Potato Mine（土豆地雷）")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--arm", action="store_true")
    ap.add_argument("--disarm", action="store_true")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--dry-run", action="store_true",
                    help="只记录不击杀（等价于把触发动作设为「警告」）")
    ap.add_argument("--strict-orphans", action="store_true",
                    help="对高危孤儿进程也击杀（默认只告警）")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--stop", action="store_true")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()

    if a.check:
        return cmd_check()
    if a.arm:
        return cmd_arm()
    if a.disarm:
        return cmd_disarm()
    if a.status:
        return cmd_status()
    if a.stop:
        return cmd_stop()
    if a.list:
        return cmd_list()
    if a.run:
        return cmd_run(dry_run=a.dry_run, strict_orphans=a.strict_orphans)
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
