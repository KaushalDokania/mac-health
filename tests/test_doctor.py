#!/usr/bin/env python3
"""
Unit and integration tests for mac-health v2.0 Phase 1 Diagnostics Engine.
Tests:
  - SIP Unprivileged Thread Sampling Fallback Ladder (Tiers A -> B -> C)
  - Process Lineage Tree Resolver & App Annotation
  - Execution Context (args, cwd, git repo/branch)
  - Open File Descriptors, Socket Extraction, Lock Detection (.lock, index.lock, *.wal, flock)
  - System Daemon Diagnostics (WindowServer & mds_stores developer dir thrashing)
  - Comprehensive Process Diagnostic Integration
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock
import subprocess

# Ensure the worktree root is on the path so diagnostics can be imported directly
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import diagnostics


class TestThreadSampling(unittest.TestCase):
    """Tests for SIP Unprivileged Thread Sampling Fallback Ladder (Tiers A, B, C)."""

    def test_parse_sample_output_collapsed(self):
        sample_txt = """
Analysis of sampling zsh (pid 47958) every 1 millisecond
Call graph:
    867 Thread_12856396   DispatchQueue_1: com.apple.main-thread  (serial)
      867 start  (in dyld) + 6688  [0x1930bbe80]
        867 zsh_main  (in zsh) + 1316  [0x100e6ce8c]

Total number in stack (recursive counted multiple, when >=5):

Sort by top of stack, same collapsed (when >= 5):
        __sigsuspend  (in libsystem_kernel.dylib)        867
        kevent  (in libsystem_kernel.dylib)              120
        select  (in libsystem_kernel.dylib)               45

Binary Images:
        0x100e3c000 -        0x100ec124f +zsh (118) /bin/zsh
"""
        symbols = diagnostics.parse_sample_output(sample_txt)
        self.assertEqual(len(symbols), 3)
        self.assertEqual(symbols[0]["symbol"], "__sigsuspend (in libsystem_kernel.dylib)")
        self.assertEqual(symbols[0]["count"], 867)
        self.assertEqual(symbols[1]["symbol"], "kevent (in libsystem_kernel.dylib)")
        self.assertEqual(symbols[1]["count"], 120)
        self.assertEqual(symbols[2]["symbol"], "select (in libsystem_kernel.dylib)")
        self.assertEqual(symbols[2]["count"], 45)

    def test_parse_sample_output_call_graph_fallback(self):
        sample_txt = """
Call graph:
    100 Thread_1
      100 main_entry  (in myapp) + 120
        60 compute_heavy  (in myapp) + 80
        40 io_wait  (in libsystem_kernel.dylib) + 12
"""
        symbols = diagnostics.parse_sample_output(sample_txt)
        self.assertTrue(len(symbols) >= 2)
        sym_names = [s["symbol"] for s in symbols]
        self.assertIn("main_entry (in myapp)", sym_names)
        self.assertIn("compute_heavy (in myapp)", sym_names)

    @patch("diagnostics.run_command")
    def test_sample_tier_a_success(self, mock_run):
        mock_output = """
Analysis of sampling python (pid 1234)
Sort by top of stack, same collapsed (when >= 5):
        PyEval_EvalFrameDefault  (in Python)        500
"""
        mock_run.return_value = (0, mock_output, "")
        res = diagnostics.sample_tier_a(1234)
        self.assertIsNotNone(res)
        self.assertEqual(res["tier"], "A")
        self.assertEqual(res["method"], "sample")
        self.assertTrue(res["success"])
        self.assertEqual(res["pid"], 1234)
        self.assertEqual(res["top_symbol"], "PyEval_EvalFrameDefault (in Python)")

    @patch("diagnostics.run_command")
    def test_sample_tier_a_permission_denied_sip(self, mock_run):
        mock_stderr = "sample[1234]: sample cannot examine process 1 (launchd) because you do not have appropriate privileges to examine it; try running with `sudo`."
        mock_run.return_value = (255, "", mock_stderr)
        res = diagnostics.sample_tier_a(1)
        self.assertIsNone(res)

    @patch("diagnostics.run_command")
    def test_sample_tier_a_timeout(self, mock_run):
        mock_run.return_value = (-1, "", "Command timed out")
        res = diagnostics.sample_tier_a(1234)
        self.assertIsNone(res)

    def test_parse_ps_m_output(self):
        ps_output = """
USER   PID   TT   %CPU STAT PRI     STIME     UTIME COMMAND   PID STAT PRI   WQ   TT  STAT      TIME COMMAND
root   341   ??    0.1 S    49T   0:34.86   1:52.61 /System   341 S    49T    1   ??  S      9:39.00 /System/Support/fseventsd
       341         0.0 S    31T   0:00.00   0:00.00           341 S    31T    1       S      9:39.00 
       341         1.5 R    50R   0:17.54   0:02.11           341 R    50R    1       R      9:39.00 
       341         0.0 U    20T   0:00.01   0:00.00           341 U    20T    1       U      9:39.00 
       341         0.0 I    31T   0:00.00   0:00.00           341 I    31T    1       I      9:39.00 
"""
        res = diagnostics.parse_ps_m_output(ps_output)
        self.assertEqual(res["total"], 5)
        self.assertEqual(res["running"], 1)
        self.assertEqual(res["disk_wait"], 1)
        self.assertEqual(res["sleeping"], 3)  # 'S' and 'I'
        self.assertEqual(len(res["threads"]), 5)
        self.assertTrue(res["threads"][2]["is_running"])
        self.assertTrue(res["threads"][3]["is_disk_wait"])

    @patch("diagnostics.run_command")
    def test_sample_tier_b_success(self, mock_run):
        mock_ps = """
USER   PID   TT   %CPU STAT PRI     STIME     UTIME COMMAND   PID STAT PRI   WQ   TT  STAT      TIME COMMAND
user  2000   ??    0.0 S    31T   0:00.05   0:00.02 /bin/zsh  2000 S    31T    -   ??  S      0:01.00 /bin/zsh
      2000         0.0 R    37T   0:00.10   0:00.05           2000 R    37T    -       R      0:01.00 
"""
        mock_run.return_value = (0, mock_ps, "")
        res = diagnostics.sample_tier_b(2000)
        self.assertIsNotNone(res)
        self.assertEqual(res["tier"], "B")
        self.assertEqual(res["method"], "ps_threads")
        self.assertEqual(res["thread_counts"]["running"], 1)
        self.assertEqual(res["thread_counts"]["sleeping"], 1)
        self.assertEqual(res["thread_counts"]["total"], 2)

    def test_parse_ps_time(self):
        self.assertAlmostEqual(diagnostics.parse_ps_time("0:00.08"), 0.08)
        self.assertAlmostEqual(diagnostics.parse_ps_time("1:23.45"), 83.45)
        self.assertAlmostEqual(diagnostics.parse_ps_time("01:02:03.45"), 3723.45)
        self.assertAlmostEqual(diagnostics.parse_ps_time("2-01:02:03"), 176523.0)
        self.assertAlmostEqual(diagnostics.parse_ps_time("12.34"), 12.34)
        self.assertAlmostEqual(diagnostics.parse_ps_time("-"), 0.0)
        self.assertAlmostEqual(diagnostics.parse_ps_time(""), 0.0)

    @patch("time.sleep", return_value=None)
    @patch("diagnostics.run_command")
    def test_measure_cpu_delta_tier_c(self, mock_run, mock_sleep):
        # Sample 0: utime 0:01.00, stime 0:00.50 -> 1.5s total CPU
        # Sample 1: utime 0:01.20, stime 0:00.55 -> 1.75s total CPU
        # Delta = 0.25s over interval 0.25s => ~100% CPU (1 core saturation)
        mock_run.side_effect = [
            (0, "0:01.00 0:00.50\n", ""),
            (0, "0:01.20 0:00.55\n", "")
        ]
        res = diagnostics.measure_cpu_delta(4500, interval=0.25)
        self.assertEqual(res["tier"], "C")
        self.assertEqual(res["method"], "cpu_delta")
        self.assertTrue(res["success"])
        self.assertEqual(res["pid"], 4500)
        self.assertGreater(res["cpu_percent"], 0.0)
        self.assertGreater(res["core_saturation_rate"], 0.0)

    @patch("diagnostics.sample_tier_a", return_value=None)
    @patch("diagnostics.sample_tier_b")
    def test_sample_process_fallback_to_tier_b(self, mock_tier_b, mock_tier_a):
        mock_tier_b.return_value = {
            "tier": "B",
            "method": "ps_threads",
            "success": True,
            "pid": 500,
            "thread_counts": {"running": 1, "disk_wait": 0, "sleeping": 2, "other": 0, "total": 3},
            "threads": [],
        }
        res = diagnostics.sample_process(500)
        mock_tier_a.assert_called_once_with(500, timeout=1.5)
        mock_tier_b.assert_called_once_with(500)
        self.assertEqual(res["tier"], "B")

    @patch("diagnostics.sample_tier_a", return_value=None)
    @patch("diagnostics.sample_tier_b", return_value=None)
    @patch("diagnostics.sample_tier_c")
    def test_sample_process_fallback_to_tier_c(self, mock_tier_c, mock_tier_b, mock_tier_a):
        mock_tier_c.return_value = {
            "tier": "C",
            "method": "cpu_delta",
            "success": True,
            "pid": 500,
            "cpu_percent": 15.0,
            "core_saturation_rate": 0.15,
        }
        res = diagnostics.sample_process(500)
        self.assertEqual(res["tier"], "C")
        mock_tier_c.assert_called_once()


class TestProcessLineage(unittest.TestCase):
    """Tests for Recursive Process Lineage Tree Resolver & App Annotations."""

    def test_annotate_app(self):
        cases = [
            ("/Applications/Cursor.app/Contents/MacOS/Cursor", "", "Cursor.app"),
            ("Cursor", "", "Cursor.app"),
            ("/Applications/Visual Studio Code.app/Contents/MacOS/Electron", "", "Code.app"),
            ("Code Helper (Plugin)", "", "Code.app"),
            ("code", "", "Code.app"),
            ("/Applications/iTerm.app/Contents/MacOS/iTerm2", "", "iTerm2.app"),
            ("iTerm2", "", "iTerm2.app"),
            ("/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", "", "Terminal.app"),
            ("Terminal", "", "Terminal.app"),
            ("tmux: server (/tmp/tmux-501/default)", "", "tmux"),
            ("/usr/local/bin/tmux", "", "tmux"),
            ("python3", "/path/to/antigravity/server.py", "antigravity"),
            ("/Applications/Slack.app/Contents/MacOS/Slack", "", "Slack.app"),
            ("/bin/zsh", "", None),
            ("/sbin/launchd", "", None),
        ]
        for comm, args, expected in cases:
            with self.subTest(comm=comm, args=args):
                self.assertEqual(diagnostics.annotate_app(comm, args), expected)

    @patch("diagnostics.run_command")
    def test_get_process_info(self, mock_run):
        mock_run.return_value = (0, "    1 /Applications/Cursor.app/Contents/MacOS/Cursor kaushal\n", "")
        info = diagnostics.get_process_info(5001)
        self.assertIsNotNone(info)
        self.assertEqual(info["pid"], 5001)
        self.assertEqual(info["ppid"], 1)
        self.assertEqual(info["comm"], "/Applications/Cursor.app/Contents/MacOS/Cursor")
        self.assertEqual(info["user"], "kaushal")
        self.assertEqual(info["app"], "Cursor.app")
        self.assertFalse(info["is_launchd"])

    @patch("diagnostics.get_process_info")
    def test_resolve_process_lineage_chain(self, mock_info):
        # Process chain: 3000 (python) -> 2000 (zsh) -> 1000 (Cursor.app) -> 1 (launchd)
        mock_info.side_effect = lambda p: {
            3000: {"pid": 3000, "ppid": 2000, "comm": "python3", "user": "kaushal", "app": None, "is_launchd": False},
            2000: {"pid": 2000, "ppid": 1000, "comm": "/bin/zsh", "user": "kaushal", "app": None, "is_launchd": False},
            1000: {"pid": 1000, "ppid": 1, "comm": "/Applications/Cursor.app/Contents/MacOS/Cursor", "user": "kaushal", "app": "Cursor.app", "is_launchd": False},
            1:    {"pid": 1, "ppid": 0, "comm": "/sbin/launchd", "user": "root", "app": None, "is_launchd": True},
        }.get(p)

        lineage = diagnostics.resolve_process_lineage(3000)
        self.assertEqual(lineage["pid"], 3000)
        self.assertEqual(lineage["depth"], 4)
        pids = [n["pid"] for n in lineage["lineage"]]
        self.assertEqual(pids, [3000, 2000, 1000, 1])
        self.assertEqual(lineage["parent_app"], "Cursor.app")
        self.assertFalse(lineage["is_daemon_or_agent"])
        self.assertEqual(lineage["root_ancestor"]["pid"], 1)
        self.assertTrue(lineage["root_ancestor"]["is_launchd"])

    @patch("diagnostics.get_process_info")
    def test_resolve_process_lineage_daemon_flag(self, mock_info):
        # Daemon directly launched by launchd: PID 400 (daemon) -> PID 1 (launchd)
        mock_info.side_effect = lambda p: {
            400: {"pid": 400, "ppid": 1, "comm": "/usr/libexec/mydaemon", "user": "root", "app": None, "is_launchd": False},
            1:   {"pid": 1, "ppid": 0, "comm": "/sbin/launchd", "user": "root", "app": None, "is_launchd": True},
        }.get(p)

        lineage = diagnostics.resolve_process_lineage(400)
        self.assertTrue(lineage["is_daemon_or_agent"])
        self.assertIsNone(lineage["parent_app"])

    @patch("diagnostics.get_process_info")
    def test_resolve_process_lineage_cycle_prevention(self, mock_info):
        # Simulated corrupted cycle: 100 -> 200 -> 100
        mock_info.side_effect = lambda p: {
            100: {"pid": 100, "ppid": 200, "comm": "procA", "user": "u", "app": None, "is_launchd": False},
            200: {"pid": 200, "ppid": 100, "comm": "procB", "user": "u", "app": None, "is_launchd": False},
        }.get(p)

        lineage = diagnostics.resolve_process_lineage(100)
        self.assertEqual(len(lineage["lineage"]), 2)


class TestExecutionContext(unittest.TestCase):
    """Tests for Execution Context (arguments, cwd, git context)."""

    @patch("diagnostics.run_command")
    def test_get_process_args(self, mock_run):
        mock_run.return_value = (0, "python3 -m unittest tests/test_doctor.py\n", "")
        args = diagnostics.get_process_args(1234)
        self.assertEqual(args, "python3 -m unittest tests/test_doctor.py")

    def test_parse_lsof_cwd(self):
        raw = "p46067\nfcwd\ntDIR\nn/Users/kaushaldokania/repo\n"
        cwd = diagnostics.parse_lsof_cwd(raw)
        self.assertEqual(cwd, "/Users/kaushaldokania/repo")

    def test_get_git_context_in_current_repo(self):
        # Current worktree is a valid git repository/worktree
        git_info = diagnostics.get_git_context(PROJECT_ROOT)
        self.assertIsNotNone(git_info)
        self.assertTrue(git_info["is_repo"])
        self.assertTrue(len(git_info["branch"]) > 0)
        self.assertTrue(len(git_info["repo_name"]) > 0)

    def test_get_git_context_non_git_dir(self):
        git_info = diagnostics.get_git_context("/tmp")
        # /tmp is typically not a git repo
        if git_info is not None:
            self.assertTrue(isinstance(git_info, dict))
        else:
            self.assertIsNone(git_info)

    @patch("diagnostics.get_process_args", return_value="node server.js")
    @patch("diagnostics.get_process_cwd", return_value="/app")
    @patch("diagnostics.get_git_context", return_value={"is_repo": True, "branch": "main", "repo_name": "app", "repo_root": "/app"})
    def test_get_process_execution_context(self, mock_git, mock_cwd, mock_args):
        ctx = diagnostics.get_process_execution_context(999)
        self.assertEqual(ctx["pid"], 999)
        self.assertEqual(ctx["args"], "node server.js")
        self.assertEqual(ctx["cwd"], "/app")
        self.assertIsNotNone(ctx["git"])
        self.assertEqual(ctx["git"]["branch"], "main")


class TestDescriptorsAndLocks(unittest.TestCase):
    """Tests for Open Descriptors, Socket Extraction, and Lock Detection."""

    def test_parse_lsof_descriptors(self):
        raw = """p1234
fcwd
tDIR
n/Users/kaushaldokania/repo
ftxt
tREG
n/usr/bin/python3
f0
tCHR
n/dev/ttys000
f1
tCHR
n/dev/ttys000
f2
tCHR
n/dev/ttys000
f3
tIPv4
n*:8080
f4
tIPv4
n127.0.0.1:51234->93.184.216.34:443
f5
tIPv6
n*:9090
f6
tREG
n/path/to/project/.git/index.lock
f7
tREG
n/var/data/state.lock
f8
tREG
n/var/data/app.db-wal
f9
tREG
n/tmp/worker.flock
"""
        parsed = diagnostics.parse_lsof_descriptors(raw)
        self.assertEqual(parsed["fd_count"], 10)  # f0 through f9
        self.assertEqual(parsed["total_descriptors"], 12)  # includes cwd and txt

        # Sockets
        sockets = parsed["sockets"]
        self.assertEqual(len(sockets), 3)

        # Listening socket
        listen_sock = next(s for s in sockets if s["fd"] == "3")
        self.assertEqual(listen_sock["status"], "LISTEN")
        self.assertEqual(listen_sock["local_port"], 8080)
        self.assertIsNone(listen_sock["remote_ip"])

        # Established socket
        estab_sock = next(s for s in sockets if s["fd"] == "4")
        self.assertEqual(estab_sock["status"], "ESTABLISHED")
        self.assertEqual(estab_sock["remote_ip"], "93.184.216.34")
        self.assertEqual(estab_sock["remote_port"], 443)
        self.assertEqual(estab_sock["local_port"], 51234)

        # Locks (.lock, .git/index.lock, *.wal, flock)
        locks = parsed["locks"]
        self.assertEqual(len(locks), 4)
        self.assertTrue(parsed["has_locks"])

        lock_types = {l["lock_type"] for l in locks}
        self.assertIn("git_index_lock", lock_types)
        self.assertIn("file_lock", lock_types)
        self.assertIn("sqlite_wal_lock", lock_types)
        self.assertIn("flock", lock_types)

    @patch("diagnostics.run_command")
    def test_get_process_descriptors_and_locks_integration(self, mock_run):
        mock_run.return_value = (0, "p555\nf0\ntCHR\nn/dev/null\nf1\ntIPv4\nn*:3000\n", "")
        res = diagnostics.get_process_descriptors_and_locks(555)
        self.assertEqual(res["pid"], 555)
        self.assertEqual(res["fd_count"], 2)
        self.assertEqual(res["socket_count"], 1)
        self.assertFalse(res["has_locks"])


class TestSystemDaemonDiagnostics(unittest.TestCase):
    """Tests for WindowServer and mds_stores Diagnostics."""

    @patch("diagnostics.run_command")
    def test_diagnose_windowserver(self, mock_run):
        ps_out = """  PID  %CPU  %MEM COMMAND
  190  12.5   2.1 /System/Library/Frameworks/CoreGraphics.framework/WindowServer
 2500  45.0   8.0 /Applications/Cursor.app/Contents/MacOS/Cursor
 3100  10.0   4.0 /Applications/iTerm.app/Contents/MacOS/iTerm2
 4200   0.5   0.2 /bin/zsh
"""
        # Call 1: ps for WindowServer and GUI consumers
        # Call 2: log show
        mock_run.side_effect = [
            (0, ps_out, ""),
            (0, "Timestamp com.apple.SkyLight: display update nominal\n", "")
        ]

        res = diagnostics.diagnose_windowserver()
        self.assertEqual(res["daemon"], "WindowServer")
        self.assertEqual(res["pid"], 190)
        self.assertEqual(res["cpu_percent"], 12.5)
        self.assertEqual(res["status"], "HEALTHY")
        self.assertTrue(len(res["top_gui_consumers"]) >= 2)
        self.assertEqual(res["top_gui_consumers"][0]["app_name"], "Cursor.app")
        self.assertTrue(res["skylight_logs"]["available"])

    def test_parse_mds_stores_paths_thrashing(self):
        raw = """p600
n/Users/kaushal/project/node_modules/react/index.js
n/Users/kaushal/project/.git/objects/pack/pack-abc.pack
n/Users/kaushal/rust_proj/target/debug/build/foo.o
n/System/Library/Fonts/SFNS.ttf
"""
        res = diagnostics.parse_mds_stores_paths(raw)
        self.assertEqual(res["path_count"], 4)
        self.assertTrue(res["thrashing_detected"])
        self.assertEqual(res["status"], "INDEXING_DEV_DIRS")

        patterns = {d["pattern"] for d in res["detected_developer_dirs"]}
        self.assertIn("node_modules", patterns)
        self.assertIn(".git", patterns)
        self.assertIn("target", patterns)

    def test_parse_mds_stores_paths_idle(self):
        raw = """p600
n/System/Library/Fonts/SFNS.ttf
n/Users/kaushal/Documents/notes.txt
"""
        res = diagnostics.parse_mds_stores_paths(raw)
        self.assertEqual(res["path_count"], 2)
        self.assertFalse(res["thrashing_detected"])
        self.assertEqual(res["status"], "NORMAL")


class TestComprehensiveDiagnoseProcess(unittest.TestCase):
    """End-to-end integration test for master diagnose_process function."""

    @patch("diagnostics.resolve_process_lineage")
    @patch("diagnostics.get_process_execution_context")
    @patch("diagnostics.get_process_descriptors_and_locks")
    @patch("diagnostics.sample_process")
    def test_diagnose_process_composite(self, mock_sample, mock_desc, mock_ctx, mock_lineage):
        mock_lineage.return_value = {
            "pid": 12345,
            "lineage": [{"pid": 12345, "ppid": 1, "comm": "python3", "app": None, "is_launchd": False}],
            "parent_app": None,
            "is_daemon_or_agent": True,
        }
        mock_ctx.return_value = {
            "pid": 12345,
            "args": "python3 worker.py",
            "cwd": "/app",
            "git": None,
        }
        mock_desc.return_value = {
            "pid": 12345,
            "fd_count": 5,
            "sockets": [],
            "locks": [],
            "has_locks": False,
        }
        mock_sample.return_value = {
            "tier": "B",
            "method": "ps_threads",
            "success": True,
            "pid": 12345,
            "thread_counts": {"running": 1, "disk_wait": 0, "sleeping": 2, "other": 0, "total": 3},
        }

        report = diagnostics.diagnose_process(12345)
        self.assertEqual(report["pid"], 12345)
        self.assertIn("lineage", report)
        self.assertIn("execution_context", report)
        self.assertIn("descriptors", report)
        self.assertIn("thread_sampling", report)
        self.assertIn("timestamp", report)
        self.assertTrue(report["lineage"]["is_daemon_or_agent"])
        self.assertEqual(report["thread_sampling"]["tier"], "B")


class TestReportFormatters(unittest.TestCase):
    """Tests for ANSI terminal report formatters."""

    def test_format_doctor_report(self):
        sample_report = {
            "pid": 4567,
            "lineage": {
                "comm": "python3",
                "parent_app": "Cursor.app",
                "is_launchd_child": False,
                "chain": [
                    {"pid": 1, "comm": "launchd", "app": None},
                    {"pid": 100, "comm": "Cursor", "app": "Cursor.app"},
                    {"pid": 4567, "comm": "python3", "app": None},
                ]
            },
            "execution_context": {
                "cwd": "/Users/kaushal/project",
                "args": "python3 script.py",
                "git": {"repository": "project", "branch": "main", "dirty": False}
            },
            "descriptors": {
                "total_open_descriptors": 10,
                "tcp_sockets": [{"name": "127.0.0.1:8000", "state": "LISTEN", "type": "TCP"}],
                "active_locks": [{"path": "/tmp/test.lock", "type": "flock"}]
            },
            "thread_sampling": {
                "tier_used": "tier_a",
                "status": "OK",
                "sample": {
                    "symbols": [{"symbol": "PyEval_EvalFrame", "count": 25, "library": "Python"}]
                }
            }
        }
        output = diagnostics.format_doctor_report(sample_report)
        self.assertIn("Process Diagnostic for PID 4567", output)
        self.assertIn("Cursor.app", output)
        self.assertIn("/Users/kaushal/project", output)
        self.assertIn("127.0.0.1:8000", output)
        self.assertIn("/tmp/test.lock", output)
        self.assertIn("PyEval_EvalFrame", output)

    def test_format_windowserver_report(self):
        ws_report = {
            "pid": 500,
            "cpu_percent": 15.2,
            "mem_percent": 3.4,
            "status": "HEALTHY",
            "top_gui_consumers": [
                {"pid": 1234, "comm": "Cursor", "cpu_percent": 12.0, "mem_percent": 2.1}
            ],
            "skylight_logs": {"summary": "2 log entries", "entries": ["log line 1"]}
        }
        output = diagnostics.format_windowserver_report(ws_report)
        self.assertIn("WindowServer", output)
        self.assertIn("Cursor", output)
        self.assertIn("HEALTHY", output)

    def test_format_mds_stores_report(self):
        mds_report = {
            "pid": 600,
            "cpu_percent": 85.0,
            "mem_percent": 1.5,
            "status": "INDEXING_DEV_DIRS",
            "thrashing_detected": True,
            "path_count": 50,
            "detected_developer_dirs": [
                {"matched_dir": "/repo/node_modules", "pattern": "node_modules"}
            ]
        }
        output = diagnostics.format_mds_stores_report(mds_report)
        self.assertIn("mds_stores", output)
        self.assertIn("node_modules", output)
        self.assertIn("WARNING", output)


if __name__ == "__main__":
    unittest.main()
