#!/usr/bin/env python3
"""
Unit tests for mac-health v2.0 Phase 2:
- Safety Shield (safety.py)
- Tiered Remediation Engine (remediation.py)
- Zero-Dep Single-Key TUI Engine (tui.py)
"""

import os
import sys
import time
import json
import signal
import termios
import tempfile
import unittest
import subprocess
from unittest.mock import patch, MagicMock

# Ensure parent directory is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import safety
import remediation
import tui


class TestSafetyShield(unittest.TestCase):
    """Tests for safety.py system whitelist and permission rules."""

    def test_system_whitelist_immutability(self):
        """SYSTEM_WHITELIST must be a frozenset containing critical macOS system processes."""
        self.assertIsInstance(safety.SYSTEM_WHITELIST, frozenset)
        expected = {"kernel_task", "launchd", "WindowServer", "loginwindow", "opendirectoryd", "sysmond"}
        for proc in expected:
            self.assertIn(proc, safety.SYSTEM_WHITELIST)

    def test_pid_zero_and_one_blocked(self):
        """PID <= 1 (kernel_task and launchd) must never be permitted."""
        permitted, reason = safety.is_action_permitted(0, "kernel_task")
        self.assertFalse(permitted)
        self.assertIn("PID 0", reason)

        permitted, reason = safety.is_action_permitted(1, "launchd")
        self.assertFalse(permitted)
        self.assertIn("PID 1", reason)

        permitted, reason = safety.is_action_permitted(-5, "invalid")
        self.assertFalse(permitted)

    def test_system_whitelist_processes_blocked(self):
        """Every process in SYSTEM_WHITELIST must be blocked regardless of PID (>1)."""
        for proc in safety.SYSTEM_WHITELIST:
            permitted, reason = safety.is_action_permitted(100, proc)
            self.assertFalse(permitted, f"Expected {proc} to be blocked by system whitelist")
            self.assertIn("system whitelist", reason.lower())

    def test_system_whitelist_full_paths_blocked(self):
        """Full binary paths to whitelisted daemons must be recognized via basename."""
        paths = [
            "/System/Library/CoreServices/WindowServer",
            "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow",
            "/usr/libexec/opendirectoryd",
            "/usr/libexec/sysmond",
            "/sbin/launchd",
        ]
        for path in paths:
            permitted, reason = safety.is_action_permitted(250, path)
            self.assertFalse(permitted, f"Expected {path} to be blocked")

    def test_user_whitelist_from_config(self):
        """Processes in user whitelist (~/.config/mac-health/config.json) must be protected."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            json.dump({"whitelist": ["Ghostty", "Cursor", "com.apple.Safari"]}, tf)
            cfg_path = tf.name

        try:
            # Ghostty should now be protected
            permitted, reason = safety.is_action_permitted(1000, "Ghostty", config_path=cfg_path)
            self.assertFalse(permitted)
            self.assertIn("user whitelist", reason.lower())

            # Path match
            permitted, reason = safety.is_action_permitted(1001, "/Applications/Ghostty.app/Contents/MacOS/Ghostty", config_path=cfg_path)
            self.assertFalse(permitted)

            # Non-whitelisted should be permitted
            permitted, reason = safety.is_action_permitted(1002, "stress_runaway", config_path=cfg_path)
            self.assertTrue(permitted)
        finally:
            if os.path.exists(cfg_path):
                os.unlink(cfg_path)

    def test_save_and_load_user_whitelist(self):
        """Test saving and loading user whitelist to custom configuration path."""
        with tempfile.TemporaryDirectory() as td:
            cfg_path = os.path.join(td, "config.json")
            wl = {"Slack", "Discord", "Docker"}
            ok = safety.save_user_whitelist(wl, config_path=cfg_path)
            self.assertTrue(ok)

            loaded = safety.load_user_whitelist(config_path=cfg_path)
            self.assertEqual(loaded, wl)

    def test_user_whitelist_corrupted_json(self):
        """Loading a corrupted or non-existent config file must return an empty set safely."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            tf.write("INVALID JSON CONTENT")
            corrupt_path = tf.name

        try:
            wl = safety.load_user_whitelist(config_path=corrupt_path)
            self.assertEqual(wl, set())

            wl_missing = safety.load_user_whitelist(config_path="/nonexistent/path/config.json")
            self.assertEqual(wl_missing, set())
        finally:
            if os.path.exists(corrupt_path):
                os.unlink(corrupt_path)


class TestRemediationEngine(unittest.TestCase):
    """Tests for remediation.py tiered actions."""

    def setUp(self):
        # Use an isolated frozen records file for tests
        self.orig_frozen_file = remediation.FROZEN_RECORDS_FILE
        self.test_frozen_file = tempfile.mktemp(suffix="_frozen.json")
        remediation.FROZEN_RECORDS_FILE = self.test_frozen_file

    def tearDown(self):
        if os.path.exists(self.test_frozen_file):
            try:
                os.unlink(self.test_frozen_file)
            except Exception:
                pass
        remediation.FROZEN_RECORDS_FILE = self.orig_frozen_file

    # --- Tier 1: Apple Silicon QoS Clamping ---

    def test_tame_ecores_safety_block(self):
        """Taming protected processes (PID 1 or WindowServer) must be blocked."""
        self.assertFalse(remediation.tame_process_to_ecores(1))
        with patch("remediation.get_comm_for_pid", return_value="WindowServer"):
            self.assertFalse(remediation.tame_process_to_ecores(500))

    @patch("subprocess.run")
    @patch("remediation.get_comm_for_pid", return_value="node_runaway")
    def test_tame_ecores_invokes_taskpolicy_and_renice(self, mock_comm, mock_run):
        """tame_process_to_ecores must invoke taskpolicy -b -p, taskpolicy -d throttle -p, and renice +19 -p."""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        result = remediation.tame_process_to_ecores(1234)
        self.assertTrue(result)

        called_cmds = [call_args[0][0] for call_args in mock_run.call_args_list]
        self.assertIn(["taskpolicy", "-b", "-p", "1234"], called_cmds)
        self.assertIn(["taskpolicy", "-d", "throttle", "-p", "1234"], called_cmds)
        self.assertIn(["renice", "+19", "-p", "1234"], called_cmds)

    # --- Tier 2: Freeze & Resume ---

    def test_freeze_safety_block(self):
        """Freezing protected processes must return (False, reason)."""
        ok, reason = remediation.freeze_process(1)
        self.assertFalse(ok)
        self.assertIn("Safety Shield", reason)

        with patch("remediation.get_comm_for_pid", return_value="sysmond"):
            ok, reason = remediation.freeze_process(200)
            self.assertFalse(ok)
            self.assertIn("Safety Shield", reason)

    def test_freeze_nonexistent_pid(self):
        """Freezing a nonexistent PID returns False."""
        ok, reason = remediation.freeze_process(999999)
        self.assertFalse(ok)
        self.assertIn("not found", reason.lower())

    def test_freeze_and_unfreeze_live_process(self):
        """Tests live SIGSTOP and SIGCONT cycle on a spawned child process."""
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        pid = proc.pid
        try:
            # Freeze the process
            ok, msg = remediation.freeze_process(pid)
            self.assertTrue(ok)
            self.assertIn("suspended via SIGSTOP", msg)

            # Verify recorded in frozen file
            records = remediation.get_frozen_processes()
            self.assertIn(str(pid), records)
            self.assertEqual(records[str(pid)]["pid"], pid)

            # Unfreeze the process
            resumed = remediation.unfreeze_process(pid)
            self.assertTrue(resumed)

            # Verify removed from records
            records_after = remediation.get_frozen_processes()
            self.assertNotIn(str(pid), records_after)
        finally:
            proc.kill()
            proc.wait()

    def test_auto_resume_expired_frozen_processes(self):
        """auto_resume_frozen_processes must unfreeze entries older than max_age_seconds."""
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        pid = proc.pid
        try:
            ok, _ = remediation.freeze_process(pid)
            self.assertTrue(ok)

            # Artificially age the frozen record
            records = remediation.get_frozen_processes()
            records[str(pid)]["frozen_at"] = time.time() - 400.0  # 400s ago
            remediation._save_frozen_records(records)

            # Sweep with 300s limit
            resumed_pids = remediation.auto_resume_frozen_processes(max_age_seconds=300.0)
            self.assertIn(pid, resumed_pids)
            self.assertNotIn(str(pid), remediation.get_frozen_processes())
        finally:
            proc.kill()
            proc.wait()

    def test_freeze_process_with_active_locks_warning(self):
        """freeze_process includes warning when process holds locks."""
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        pid = proc.pid
        try:
            with patch("remediation.get_open_descriptors_and_locks", return_value={"has_locks": True, "locks": ["FLOCK"], "sockets": []}):
                ok, msg = remediation.freeze_process(pid)
                self.assertTrue(ok)
                self.assertIn("Warning: process holds active file/socket locks", msg)
        finally:
            proc.kill()
            proc.wait()

    def test_unfreeze_process_already_dead_cleans_records(self):
        """unfreeze_process gracefully cleans up record even if process is already dead."""
        fake_pid = 777777
        records = {str(fake_pid): {"pid": fake_pid, "comm": "dead_proc", "frozen_at": time.time()}}
        remediation._save_frozen_records(records)
        self.assertIn(str(fake_pid), remediation.get_frozen_processes())

        # Unfreezing dead PID should clean up record and return True
        res = remediation.unfreeze_process(fake_pid)
        self.assertTrue(res)
        self.assertNotIn(str(fake_pid), remediation.get_frozen_processes())

    def test_fallback_get_open_descriptors_and_locks(self):
        """_fallback_get_open_descriptors_and_locks parses lsof output correctly."""
        mock_lsof = (
            "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
            "python3 100 user 3u IPv4 0x1234 0t0 TCP *:8080 (LISTEN)\n"
            "python3 100 user 4u REG 1,1 1024 5678 /tmp/app.lock (txt lock)\n"
        )
        with patch("subprocess.run") as mock_run:
            mock_res = MagicMock()
            mock_res.returncode = 0
            mock_res.stdout = mock_lsof
            mock_run.return_value = mock_res

            info = remediation._fallback_get_open_descriptors_and_locks(100)
            self.assertTrue(info["has_locks"])
            self.assertEqual(len(info["sockets"]), 1)
            self.assertEqual(len(info["locks"]), 1)

    # --- Tier 3: Launchd Shield & Tree Termination ---

    def test_terminate_tree_safety_block(self):
        """Terminating protected processes must be refused."""
        self.assertFalse(remediation.terminate_process_tree(1))
        with patch("remediation.get_comm_for_pid", return_value="loginwindow"):
            self.assertFalse(remediation.terminate_process_tree(300))

    def test_terminate_process_tree_live(self):
        """Terminating a live child process gracefully via SIGTERM."""
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        pid = proc.pid
        try:
            self.assertTrue(remediation.is_process_alive(pid))
            terminated = remediation.terminate_process_tree(pid, force=False, timeout=1.0)
            self.assertTrue(terminated)
            self.assertFalse(remediation.is_process_alive(pid))
        finally:
            try:
                proc.kill()
                proc.wait()
            except Exception:
                pass

    def test_terminate_process_tree_force(self):
        """Terminating with force=True sends SIGKILL immediately."""
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        pid = proc.pid
        try:
            terminated = remediation.terminate_process_tree(pid, force=True)
            self.assertTrue(terminated)
            self.assertFalse(remediation.is_process_alive(pid))
        finally:
            try:
                proc.kill()
                proc.wait()
            except Exception:
                pass

    def test_launchd_shield_detection(self):
        """Tests launchd shield detection via launchctl list or ppid == 1."""
        # Test PPID == 1 detection
        with patch("remediation.get_process_ppid", return_value=1):
            is_launchd, label = remediation.is_managed_by_launchd(1234)
            self.assertTrue(is_launchd)
            self.assertIsNone(label)

        # Test launchctl list match
        mock_output = "1234\t0\tcom.apple.mockservice\n5678\t0\tcom.other.service\n"
        with patch("subprocess.run") as mock_run:
            mock_res = MagicMock()
            mock_res.returncode = 0
            mock_res.stdout = mock_output
            mock_run.return_value = mock_res

            is_launchd, label = remediation.is_managed_by_launchd(1234)
            self.assertTrue(is_launchd)
            self.assertEqual(label, "com.apple.mockservice")

    # --- Unified Memory: Ollama Model Eviction ---

    @patch("urllib.request.urlopen")
    def test_unload_ollama_model_success(self, mock_urlopen):
        """unload_ollama_model sends POST to /api/generate with keep_alive: 0."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        result = remediation.unload_ollama_model("llama3")
        self.assertTrue(result)

        # Inspect request
        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.full_url, "http://127.0.0.1:11434/api/generate")
        self.assertEqual(req.headers.get("Content-type"), "application/json")
        body = json.loads(req.data.decode("utf-8"))
        self.assertEqual(body, {"model": "llama3", "keep_alive": 0})

    @patch("urllib.request.urlopen", side_effect=Exception("Connection refused"))
    def test_unload_ollama_model_failure(self, mock_urlopen):
        """unload_ollama_model gracefully handles failure."""
        result = remediation.unload_ollama_model("nonexistent_model")
        self.assertFalse(result)

    # --- Triage Process Ranking ---

    @patch("subprocess.check_output")
    def test_get_triage_candidates_calculation(self, mock_ps):
        """
        Tests parsing ps output:
        composite = cpu_pct + (3.0 * ram_gb)
        ram_gb = rss_kb / (1024 * 1024)
        """
        mock_ps.return_value = (
            "  PID  PPID  %CPU      RSS COMM\n"
            "  101     1  50.0  1048576 /usr/local/bin/python3\n"
            "  102     1  10.0  2097152 /usr/bin/node\n"
            "    1     0   0.0    14560 /sbin/launchd\n"
        ).encode("utf-8")

        candidates = remediation.get_triage_candidates(sort_by="composite")
        self.assertEqual(len(candidates), 3)

        # Proc 101: cpu=50.0, ram=1.0 GB -> composite = 50.0 + 3.0*1.0 = 53.0
        p101 = next(p for p in candidates if p["pid"] == 101)
        self.assertEqual(p101["cpu_pct"], 50.0)
        self.assertAlmostEqual(p101["ram_gb"], 1.0, places=2)
        self.assertAlmostEqual(p101["composite"], 53.0, places=2)
        self.assertFalse(p101["is_protected"])

        # Proc 1: launchd -> is_protected must be True
        p1 = next(p for p in candidates if p["pid"] == 1)
        self.assertTrue(p1["is_protected"])

        # Verify sorting by composite
        # Proc 102: cpu=10.0, ram=2.0 GB -> composite = 10.0 + 6.0 = 16.0
        # Order should be p101 (53.0) then p102 (16.0) then p1
        self.assertEqual(candidates[0]["pid"], 101)
        self.assertEqual(candidates[1]["pid"], 102)

        # Test sorting by cpu
        cpu_sorted = remediation.get_triage_candidates(sort_by="cpu")
        self.assertEqual(cpu_sorted[0]["pid"], 101)

        # Test sorting by memory
        mem_sorted = remediation.get_triage_candidates(sort_by="memory")
        self.assertEqual(mem_sorted[0]["pid"], 102)


class TestTUIEngine(unittest.TestCase):
    """Tests for tui.py keystroke reading and UI formatting."""

    def test_ansi_escape_decoding(self):
        """ANSI sequences for arrow keys and special keys decode correctly."""
        # Test Up arrow (\x1b[A)
        r, w = os.pipe()
        os.write(w, b"\x1b[A")
        os.close(w)
        key = tui.decode_ansi_sequence(r)
        os.close(r)
        self.assertEqual(key, "Up")

        # Test Down arrow (\x1b[B)
        r, w = os.pipe()
        os.write(w, b"\x1b[B")
        os.close(w)
        key = tui.decode_ansi_sequence(r)
        os.close(r)
        self.assertEqual(key, "Down")

        # Test Right arrow (\x1b[C)
        r, w = os.pipe()
        os.write(w, b"\x1b[C")
        os.close(w)
        key = tui.decode_ansi_sequence(r)
        os.close(r)
        self.assertEqual(key, "Right")

        # Test Left arrow (\x1b[D)
        r, w = os.pipe()
        os.write(w, b"\x1b[D")
        os.close(w)
        key = tui.decode_ansi_sequence(r)
        os.close(r)
        self.assertEqual(key, "Left")

    def test_single_keystroke_pipe_fallback(self):
        """When stdin is not a tty (pipes/tests), get_single_keystroke reads cleanly."""
        with patch("sys.stdin.isatty", return_value=False):
            with patch("sys.stdin.read", side_effect=["q", "\n", " ", "\x03"]):
                self.assertEqual(tui.get_single_keystroke(), "q")
                self.assertEqual(tui.get_single_keystroke(), "Enter")
                self.assertEqual(tui.get_single_keystroke(), "Space")
                self.assertEqual(tui.get_single_keystroke(), "Ctrl+C")

    @patch("termios.tcsetattr")
    @patch("termios.tcgetattr")
    @patch("tty.setraw")
    @patch("os.read")
    @patch("sys.stdin.fileno", return_value=0)
    @patch("sys.stdin.isatty", return_value=True)
    def test_terminal_restoration_guaranteed(self, mock_isatty, mock_fileno, mock_read, mock_setraw, mock_tcgetattr, mock_tcsetattr):
        """termios.tcsetattr must ALWAYS be called in finally block even if read raises an exception."""
        fake_attrs = [1, 2, 3]
        mock_tcgetattr.return_value = fake_attrs
        mock_read.side_effect = RuntimeError("Read error")

        with self.assertRaises(RuntimeError):
            tui.get_single_keystroke()

        mock_tcsetattr.assert_called_once_with(0, termios.TCSADRAIN, fake_attrs)

    def test_format_process_row(self):
        """format_process_row formats process stats into table columns with correct flags."""
        proc = {
            "pid": 4567,
            "ppid": 1,
            "cpu_pct": 25.5,
            "rss_kb": 524288,
            "ram_gb": 0.5,
            "comm": "/usr/local/bin/my_worker",
            "base_comm": "my_worker",
            "composite": 27.0,
            "is_protected": False,
        }
        row = tui.format_process_row(proc, is_selected=False, is_frozen=False, width=80)
        self.assertIn("4567", row)
        self.assertIn("25.5%", row)
        self.assertIn("my_worker", row)

        # Selected row contains selector indicator
        sel_row = tui.format_process_row(proc, is_selected=True, is_frozen=False, width=80)
        self.assertIn("▶", sel_row)

        # Frozen status flag
        frozen_row = tui.format_process_row(proc, is_selected=False, is_frozen=True, width=80)
        self.assertIn("FROZEN", frozen_row)

        # Shield flag for protected process
        proc["is_protected"] = True
        shield_row = tui.format_process_row(proc, is_selected=False, is_frozen=False, width=80)
        self.assertIn("SHIELD", shield_row)

    def test_single_keystroke_raise_ctrl_c(self):
        """When raise_ctrl_c=True, \x03 raises KeyboardInterrupt."""
        with patch("sys.stdin.isatty", return_value=False):
            with patch("sys.stdin.read", return_value="\x03"):
                with self.assertRaises(KeyboardInterrupt):
                    tui.get_single_keystroke(raise_ctrl_c=True)

    def test_tui_actions_handle_protection(self):
        """TUI actions block operations on protected processes and format warning."""
        protected_target = {
            "pid": 1,
            "base_comm": "launchd",
            "is_protected": True,
        }
        res_tame = tui._handle_tame(protected_target)
        self.assertIn("SAFETY SHIELD BLOCKED", res_tame)

        res_freeze = tui._handle_freeze(protected_target)
        self.assertIn("SAFETY SHIELD BLOCKED", res_freeze)

        res_kill = tui._handle_kill(protected_target)
        self.assertIn("SAFETY SHIELD BLOCKED", res_kill)

    def test_render_triage_view(self):
        """render_triage_view renders header, candidate table, and hotkeys."""
        candidates = [{
            "pid": 8888,
            "ppid": 1,
            "cpu_pct": 12.0,
            "rss_kb": 1048576,
            "ram_gb": 1.0,
            "comm": "stress",
            "base_comm": "stress",
            "composite": 15.0,
            "is_protected": False,
        }]
        view = tui.render_triage_view(candidates, selected_index=0, sort_by="composite", status_message="Testing status")
        self.assertIn("mac-health v2.0", view)
        self.assertIn("8888", view)
        self.assertIn("Testing status", view)
        self.assertIn("Tame (E-Core)", view)
        self.assertIn("Kill Tree", view)


if __name__ == "__main__":
    unittest.main()
