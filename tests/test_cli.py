#!/usr/bin/env python3
"""
Unit tests for mac-health v2.0 CLI Router and Subcommands.
Zero external dependencies — standard macOS Python 3 library only.
"""

import os
import sys
import io
import unittest
from unittest.mock import patch, MagicMock

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import monitor


class TestCliRouter(unittest.TestCase):
    """Tests CLI argument parsing, routing, and command handlers in monitor.py."""

    def test_version_output(self):
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            with patch("sys.argv", ["monitor.py", "--version"]):
                with self.assertRaises(SystemExit) as cm:
                    monitor.main()
                self.assertEqual(cm.exception.code, 0)
                out = fake_out.getvalue()
                self.assertIn("mac-health v2.0.0", out)

    def test_help_output(self):
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            with patch("sys.argv", ["monitor.py", "--help"]):
                with self.assertRaises(SystemExit) as cm:
                    monitor.main()
                self.assertEqual(cm.exception.code, 0)
                out = fake_out.getvalue()
                self.assertIn("v2.0.0", out)
                self.assertIn("mh doctor", out)
                self.assertIn("mh fix", out)
                self.assertIn("mh restore", out)
                self.assertIn("mh unfreeze", out)
                self.assertIn("mh config", out)

    def test_doctor_help(self):
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            monitor.handle_doctor(["--help"])
            out = fake_out.getvalue()
            self.assertIn("mac-health doctor", out)
            self.assertIn("mh doctor <PID>", out)
            self.assertIn("mh doctor windowserver", out)

    @patch("diagnostics.diagnose_windowserver")
    def test_doctor_windowserver(self, mock_ws):
        mock_ws.return_value = {
            "daemon": "WindowServer",
            "pid": 500,
            "cpu_percent": 15.0,
            "mem_percent": 3.0,
            "status": "HEALTHY",
            "top_gui_consumers": [],
            "skylight_logs": {"summary": "Clean", "entries": []},
        }
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            monitor.handle_doctor(["windowserver"])
            out = fake_out.getvalue()
            self.assertIn("WindowServer", out)
            self.assertIn("HEALTHY", out)

    @patch("diagnostics.diagnose_mds_stores")
    def test_doctor_mds(self, mock_mds):
        mock_mds.return_value = {
            "daemon": "mds_stores",
            "pid": 600,
            "cpu_percent": 2.0,
            "mem_percent": 1.0,
            "status": "NORMAL",
            "thrashing_detected": False,
            "detected_developer_dirs": [],
            "path_count": 10,
        }
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            monitor.handle_doctor(["mds"])
            out = fake_out.getvalue()
            self.assertIn("mds_stores", out)
            self.assertIn("Spotlight", out)

    @patch("remediation.is_process_alive", return_value=True)
    @patch("diagnostics.diagnose_process")
    def test_doctor_target_pid(self, mock_diag, mock_alive):
        mock_diag.return_value = {
            "pid": 9999,
            "lineage": {"comm": "test_app", "chain": []},
            "execution_context": {"cwd": "/tmp", "args": "test"},
            "descriptors": {"total_open_descriptors": 5, "tcp_sockets": [], "active_locks": []},
            "thread_sampling": {"tier_used": "tier_a", "status": "OK", "sample": {}},
        }
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            monitor.handle_doctor(["9999"])
            out = fake_out.getvalue()
            self.assertIn("PID 9999", out)
            self.assertIn("test_app", out)

    @patch("remediation.get_triage_candidates")
    def test_doctor_auto_candidates_below_threshold(self, mock_candidates):
        mock_candidates.return_value = [
            {"pid": 1234, "comm": "zsh", "base_comm": "zsh", "cpu_pct": 5.0, "ram_gb": 0.05, "mem_rss_mb": 51.2},
            {"pid": 2345, "comm": "python", "base_comm": "python", "cpu_pct": 2.1, "ram_gb": 0.12},
        ]
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            monitor.handle_doctor([])
            out = fake_out.getvalue()
            self.assertIn("Active Candidate Processes", out)
            self.assertIn("PID   1234", out)
            self.assertIn("zsh", out)
            self.assertIn("51.2 MB RSS", out)

    @patch("remediation.get_triage_candidates")
    @patch("diagnostics.diagnose_windowserver")
    def test_doctor_auto_detects_windowserver(self, mock_ws, mock_candidates):
        mock_candidates.return_value = [
            {"pid": 420, "comm": "/usr/bin/WindowServer", "base_comm": "WindowServer", "cpu_pct": 45.0, "ram_gb": 0.5, "is_protected": True},
            {"pid": 9999, "comm": "python", "base_comm": "python", "cpu_pct": 20.0, "ram_gb": 0.2, "is_protected": False},
        ]
        mock_ws.return_value = {
            "daemon": "WindowServer",
            "pid": 420,
            "cpu_percent": 45.0,
            "mem_percent": 2.0,
            "status": "HEALTHY",
            "top_gui_consumers": [],
            "skylight_logs": {"summary": "Clean", "entries": []},
        }
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            monitor.handle_doctor([])
            out = fake_out.getvalue()
            self.assertIn("Auto-diagnosing #1 CPU consumer: WindowServer", out)
            self.assertIn("High User-Space Process Detected: PID 9999", out)
            mock_ws.assert_called_once()

    def test_fix_help(self):
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            monitor.handle_fix(["--help"])
            out = fake_out.getvalue()
            self.assertIn("mac-health fix", out)
            self.assertIn("mh fix <PID> [--tame]", out)
            self.assertIn("mh fix <PID> --freeze", out)

    @patch("remediation.is_process_alive", return_value=True)
    @patch("remediation.get_comm_for_pid", return_value="hog_proc")
    @patch("remediation.tame_process_to_ecores", return_value=True)
    def test_fix_pid_tame(self, mock_tame, mock_comm, mock_alive):
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            monitor.handle_fix(["12345", "--tame"])
            out = fake_out.getvalue()
            self.assertIn("PID 12345 (hog_proc) tamed to Apple Silicon Efficiency cores", out)
            mock_tame.assert_called_once_with(12345)

    @patch("remediation.is_process_alive", return_value=True)
    @patch("remediation.get_comm_for_pid", return_value="freeze_proc")
    @patch("remediation.freeze_process", return_value=(True, "Pre-freeze clean"))
    def test_fix_pid_freeze(self, mock_freeze, mock_comm, mock_alive):
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            monitor.handle_fix(["12345", "--freeze"])
            out = fake_out.getvalue()
            self.assertIn("PID 12345 (freeze_proc) frozen with SIGSTOP", out)
            mock_freeze.assert_called_once_with(12345)

    @patch("remediation.is_process_alive", return_value=True)
    @patch("remediation.get_comm_for_pid", return_value="kill_proc")
    @patch("remediation.is_managed_by_launchd", return_value=(False, None))
    @patch("remediation.terminate_process_tree", return_value=True)
    def test_fix_pid_kill(self, mock_kill, mock_launchd, mock_comm, mock_alive):
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            monitor.handle_fix(["12345", "--kill"])
            out = fake_out.getvalue()
            self.assertIn("Process tree for PID 12345 (kill_proc) terminated successfully", out)
            mock_kill.assert_called_once_with(12345, force=False)

    @patch("remediation.restore_process_priority", return_value=True)
    @patch("remediation.get_comm_for_pid", return_value="tamed_proc")
    def test_restore_pid(self, mock_comm, mock_restore):
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            monitor.handle_restore(["12345"])
            out = fake_out.getvalue()
            self.assertIn("PID 12345 (tamed_proc) priority restored to normal", out)
            mock_restore.assert_called_once_with(12345)

    @patch("remediation.unfreeze_process", return_value=True)
    @patch("remediation.get_comm_for_pid", return_value="frozen_proc")
    def test_unfreeze_pid(self, mock_comm, mock_unfreeze):
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            monitor.handle_unfreeze(["12345"])
            out = fake_out.getvalue()
            self.assertIn("PID 12345 (frozen_proc) resumed", out)
            mock_unfreeze.assert_called_once_with(12345)

    def test_config_view(self):
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            monitor.handle_config(["--view"])
            out = fake_out.getvalue()
            self.assertIn("mac-health Configuration", out)
            self.assertIn("Autonomous Watchdog", out)
            self.assertIn("Protected Process Whitelist", out)

    @patch("config.reset_config_to_defaults", return_value=True)
    def test_config_reset(self, mock_reset):
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            monitor.handle_config(["--reset"])
            out = fake_out.getvalue()
            self.assertIn("Configuration reset to recommended defaults", out)
            mock_reset.assert_called_once()

    def test_config_path(self):
        with patch("sys.stdout", new=io.StringIO()) as fake_out:
            monitor.handle_config(["--path"])
            out = fake_out.getvalue().strip()
            self.assertTrue(out.endswith("config.json"))

    def test_safety_shield_blocks_pid_1(self):
        """Verify safety shield intercepts fix requests on PID 1 (launchd)."""
        with patch("remediation.is_process_alive", return_value=True):
            with patch("remediation.get_comm_for_pid", return_value="launchd"):
                with patch("sys.stdout", new=io.StringIO()) as fake_out:
                    monitor.handle_fix(["1", "--tame"])
                    out = fake_out.getvalue()
                    self.assertIn("Safety Shield: Operation blocked on PID 1", out)


if __name__ == "__main__":
    unittest.main()
