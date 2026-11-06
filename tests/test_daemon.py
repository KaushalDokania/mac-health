#!/usr/bin/env python3
"""
Unit tests for mac-health v2.0 Phase 3:
- Centralized Configuration Management (config.py)
- Safety Whitelist Pattern Matching (safety.py)
- Priority Restoration & Remediation Notifications (remediation.py)
- Watchdog Autonomous Policy Engine (watchdog.py)
"""

import os
import sys
import json
import tempfile
import unittest
import subprocess
from unittest.mock import patch, MagicMock

# Ensure parent directory is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import config
import safety
import remediation
import watchdog


class TestConfigManagement(unittest.TestCase):
    """Tests for config.py configuration schema, defaults, I/O, and environment overrides."""

    def test_default_config_schema(self):
        """Default config must conform to the v2.0.0 schema specification."""
        cfg = config.get_default_config()
        self.assertEqual(cfg.get("version"), "2.0.0")

        # auto_tame section
        auto_tame = cfg.get("auto_tame")
        self.assertIsInstance(auto_tame, dict)
        self.assertFalse(auto_tame.get("enabled"))
        self.assertEqual(auto_tame.get("sustained_cpu_threshold_pct"), 90.0)
        self.assertEqual(auto_tame.get("duration_threshold_minutes"), 15)
        self.assertEqual(auto_tame.get("action"), "tame_to_ecores")

        # notifications section
        notif = cfg.get("notifications")
        self.assertIsInstance(notif, dict)
        self.assertTrue(notif.get("enabled"))
        self.assertTrue(notif.get("sound"))
        self.assertEqual(notif.get("cooldown_minutes"), 30)

        # whitelist section
        wl = cfg.get("whitelist")
        self.assertIsInstance(wl, dict)
        exact = wl.get("exact_matches")
        self.assertIsInstance(exact, list)
        for item in ["loginwindow", "WindowServer", "kernel_task", "launchd"]:
            self.assertIn(item, exact)

        subs = wl.get("substring_patterns")
        self.assertIsInstance(subs, list)
        for item in ["antigravity", "cursor", "docker", "ollama", "cargo build"]:
            self.assertIn(item, subs)

    def test_config_path_default_and_env_override(self):
        """get_config_path() must check MAC_HEALTH_CONFIG and fallback to ~/.config/mac-health/config.json."""
        with patch.dict(os.environ, {}, clear=True):
            default_path = config.get_config_path()
            self.assertEqual(default_path, os.path.expanduser("~/.config/mac-health/config.json"))

        test_override = "/tmp/test_custom_config.json"
        with patch.dict(os.environ, {"MAC_HEALTH_CONFIG": test_override}):
            custom_path = config.get_config_path()
            self.assertEqual(custom_path, os.path.abspath(test_override))

    def test_config_save_and_load(self):
        """save_config() and load_config() must persist and retrieve settings properly."""
        with tempfile.TemporaryDirectory() as td:
            cfg_path = os.path.join(td, "nested", "sub", "config.json")
            custom_cfg = config.get_default_config()
            custom_cfg["auto_tame"]["enabled"] = True
            custom_cfg["auto_tame"]["sustained_cpu_threshold_pct"] = 85.0
            custom_cfg["whitelist"]["exact_matches"].append("MyCustomApp")

            ok = config.save_config(custom_cfg, config_path=cfg_path)
            self.assertTrue(ok)
            self.assertTrue(os.path.isfile(cfg_path))

            loaded = config.load_config(config_path=cfg_path)
            self.assertTrue(loaded["auto_tame"]["enabled"])
            self.assertEqual(loaded["auto_tame"]["sustained_cpu_threshold_pct"], 85.0)
            self.assertIn("MyCustomApp", loaded["whitelist"]["exact_matches"])

    def test_config_corrupted_json_fallback(self):
        """load_config() must safely fallback to defaults on corrupted JSON without crashing."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            tf.write("{ this is definitely not valid json syntax ]")
            corrupt_path = tf.name

        try:
            loaded = config.load_config(config_path=corrupt_path)
            self.assertIsInstance(loaded, dict)
            self.assertEqual(loaded.get("version"), "2.0.0")
            self.assertFalse(loaded["auto_tame"]["enabled"])
        finally:
            if os.path.isfile(corrupt_path):
                os.unlink(corrupt_path)

    def test_config_missing_file_fallback(self):
        """load_config() on non-existent file returns default config safely."""
        loaded = config.load_config(config_path="/tmp/non_existent_path_4829103/config.json")
        self.assertIsInstance(loaded, dict)
        self.assertEqual(loaded.get("version"), "2.0.0")

    def test_format_config_view(self):
        """format_config_view() returns a well-formatted string summary."""
        cfg = config.get_default_config()
        cfg["auto_tame"]["enabled"] = True
        view = config.format_config_view(cfg)
        self.assertIsInstance(view, str)
        self.assertIn("mac-health Configuration", view)
        self.assertIn("Autonomous Watchdog (Auto-Tame): Enabled", view)
        self.assertIn("CPU Threshold", view)
        self.assertIn("loginwindow", view)


class TestSafetyWhitelist(unittest.TestCase):
    """Tests for safety.py is_whitelisted() exact and substring pattern matching."""

    def test_is_whitelisted_system_pids(self):
        """PID 0 (kernel) and PID 1 (launchd) must always be whitelisted."""
        self.assertTrue(safety.is_whitelisted("any_name", pid=0))
        self.assertTrue(safety.is_whitelisted("any_name", pid=1))

        # Default pid=-1 should NOT automatically be whitelisted
        self.assertFalse(safety.is_whitelisted("my_unwhitelisted_proc", pid=-1))

    def test_is_whitelisted_immutable_system_whitelist(self):
        """All processes in SYSTEM_WHITELIST must return True even if no cfg provided."""
        for name in safety.SYSTEM_WHITELIST:
            self.assertTrue(safety.is_whitelisted(name, pid=100))
            self.assertTrue(safety.is_whitelisted(f"/System/Library/CoreServices/{name}", pid=101))

    def test_is_whitelisted_exact_matches(self):
        """Processes matching cfg exact_matches must return True."""
        cfg = {
            "whitelist": {
                "exact_matches": ["loginwindow", "WindowServer", "CustomDaemon"],
                "substring_patterns": [],
            }
        }
        self.assertTrue(safety.is_whitelisted("CustomDaemon", pid=200, cfg=cfg))
        self.assertTrue(safety.is_whitelisted("/usr/local/bin/CustomDaemon", pid=201, cfg=cfg))
        self.assertFalse(safety.is_whitelisted("OtherApp", pid=202, cfg=cfg))

    def test_is_whitelisted_substring_patterns(self):
        """Processes containing any substring_patterns must return True case-insensitively."""
        cfg = {
            "whitelist": {
                "exact_matches": [],
                "substring_patterns": ["antigravity", "cursor", "docker", "ollama", "cargo build"],
            }
        }
        self.assertTrue(safety.is_whitelisted("cargo build --release", pid=300, cfg=cfg))
        self.assertTrue(safety.is_whitelisted("/Applications/Cursor.app/Contents/MacOS/Cursor", pid=301, cfg=cfg))
        self.assertTrue(safety.is_whitelisted("com.docker.backend", pid=302, cfg=cfg))
        self.assertTrue(safety.is_whitelisted("OLLAMA_SERVICE", pid=303, cfg=cfg))
        self.assertTrue(safety.is_whitelisted("antigravity-daemon", pid=304, cfg=cfg))

        # Non-matching
        self.assertFalse(safety.is_whitelisted("heavy_ffmpeg_encode", pid=305, cfg=cfg))
        self.assertFalse(safety.is_whitelisted("python_runaway", pid=306, cfg=cfg))

    def test_is_whitelisted_legacy_list_support(self):
        """Legacy configuration with whitelist as a list must be supported."""
        cfg = {"whitelist": ["legacy_worker", "slack"]}
        self.assertTrue(safety.is_whitelisted("legacy_worker", pid=400, cfg=cfg))
        self.assertFalse(safety.is_whitelisted("unknown", pid=401, cfg=cfg))


class TestRemediationRestoreAndNotification(unittest.TestCase):
    """Tests for remediation.py restore_process_priority() and send_auto_tame_notification()."""

    @patch("subprocess.run")
    def test_restore_process_priority_success(self, mock_run):
        """restore_process_priority must run taskpolicy -B -p <PID> and renice 0 -p <PID>."""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        result = remediation.restore_process_priority(1234)
        self.assertTrue(result)

        called_cmds = [call_args[0][0] for call_args in mock_run.call_args_list]
        self.assertIn(["taskpolicy", "-B", "-p", "1234"], called_cmds)
        self.assertIn(["renice", "0", "-p", "1234"], called_cmds)

    def test_restore_process_priority_invalid_pid(self):
        """restore_process_priority returns False for invalid PIDs (<= 0)."""
        self.assertFalse(remediation.restore_process_priority(0))
        self.assertFalse(remediation.restore_process_priority(-5))

    @patch("subprocess.run", side_effect=subprocess.SubprocessError("Command failed"))
    def test_restore_process_priority_handles_subprocess_error(self, mock_run):
        """restore_process_priority returns False cleanly on subprocess error."""
        result = remediation.restore_process_priority(9999)
        self.assertFalse(result)

    @patch("subprocess.run")
    def test_send_auto_tame_notification(self, mock_run):
        """send_auto_tame_notification dispatches macOS notification via osascript."""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        result = remediation.send_auto_tame_notification("node_worker", 5555, duration_min=15, cpu_pct=94.5)
        self.assertTrue(result)

        called_cmd = mock_run.call_args[0][0]
        self.assertEqual(called_cmd[0], "osascript")
        self.assertEqual(called_cmd[1], "-e")
        script_text = called_cmd[2]
        self.assertIn("display notification", script_text)
        self.assertIn("node_worker", script_text)
        self.assertIn("5555", script_text)
        self.assertIn("94%", script_text)
        self.assertIn("15m", script_text)

    @patch("subprocess.run", side_effect=Exception("osascript error"))
    def test_send_auto_tame_notification_error_handling(self, mock_run):
        """send_auto_tame_notification returns False cleanly on failure."""
        result = remediation.send_auto_tame_notification("bad_proc", 1111)
        self.assertFalse(result)


class TestWatchdogPolicyEngine(unittest.TestCase):
    """Tests for watchdog.py autonomous watchdog policy evaluation and candidate tracking."""

    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.history_file = os.path.join(self.test_dir.name, "process_history.json")

    def tearDown(self):
        self.test_dir.cleanup()

    def test_watchdog_tracks_candidates_across_ticks(self):
        """Runaway candidates exceeding sustained_cpu_threshold_pct are tracked across ticks in history."""
        cfg = {
            "auto_tame": {
                "enabled": True,
                "sustained_cpu_threshold_pct": 90.0,
                "duration_threshold_minutes": 15,  # 900 seconds
                "action": "tame_to_ecores",
            },
            "notifications": {"enabled": False},
            "whitelist": {"exact_matches": [], "substring_patterns": []},
        }

        # Tick 1: Candidate starts exceeding threshold (CPU=95%, elapsed=0s)
        procs_t1 = [{"pid": 1001, "cpu_pct": 95.0, "comm": "runaway_compiler"}]
        actions_t1 = watchdog.evaluate_auto_tame_policy(
            procs_t1, history_file=self.history_file, config_data=cfg, current_time=1000.0
        )
        self.assertEqual(actions_t1, [])

        history_t1 = watchdog.load_process_history(self.history_file)
        self.assertIn("1001", history_t1)
        self.assertEqual(history_t1["1001"]["first_seen"], 1000.0)
        self.assertEqual(history_t1["1001"]["last_seen"], 1000.0)
        self.assertFalse(history_t1["1001"]["tamed"])

        # Tick 2: 500s later (still under 900s threshold)
        actions_t2 = watchdog.evaluate_auto_tame_policy(
            procs_t1, history_file=self.history_file, config_data=cfg, current_time=1500.0
        )
        self.assertEqual(actions_t2, [])

        history_t2 = watchdog.load_process_history(self.history_file)
        self.assertEqual(history_t2["1001"]["first_seen"], 1000.0)
        self.assertEqual(history_t2["1001"]["last_seen"], 1500.0)
        self.assertFalse(history_t2["1001"]["tamed"])

    @patch("watchdog.send_auto_tame_notification")
    @patch("watchdog.tame_process_to_ecores", return_value=True)
    def test_watchdog_auto_tames_when_duration_met(self, mock_tame, mock_notify):
        """When sustained CPU exceeds duration_threshold_minutes, auto-tame is executed."""
        cfg = {
            "auto_tame": {
                "enabled": True,
                "sustained_cpu_threshold_pct": 90.0,
                "duration_threshold_minutes": 15,  # 900 seconds
                "action": "tame_to_ecores",
            },
            "notifications": {"enabled": True},
            "whitelist": {"exact_matches": [], "substring_patterns": []},
        }

        procs = [{"pid": 2002, "cpu_pct": 96.0, "comm": "heavy_stress"}]

        # Tick 1: First seen at t=1000.0
        watchdog.evaluate_auto_tame_policy(procs, history_file=self.history_file, config_data=cfg, current_time=1000.0)

        # Tick 2: 950 seconds later (t=1950.0 >= 900s)
        actions = watchdog.evaluate_auto_tame_policy(
            procs, history_file=self.history_file, config_data=cfg, current_time=1950.0
        )

        self.assertEqual(len(actions), 1)
        action = actions[0]
        self.assertEqual(action["action"], "tame_to_ecores")
        self.assertEqual(action["pid"], 2002)
        self.assertEqual(action["status"], "success")

        mock_tame.assert_called_once_with(2002)
        mock_notify.assert_called_once()

        # Verify history marked as tamed
        history = watchdog.load_process_history(self.history_file)
        self.assertTrue(history["2002"]["tamed"])
        self.assertEqual(history["2002"]["tamed_at"], 1950.0)

    @patch("watchdog.tame_process_to_ecores")
    def test_watchdog_does_not_retame_on_subsequent_ticks(self, mock_tame):
        """Already-tamed processes are not re-tamed on subsequent ticks."""
        cfg = {
            "auto_tame": {
                "enabled": True,
                "sustained_cpu_threshold_pct": 90.0,
                "duration_threshold_minutes": 15,
                "action": "tame_to_ecores",
            },
            "notifications": {"enabled": False},
            "whitelist": {"exact_matches": [], "substring_patterns": []},
        }

        # Seed history with an already-tamed process
        history = {
            "3003": {
                "pid": 3003,
                "comm": "already_tamed_proc",
                "first_seen": 1000.0,
                "last_seen": 2000.0,
                "last_cpu": 95.0,
                "tamed": True,
                "tamed_at": 1950.0,
            }
        }
        watchdog.save_process_history(history, self.history_file)

        procs = [{"pid": 3003, "cpu_pct": 95.0, "comm": "already_tamed_proc"}]
        actions = watchdog.evaluate_auto_tame_policy(
            procs, history_file=self.history_file, config_data=cfg, current_time=2100.0
        )

        self.assertEqual(actions, [])
        mock_tame.assert_not_called()

    @patch("watchdog.tame_process_to_ecores")
    def test_watchdog_ignores_whitelisted_processes(self, mock_tame):
        """Processes matching safety whitelists must never be tamed even if duration is exceeded."""
        cfg = {
            "auto_tame": {
                "enabled": True,
                "sustained_cpu_threshold_pct": 90.0,
                "duration_threshold_minutes": 15,
                "action": "tame_to_ecores",
            },
            "notifications": {"enabled": False},
            "whitelist": {
                "exact_matches": ["WindowServer"],
                "substring_patterns": ["cursor", "docker"],
            },
        }

        # Candidate 1: WindowServer (system whitelist)
        # Candidate 2: cursor (substring whitelist)
        procs = [
            {"pid": 4001, "cpu_pct": 99.0, "comm": "WindowServer"},
            {"pid": 4002, "cpu_pct": 98.0, "comm": "/Applications/Cursor.app/Contents/MacOS/Cursor"},
        ]

        # Tick 1: First seen at t=1000
        watchdog.evaluate_auto_tame_policy(procs, history_file=self.history_file, config_data=cfg, current_time=1000.0)

        # Tick 2: 1000 seconds later
        actions = watchdog.evaluate_auto_tame_policy(
            procs, history_file=self.history_file, config_data=cfg, current_time=2000.0
        )

        self.assertEqual(actions, [])
        mock_tame.assert_not_called()

    @patch("watchdog.tame_process_to_ecores")
    def test_watchdog_disabled_policy(self, mock_tame):
        """When auto_tame.enabled is False, runaway processes are tracked but never tamed."""
        cfg = {
            "auto_tame": {
                "enabled": False,
                "sustained_cpu_threshold_pct": 90.0,
                "duration_threshold_minutes": 15,
                "action": "tame_to_ecores",
            },
            "notifications": {"enabled": False},
            "whitelist": {"exact_matches": [], "substring_patterns": []},
        }

        procs = [{"pid": 5001, "cpu_pct": 99.0, "comm": "crypto_miner"}]

        # Tick 1
        watchdog.evaluate_auto_tame_policy(procs, history_file=self.history_file, config_data=cfg, current_time=1000.0)

        # Tick 2: Exceeded duration threshold
        actions = watchdog.evaluate_auto_tame_policy(
            procs, history_file=self.history_file, config_data=cfg, current_time=2500.0
        )

        self.assertEqual(actions, [])
        mock_tame.assert_not_called()

        history = watchdog.load_process_history(self.history_file)
        self.assertIn("5001", history)
        self.assertFalse(history["5001"]["tamed"])

    @patch("watchdog.is_process_alive", return_value=True)
    @patch("watchdog.restore_process_priority", return_value=True)
    def test_watchdog_priority_auto_restore_when_cpu_drops(self, mock_restore, mock_alive):
        """When a tamed process's CPU drops below threshold, its priority is automatically restored."""
        cfg = {
            "auto_tame": {
                "enabled": True,
                "sustained_cpu_threshold_pct": 90.0,
                "duration_threshold_minutes": 15,
                "action": "tame_to_ecores",
            },
            "notifications": {"enabled": False},
            "whitelist": {"exact_matches": [], "substring_patterns": []},
        }

        # Seed history with a previously tamed process
        history = {
            "6001": {
                "pid": 6001,
                "comm": "heavy_task",
                "first_seen": 1000.0,
                "last_seen": 2000.0,
                "last_cpu": 95.0,
                "tamed": True,
                "tamed_at": 1950.0,
            }
        }
        watchdog.save_process_history(history, self.history_file)

        # Process CPU has now dropped to 15% (below threshold)
        procs_dropped = [{"pid": 6001, "cpu_pct": 15.0, "comm": "heavy_task"}]
        actions = watchdog.evaluate_auto_tame_policy(
            procs_dropped, history_file=self.history_file, config_data=cfg, current_time=2200.0
        )

        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["action"], "restore_priority")
        self.assertEqual(actions[0]["pid"], 6001)
        self.assertEqual(actions[0]["status"], "success")

        mock_restore.assert_called_once_with(6001)

        # Verify entry was cleaned up from history
        history_after = watchdog.load_process_history(self.history_file)
        self.assertNotIn("6001", history_after)

    @patch("watchdog.is_process_alive", return_value=False)
    @patch("watchdog.restore_process_priority")
    def test_watchdog_cleans_up_dead_process_without_restore(self, mock_restore, mock_alive):
        """Terminated processes are cleaned from history without calling restore_process_priority."""
        cfg = {
            "auto_tame": {
                "enabled": True,
                "sustained_cpu_threshold_pct": 90.0,
                "duration_threshold_minutes": 15,
                "action": "tame_to_ecores",
            },
            "notifications": {"enabled": False},
            "whitelist": {"exact_matches": [], "substring_patterns": []},
        }

        history = {
            "7001": {
                "pid": 7001,
                "comm": "dead_task",
                "first_seen": 1000.0,
                "last_seen": 2000.0,
                "last_cpu": 95.0,
                "tamed": True,
                "tamed_at": 1950.0,
            }
        }
        watchdog.save_process_history(history, self.history_file)

        # No running procs
        actions = watchdog.evaluate_auto_tame_policy(
            [], history_file=self.history_file, config_data=cfg, current_time=2500.0
        )

        self.assertEqual(actions, [])
        mock_restore.assert_not_called()

        history_after = watchdog.load_process_history(self.history_file)
        self.assertNotIn("7001", history_after)

    def test_watchdog_normalizes_tuple_and_dict_formats(self):
        """evaluate_auto_tame_policy supports processes given as dicts or tuples."""
        cfg = {
            "auto_tame": {"enabled": False, "sustained_cpu_threshold_pct": 80.0},
            "notifications": {"enabled": False},
            "whitelist": {"exact_matches": [], "substring_patterns": []},
        }

        # Tuple format: (pid, cpu, comm)
        # Dict format: {"pid": ..., "cpu_pct": ..., "comm": ...}
        input_procs = [
            (8001, 85.0, "tuple_proc"),
            {"pid": 8002, "cpu_pct": 90.0, "comm": "dict_proc"},
        ]

        watchdog.evaluate_auto_tame_policy(
            input_procs, history_file=self.history_file, config_data=cfg, current_time=1000.0
        )

        history = watchdog.load_process_history(self.history_file)
        self.assertIn("8001", history)
        self.assertIn("8002", history)
        self.assertEqual(history["8001"]["comm"], "tuple_proc")
        self.assertEqual(history["8002"]["comm"], "dict_proc")

    def test_reset_config_to_defaults(self):
        """reset_config_to_defaults restores defaults and writes them to disk."""
        target_file = os.path.join(self.test_dir.name, "reset_config.json")
        custom_cfg = {"version": "0.1", "custom_key": True}
        config.save_config(custom_cfg, target_file)

        res = config.reset_config_to_defaults(target_file)
        self.assertTrue(res)
        loaded = config.load_config(target_file)
        self.assertEqual(loaded["version"], "2.0.0")
        self.assertIn("auto_tame", loaded)
        self.assertNotIn("custom_key", loaded)


if __name__ == "__main__":
    unittest.main()
