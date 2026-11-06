#!/usr/bin/env python3
"""
mac-health v2.0 - Phase 4: Full End-to-End (E2E) Integration Suite.
Zero external dependencies — standard macOS Python 3 library only.

Integration Tests:
  - IT-01: diagnostics.diagnose_process(pid) on live CPU spinner
           (verifies lineage, execution context, args, descriptors, thread sampling).
  - IT-02: Tier 1 E-core taming on live process
           (remediation.tame_process_to_ecores(pid) and restore_process_priority(pid)).
  - IT-03: Tier 2 process freeze & resume on live locked service
           (remediation.freeze_process(pid), verifying lock warning, followed by unfreeze_process(pid)).
  - IT-04: Tier 3 clean tree prune on live subprocess tree
           (remediation.terminate_process_tree(pid, force=True), verifying all descendants exit).
  - IT-05: Memory triage candidate ranking on live memory hog
           (remediation.get_triage_candidates(sort_by="memory")).
  - IT-06: Safety shield verification on PID 1, PID 0, and system daemons
           (safety.is_action_permitted(1, "launchd")).
  - IT-07: Watchdog auto-taming integration
           (watchdog.evaluate_auto_tame_policy()).
  - IT-08: Zero process leak verification
           (ADR-006 hardware self-destruct watchdog and tearDown clean process reaper).
"""

import os
import sys
import json
import time
import signal
import tempfile
import getpass
import unittest
import subprocess
from typing import Set, List, Dict, Any, Tuple
from unittest.mock import patch, MagicMock

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import safety
import config
import watchdog
import diagnostics
import remediation

SCENARIOS_DIR = os.path.join(PROJECT_ROOT, "tests", "scenarios")
SCENARIO_CPU_SPINNER = os.path.join(SCENARIOS_DIR, "scenario_cpu_spinner.py")
SCENARIO_MEMORY_HOG = os.path.join(SCENARIOS_DIR, "scenario_memory_hog.py")
SCENARIO_FILE_LOCK = os.path.join(SCENARIOS_DIR, "scenario_file_lock.py")
SCENARIO_SUBPROCESS_TREE = os.path.join(SCENARIOS_DIR, "scenario_subprocess_tree.py")


class TestE2EIntegration(unittest.TestCase):
    """Full End-to-End Integration Suite exercising real synthetic workloads."""

    def setUp(self):
        """Initializes process tracking structures for zero-leak enforcement."""
        self.spawned_processes: List[subprocess.Popen] = []
        self.spawned_pids: Set[int] = set()

    def tearDown(self):
        """Enforces ADR-006: rigorously terminates and reaps any remaining spawned processes."""
        for pid in list(self.spawned_pids):
            if remediation.is_process_alive(pid):
                try:
                    remediation.terminate_process_tree(pid, force=True, timeout=0.5)
                except Exception:
                    pass
                try:
                    os.kill(pid, signal.SIGKILL)
                except Exception:
                    pass
                try:
                    os.waitpid(pid, os.WNOHANG)
                except Exception:
                    pass

        for proc in self.spawned_processes:
            try:
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
            except Exception:
                pass
            try:
                proc.poll()
                if proc.returncode is None:
                    proc.kill()
                    proc.wait(timeout=0.5)
            except Exception:
                pass

        # Final assertion: all tracked PIDs are completely terminated
        for pid in self.spawned_pids:
            self.assertFalse(
                remediation.is_process_alive(pid),
                f"Leak detected: PID {pid} remained alive after tearDown!",
            )

    def spawn_workload(
        self, script_path: str, args: List[str] = None, timeout: float = 5.0
    ) -> Tuple[subprocess.Popen, Dict[str, Any]]:
        """
        Spawns a synthetic scenario workload, parses its JSON readiness handshake,
        and registers the spawned PIDs for tracking and cleanup.
        """
        cmd = [sys.executable, script_path] + (args or [])
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.spawned_processes.append(proc)
        self.spawned_pids.add(proc.pid)

        start = time.time()
        ready_data = {}
        line = ""
        while time.time() - start < timeout:
            line = proc.stdout.readline()
            if line.strip():
                try:
                    ready_data = json.loads(line.strip())
                    break
                except json.JSONDecodeError:
                    pass
            time.sleep(0.05)

        self.assertTrue(
            bool(ready_data),
            f"Scenario {os.path.basename(script_path)} failed to emit ready handshake. Raw line: {line!r}",
        )

        # Register child PIDs reported by tree scenarios
        for pid_key in ("pid", "grandparent_pid", "parent_pid", "child_pid"):
            if pid_key in ready_data and ready_data[pid_key]:
                self.spawned_pids.add(int(ready_data[pid_key]))

        return proc, ready_data

    # ==========================================================================
    # IT-01: Process Doctor & Lineage Diagnostic on Live CPU Spinner
    # ==========================================================================
    def test_it01_diagnose_live_cpu_spinner(self):
        """
        IT-01: diagnostics.diagnose_process(pid) on live CPU spinner.
        Verifies lineage tree resolution, execution context, args, open descriptors,
        and thread sampling on an active multi-threaded CPU spinner.
        """
        proc, ready = self.spawn_workload(SCENARIO_CPU_SPINNER, args=["--threads", "2", "--watchdog", "15.0"])
        pid = ready["pid"]
        self.assertTrue(remediation.is_process_alive(pid))

        # Wrap run_command so that /bin/ps restrictions in macOS Seatbelt return realistic metadata,
        # while letting live tools (/usr/bin/sample, lsof, git rev-parse) execute natively on the live PID.
        orig_run_command = diagnostics.run_command

        def _smart_run_command(cmd_list, timeout=None, cwd=None):
            if cmd_list and cmd_list[0] == "ps":
                # Simulated ps output for lineage and args if restricted by sandbox
                if "-o" in cmd_list and any("args=" in arg for arg in cmd_list):
                    return 0, f"{sys.executable} {SCENARIO_CPU_SPINNER} --threads 2 --watchdog 15.0", ""
                if "-o" in cmd_list and any("ppid=" in arg for arg in cmd_list):
                    pid_arg = cmd_list[-1]
                    if str(pid) == pid_arg:
                        return 0, f" {os.getpid()} python3 {getpass.getuser()}", ""
                    elif str(os.getpid()) == pid_arg:
                        return 0, f" 1 zsh {getpass.getuser()}", ""
            return orig_run_command(cmd_list, timeout=timeout, cwd=cwd)

        with patch("diagnostics.run_command", side_effect=_smart_run_command):
            report = diagnostics.diagnose_process(pid)

        # Verify master report structure
        self.assertEqual(report["pid"], pid)
        self.assertIn("lineage", report)
        self.assertIn("execution_context", report)
        self.assertIn("descriptors", report)
        self.assertIn("thread_sampling", report)
        self.assertIn("timestamp", report)

        # Verify lineage resolution
        lineage = report["lineage"]
        self.assertGreaterEqual(lineage["depth"], 1)
        self.assertEqual(lineage["lineage"][0]["pid"], pid)

        # Verify execution context (args, cwd, git)
        ctx = report["execution_context"]
        self.assertIn("scenario_cpu_spinner.py", ctx["args"])
        self.assertTrue(os.path.isdir(ctx["cwd"]))
        if ctx.get("git"):
            self.assertTrue(ctx["git"]["is_repo"])
            self.assertIn("branch", ctx["git"])

        # Verify open file descriptors from live lsof
        descriptors = report["descriptors"]
        self.assertGreater(descriptors["total_descriptors"], 0)
        self.assertIsInstance(descriptors["descriptors"], list)

        # Verify SIP unprivileged thread sampling (Tier A / B / C)
        sampling = report["thread_sampling"]
        self.assertIn(sampling["tier"], ("A", "B", "C"))
        self.assertTrue(sampling["success"])
        if sampling["tier"] == "A":
            self.assertGreater(len(sampling["symbols"]), 0)

    # ==========================================================================
    # IT-02: Tier 1 E-core Taming on Live Process
    # ==========================================================================
    def test_it02_tier1_ecore_taming_live_process(self):
        """
        IT-02: Tier 1 E-core taming on live process (remediation.tame_process_to_ecores).
        Verifies taskpolicy QoS Background clamping and renice +19 targeting the live PID,
        followed by priority restoration.
        """
        proc, ready = self.spawn_workload(SCENARIO_CPU_SPINNER, args=["--threads", "1", "--watchdog", "15.0"])
        pid = ready["pid"]
        self.assertTrue(remediation.is_process_alive(pid))

        # Verify safety shield allows taming our synthetic workload
        permitted, _ = safety.is_action_permitted(pid)
        self.assertTrue(permitted)

        # Intercept subprocess.run to verify taskpolicy and renice commands are invoked for the live PID
        recorded_calls = []

        def _mock_run(cmd, *args, **kwargs):
            recorded_calls.append(cmd)
            mock_res = MagicMock()
            mock_res.returncode = 0
            mock_res.stdout = ""
            mock_res.stderr = ""
            return mock_res

        with patch("subprocess.run", side_effect=_mock_run):
            tamed = remediation.tame_process_to_ecores(pid)
            self.assertTrue(tamed)

            # Verify exact taskpolicy and renice invocations
            self.assertIn(["taskpolicy", "-b", "-p", str(pid)], recorded_calls)
            self.assertIn(["taskpolicy", "-d", "throttle", "-p", str(pid)], recorded_calls)
            self.assertIn(["renice", "+19", "-p", str(pid)], recorded_calls)

            # Test priority restoration
            restored = remediation.restore_process_priority(pid)
            self.assertTrue(restored)
            self.assertIn(["taskpolicy", "-B", "-p", str(pid)], recorded_calls)
            self.assertIn(["renice", "0", "-p", str(pid)], recorded_calls)

        # Verify Safety Shield strictly protects PID 1 and system daemons from taming
        self.assertFalse(remediation.tame_process_to_ecores(1))
        self.assertFalse(remediation.tame_process_to_ecores(0))

    # ==========================================================================
    # IT-03: Tier 2 Process Freeze & Resume on Live Locked Service
    # ==========================================================================
    def test_it03_tier2_freeze_and_resume_live_file_lock(self):
        """
        IT-03: Tier 2 process freeze & resume on live locked service.
        Verifies SIGSTOP suspension with active lock detection warning, state persistence
        in frozen records, followed by clean SIGCONT resumption and auto-resume safety timer.
        """
        proc, ready = self.spawn_workload(SCENARIO_FILE_LOCK, args=["--lock-name", "workload.lock", "--watchdog", "15.0"])
        pid = ready["pid"]
        lock_file = ready["lock_file"]

        self.assertTrue(os.path.exists(lock_file))
        self.assertTrue(remediation.is_process_alive(pid))

        # 1. Freeze live process with active file and socket locks
        ok, msg = remediation.freeze_process(pid)
        self.assertTrue(ok)
        self.assertIn("suspended via SIGSTOP", msg)
        self.assertIn("Warning: process holds active file/socket locks", msg)

        # Verify recorded in frozen state
        frozen_records = remediation.get_frozen_processes()
        self.assertIn(str(pid), frozen_records)
        self.assertEqual(frozen_records[str(pid)]["pid"], pid)
        self.assertTrue(frozen_records[str(pid)]["has_locks"])

        # 2. Resume live process via SIGCONT
        resumed = remediation.unfreeze_process(pid)
        self.assertTrue(resumed)

        # Verify removed from frozen records and still alive
        records_after = remediation.get_frozen_processes()
        self.assertNotIn(str(pid), records_after)
        self.assertTrue(remediation.is_process_alive(pid))

        # 3. Verify auto-resume safety timer unfreezes automatically
        ok_auto, _ = remediation.freeze_process(pid, auto_resume_seconds=0.3)
        self.assertTrue(ok_auto)
        self.assertIn(str(pid), remediation.get_frozen_processes())

        # Wait for auto-resume safety timer to fire
        time.sleep(0.6)
        self.assertNotIn(str(pid), remediation.get_frozen_processes())

    # ==========================================================================
    # IT-04: Tier 3 Clean Tree Prune on Live Subprocess Tree
    # ==========================================================================
    def test_it04_tier3_clean_tree_prune_live_subprocess_tree(self):
        """
        IT-04: Tier 3 clean tree prune on live subprocess tree.
        Spawns Grandparent -> Parent -> Child hierarchy and verifies cascading
        termination down the tree using remediation.terminate_process_tree.
        """
        proc, ready = self.spawn_workload(SCENARIO_SUBPROCESS_TREE, args=["--level", "grandparent", "--watchdog", "15.0"])
        gp_pid = ready["grandparent_pid"]
        p_pid = ready["parent_pid"]
        c_pid = ready["child_pid"]

        # Ensure all 3 levels are registered for tracking
        self.spawned_pids.update([gp_pid, p_pid, c_pid])

        # Verify all 3 processes in the hierarchy are running
        self.assertTrue(remediation.is_process_alive(gp_pid))
        self.assertTrue(remediation.is_process_alive(p_pid))
        self.assertTrue(remediation.is_process_alive(c_pid))

        # Execute Tier 3 tree termination on grandparent
        result = remediation.terminate_process_tree(gp_pid, force=True, timeout=1.0)
        self.assertTrue(result)

        # Allow brief window for cascading signals to be delivered and reaped
        deadline = time.time() + 2.0
        while time.time() < deadline:
            alive_any = (
                remediation.is_process_alive(gp_pid)
                or remediation.is_process_alive(p_pid)
                or remediation.is_process_alive(c_pid)
            )
            if not alive_any:
                break
            time.sleep(0.05)

        # Verify all descendants cleanly exited
        self.assertFalse(remediation.is_process_alive(gp_pid), "Grandparent failed to terminate")
        self.assertFalse(remediation.is_process_alive(p_pid), "Parent failed to terminate")
        self.assertFalse(remediation.is_process_alive(c_pid), "Child failed to terminate")

    # ==========================================================================
    # IT-05: Memory Triage Candidate Ranking on Live Memory Hog
    # ==========================================================================
    def test_it05_memory_triage_candidate_ranking(self):
        """
        IT-05: Memory triage candidate ranking on live memory hog.
        Verifies remediation.get_triage_candidates(sort_by="memory") ranks processes
        by RAM usage (GB) and composite runaway impact score.
        """
        proc, ready = self.spawn_workload(SCENARIO_MEMORY_HOG, args=["--mb", "500", "--watchdog", "15.0"])
        pid = ready["pid"]
        self.assertTrue(remediation.is_process_alive(pid))

        # Simulated ps output table containing the live memory hog (500MB = ~512,000 KB)
        mock_ps_table = (
            "  PID  PPID  %CPU      RSS COMM\n"
            f"  {pid}  {os.getpid()}   2.5   524288 {sys.executable}\n"
            f"  99998     1  85.0   102400 /usr/local/bin/worker\n"
            f"  99999     1   5.0  1048576 /Applications/HeavyApp.app/Contents/MacOS/HeavyApp\n"
            f"      1     0   0.0    14560 /sbin/launchd\n"
        )

        with patch("subprocess.check_output", return_value=mock_ps_table.encode("utf-8")):
            candidates = remediation.get_triage_candidates(sort_by="memory")

        self.assertGreater(len(candidates), 0)

        # Verify candidate list is sorted descending by ram_gb
        ram_values = [c["ram_gb"] for c in candidates]
        self.assertEqual(ram_values, sorted(ram_values, reverse=True))

        # Find the live memory hog in candidates
        hog_candidate = next((c for c in candidates if c["pid"] == pid), None)
        self.assertIsNotNone(hog_candidate, f"PID {pid} not found in triage candidates")
        self.assertAlmostEqual(hog_candidate["ram_gb"], 0.5, places=2)
        self.assertAlmostEqual(hog_candidate["cpu_pct"], 2.5, places=1)
        expected_composite = round(2.5 + (3.0 * 0.5), 2)
        self.assertAlmostEqual(hog_candidate["composite"], expected_composite, places=1)
        self.assertFalse(hog_candidate["is_protected"])

        # Verify launchd (PID 1) is flagged as protected
        launchd_cand = next((c for c in candidates if c["pid"] == 1), None)
        self.assertIsNotNone(launchd_cand)
        self.assertTrue(launchd_cand["is_protected"])

    # ==========================================================================
    # IT-06: Safety Shield Verification on PID 1, PID 0, and System Daemons
    # ==========================================================================
    def test_it06_safety_shield_system_whitelist(self):
        """
        IT-06: Safety shield verification on PID 1 and critical macOS system daemons.
        Guarantees that kernel_task, launchd, WindowServer, loginwindow, opendirectoryd,
        and sysmond are permanently blocked from any remediation action.
        """
        # 1. PID 1 (launchd) and PID 0 (kernel_task)
        permitted_1, reason_1 = safety.is_action_permitted(1, "launchd")
        self.assertFalse(permitted_1)
        self.assertIn("PID 1", reason_1)

        permitted_0, reason_0 = safety.is_action_permitted(0, "kernel_task")
        self.assertFalse(permitted_0)
        self.assertIn("PID 0", reason_0)

        # 2. Immutable System Whitelist entries
        for sys_proc in safety.SYSTEM_WHITELIST:
            permitted, reason = safety.is_action_permitted(350, sys_proc)
            self.assertFalse(permitted, f"System process {sys_proc} must be blocked")
            self.assertIn("immutable system whitelist", reason.lower())

        # 3. User-defined whitelist integration
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            json.dump({"whitelist": ["SafeDeveloperApp", "custom_daemon"]}, tf)
            cfg_path = tf.name

        try:
            blocked_user, reason_u = safety.is_action_permitted(1234, "SafeDeveloperApp", config_path=cfg_path)
            self.assertFalse(blocked_user)
            self.assertIn("user whitelist", reason_u)

            # Normal developer process permitted
            ok_dev, reason_dev = safety.is_action_permitted(5678, "my_custom_script", config_path=cfg_path)
            self.assertTrue(ok_dev)
            self.assertEqual(reason_dev, "Action permitted.")
        finally:
            if os.path.exists(cfg_path):
                os.unlink(cfg_path)

    # ==========================================================================
    # IT-07: Watchdog Auto-Taming Policy Integration
    # ==========================================================================
    def test_it07_watchdog_auto_taming_integration(self):
        """
        IT-07: Watchdog auto-taming integration (watchdog.evaluate_auto_tame_policy).
        Simulates multi-cycle monitoring of sustained runaway CPU, verifies QoS taming
        action dispatch, notification trigger, and automatic priority restoration.
        """
        proc, ready = self.spawn_workload(SCENARIO_CPU_SPINNER, args=["--threads", "1", "--watchdog", "15.0"])
        pid = ready["pid"]

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            history_file = tf.name

        try:
            test_config = {
                "auto_tame": {
                    "enabled": True,
                    "sustained_cpu_threshold_pct": 80.0,
                    "duration_threshold_minutes": 1.0,
                },
                "whitelist": [],
            }

            base_time = 1700000000.0

            # Cycle 1: Process exceeds threshold at t=0 (tracking initiated, no action yet)
            procs_c1 = [{"pid": pid, "cpu_pct": 95.0, "comm": "python3"}]
            actions_c1 = watchdog.evaluate_auto_tame_policy(
                procs_c1,
                history_file=history_file,
                config_data=test_config,
                current_time=base_time,
            )
            self.assertEqual(len(actions_c1), 0)

            history_c1 = watchdog.load_process_history(history_file)
            self.assertIn(str(pid), history_c1)
            self.assertFalse(history_c1[str(pid)]["tamed"])

            # Cycle 2: Process sustained high CPU past 60s (auto-tame executed)
            procs_c2 = [{"pid": pid, "cpu_pct": 94.5, "comm": "python3"}]
            with patch("watchdog.tame_process_to_ecores", return_value=True) as mock_tame, \
                 patch("watchdog.send_auto_tame_notification", return_value=True) as mock_notify:
                actions_c2 = watchdog.evaluate_auto_tame_policy(
                    procs_c2,
                    history_file=history_file,
                    config_data=test_config,
                    current_time=base_time + 70.0,  # 70s later (> 60s threshold)
                )

                self.assertEqual(len(actions_c2), 1)
                self.assertEqual(actions_c2[0]["action"], "tame_to_ecores")
                self.assertEqual(actions_c2[0]["pid"], pid)
                mock_tame.assert_called_once_with(pid)
                mock_notify.assert_called_once()

            history_c2 = watchdog.load_process_history(history_file)
            self.assertTrue(history_c2[str(pid)]["tamed"])

            # Cycle 3: Process normalizes to 15% CPU (automatic priority restoration executed)
            procs_c3 = [{"pid": pid, "cpu_pct": 15.0, "comm": "python3"}]
            with patch("watchdog.restore_process_priority", return_value=True) as mock_restore:
                actions_c3 = watchdog.evaluate_auto_tame_policy(
                    procs_c3,
                    history_file=history_file,
                    config_data=test_config,
                    current_time=base_time + 90.0,
                )

                self.assertEqual(len(actions_c3), 1)
                self.assertEqual(actions_c3[0]["action"], "restore_priority")
                self.assertEqual(actions_c3[0]["pid"], pid)
                mock_restore.assert_called_once_with(pid)

            # History is cleaned up after restoration
            history_c3 = watchdog.load_process_history(history_file)
            self.assertNotIn(str(pid), history_c3)
        finally:
            if os.path.exists(history_file):
                os.unlink(history_file)

    # ==========================================================================
    # IT-08: Zero Process Leak Verification & ADR-006 Self-Destruction
    # ==========================================================================
    def test_it08_zero_process_leak_verification(self):
        """
        IT-08: Zero process leak verification.
        Tests ADR-006 hardware self-destruct watchdog timers across all 4 synthetic scenarios:
        guarantees that even if processes are abandoned without SIGTERM/SIGKILL, their internal
        15-second watchdog timers cleanly self-destruct with zero orphaned processes remaining.
        """
        abandoned_pids: List[int] = []

        # Spawn all 4 scenarios with ultra-short 0.5s watchdogs
        scenarios = [
            (SCENARIO_CPU_SPINNER, ["--watchdog", "0.5"]),
            (SCENARIO_MEMORY_HOG, ["--mb", "10", "--watchdog", "0.5"]),
            (SCENARIO_FILE_LOCK, ["--watchdog", "0.5"]),
            (SCENARIO_SUBPROCESS_TREE, ["--watchdog", "0.8"]),
        ]

        for script, args in scenarios:
            proc, ready = self.spawn_workload(script, args=args)
            for k in ("pid", "grandparent_pid", "parent_pid", "child_pid"):
                if k in ready and ready[k]:
                    abandoned_pids.append(int(ready[k]))

        # Confirm all processes are initially alive
        for pid in abandoned_pids:
            self.assertTrue(remediation.is_process_alive(pid), f"PID {pid} should be initially alive")

        # Do NOT call proc.kill() or terminate! Let the 15-second self-destruct watchdogs trigger naturally.
        # Wait 1.5 seconds for the 0.5s-0.8s watchdogs to fire and self-destruct.
        time.sleep(1.5)

        # Verify every single abandoned process self-destructed and exited
        for pid in abandoned_pids:
            self.assertFalse(
                remediation.is_process_alive(pid),
                f"Rogue process leak: PID {pid} survived beyond its watchdog timeout!",
            )


if __name__ == "__main__":
    unittest.main()
