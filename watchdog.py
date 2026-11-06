#!/usr/bin/env python3
"""
mac-health v2.0 - Watchdog Policy Engine.
Zero external dependencies — standard macOS Python 3.

Evaluates running processes against autonomous watchdog policies.
Tracks sustained runaway CPU usage across monitoring cycles and executes
tiered remediation (QoS clamping to E-cores) and automatic priority restoration.
"""

import os
import sys
import json
import time
from typing import List, Dict, Any, Optional, Tuple

from config import load_config
from safety import is_whitelisted
from remediation import (
    tame_process_to_ecores,
    restore_process_priority,
    send_auto_tame_notification,
    is_process_alive,
)

DEFAULT_HISTORY_FILE = "/tmp/macmonitor_process_history.json"


def load_process_history(history_file: Optional[str] = None) -> Dict[str, Any]:
    """
    Loads process history from disk.
    Returns a dictionary mapping PID string -> candidate metadata.
    Safely returns an empty dictionary if file does not exist or is corrupt.
    """
    path = history_file or DEFAULT_HISTORY_FILE
    if not os.path.isfile(path):
        return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except Exception:
        pass

    return {}


def save_process_history(history: Dict[str, Any], history_file: Optional[str] = None) -> bool:
    """
    Saves process history to disk.
    Automatically creates parent directories.
    Returns True on success, False on error.
    """
    path = history_file or DEFAULT_HISTORY_FILE
    try:
        parent_dir = os.path.dirname(os.path.abspath(path))
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)
            f.write("\n")
        return True
    except Exception:
        return False


def clear_process_history(history_file: Optional[str] = None) -> bool:
    """
    Removes the process history tracking file.
    Returns True if removed or did not exist, False on failure.
    """
    path = history_file or DEFAULT_HISTORY_FILE
    try:
        if os.path.isfile(path):
            os.unlink(path)
        return True
    except Exception:
        return False


def _normalize_proc(proc: Any) -> Optional[Tuple[int, float, str]]:
    """
    Normalizes process representations (dict or tuple/list) into (pid, cpu_pct, comm).
    Returns None if the entry cannot be safely parsed.
    """
    if isinstance(proc, dict):
        try:
            pid = int(proc.get("pid", 0))
            cpu = float(proc.get("cpu_pct", proc.get("cpu", proc.get("pcpu", 0.0))))
            comm = str(proc.get("comm", proc.get("command", proc.get("name", ""))))
            if pid > 0:
                return pid, cpu, comm
        except (ValueError, TypeError):
            return None
    elif isinstance(proc, (list, tuple)) and len(proc) >= 3:
        try:
            # Check if format is (pid, cpu, comm)
            if isinstance(proc[1], (int, float)) and isinstance(proc[0], (int, str)):
                pid = int(proc[0])
                cpu = float(proc[1])
                comm = str(proc[2])
                if pid > 0:
                    return pid, cpu, comm
            # Check if format is (cpu, pid, comm)
            elif isinstance(proc[0], (int, float)) and isinstance(proc[1], (int, str)):
                cpu = float(proc[0])
                pid = int(proc[1])
                comm = str(proc[2])
                if pid > 0:
                    return pid, cpu, comm
        except (ValueError, TypeError):
            return None
    return None


def evaluate_auto_tame_policy(
    top_cpu_procs: List[Any],
    history_file: Optional[str] = None,
    config_data: Optional[Dict[str, Any]] = None,
    current_time: Optional[float] = None,
) -> List[Dict[str, Any]]:
    """
    Evaluates running processes against the autonomous auto-tame policy.

    1. Loads or initializes process history tracking.
    2. Identifies processes exceeding sustained CPU threshold.
    3. If auto_tame["enabled"] is True:
       - Identifies processes exceeding threshold for >= duration_threshold_minutes.
       - Skips whitelisted processes via is_whitelisted(comm, pid, config_data).
       - Invokes tame_process_to_ecores(pid) and sends macOS notification.
       - Records action records.
    4. Auto-restores priority when a previously tamed process drops below threshold.
    5. Cleans up stale entries for processes that normalized or terminated.
    6. Persists updated tracking history to disk.

    Returns:
        List of action dictionaries describing remediation or priority restoration events.
    """
    now = float(current_time) if current_time is not None else time.time()
    cfg = config_data if config_data is not None else load_config()
    history = load_process_history(history_file)

    auto_tame = cfg.get("auto_tame", {})
    enabled = bool(auto_tame.get("enabled", False))
    cpu_threshold = float(auto_tame.get("sustained_cpu_threshold_pct", 90.0))
    duration_min = float(auto_tame.get("duration_threshold_minutes", 15))
    duration_sec = duration_min * 60.0
    action_type = auto_tame.get("action", "tame_to_ecores")

    notif_cfg = cfg.get("notifications", {})
    notifications_enabled = bool(notif_cfg.get("enabled", True))

    actions: List[Dict[str, Any]] = []

    # 1. Parse active processes meeting or exceeding sustained CPU threshold
    active_candidates: Dict[str, Dict[str, Any]] = {}
    for item in top_cpu_procs:
        norm = _normalize_proc(item)
        if norm is None:
            continue
        pid, cpu_pct, comm = norm
        if cpu_pct >= cpu_threshold:
            active_candidates[str(pid)] = {
                "pid": pid,
                "cpu_pct": cpu_pct,
                "comm": comm,
            }

    # 2. Update tracking history and evaluate policy for candidates
    for pid_str, info in active_candidates.items():
        pid = info["pid"]
        comm = info["comm"]
        cpu_pct = info["cpu_pct"]

        if pid_str not in history:
            history[pid_str] = {
                "pid": pid,
                "comm": comm,
                "first_seen": now,
                "last_seen": now,
                "last_cpu": cpu_pct,
                "tamed": False,
                "tamed_at": None,
            }
        else:
            entry = history[pid_str]
            entry["last_seen"] = now
            entry["last_cpu"] = cpu_pct
            if comm:
                entry["comm"] = comm

        entry = history[pid_str]
        elapsed = now - entry.get("first_seen", now)

        # Evaluate autonomous taming threshold
        if enabled:
            if elapsed >= duration_sec and not entry.get("tamed", False):
                # Safety check against immutable & user whitelists
                if is_whitelisted(entry.get("comm", comm), pid=pid, cfg=cfg):
                    continue

                # Execute configured action (default: tame_to_ecores)
                tamed = False
                if action_type == "tame_to_ecores":
                    tamed = tame_process_to_ecores(pid)
                else:
                    tamed = tame_process_to_ecores(pid)

                if tamed:
                    entry["tamed"] = True
                    entry["tamed_at"] = now
                    if notifications_enabled:
                        send_auto_tame_notification(entry.get("comm", comm), pid, int(duration_min), cpu_pct)
                    actions.append({
                        "action": "tame_to_ecores",
                        "pid": pid,
                        "comm": entry.get("comm", comm),
                        "cpu_pct": cpu_pct,
                        "duration_seconds": elapsed,
                        "timestamp": now,
                        "status": "success",
                    })
                else:
                    actions.append({
                        "action": "tame_to_ecores",
                        "pid": pid,
                        "comm": entry.get("comm", comm),
                        "cpu_pct": cpu_pct,
                        "duration_seconds": elapsed,
                        "timestamp": now,
                        "status": "failed",
                    })

    # 3. Clean up stale entries & auto-restore priority when utilization drops
    stale_pids = [p for p in list(history.keys()) if p not in active_candidates]
    for pid_str in stale_pids:
        entry = history[pid_str]
        pid = entry.get("pid", int(pid_str))
        comm = entry.get("comm", "")

        # Auto-restore priority if the process was previously tamed
        if entry.get("tamed", False):
            if is_process_alive(pid):
                restored = restore_process_priority(pid)
                actions.append({
                    "action": "restore_priority",
                    "pid": pid,
                    "comm": comm,
                    "timestamp": now,
                    "status": "success" if restored else "failed",
                })

        del history[pid_str]

    # 4. Persist updated history state
    save_process_history(history, history_file)

    return actions
