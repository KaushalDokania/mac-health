#!/usr/bin/env python3
"""
mac-health v2.0 - Safety Shield & Protected Whitelist.
Zero external dependencies — standard macOS Python 3.

Guarantees system integrity by preventing remediation actions (taming, freezing,
or termination) on essential macOS system daemons and user-whitelisted processes.
"""

import os
import sys
import json
import subprocess
from typing import Tuple, Set

# Immutable System Whitelist protecting critical macOS kernel and display infrastructure
SYSTEM_WHITELIST: frozenset[str] = frozenset({
    "kernel_task",
    "launchd",
    "WindowServer",
    "loginwindow",
    "opendirectoryd",
    "sysmond",
})

DEFAULT_CONFIG_PATH = os.path.expanduser("~/.config/mac-health/config.json")


def _get_comm_for_pid(pid: int) -> str:
    """Best-effort retrieval of process command name by PID."""
    if pid <= 0:
        return "kernel_task" if pid == 0 else ""
    try:
        out = subprocess.check_output(
            ["ps", "-p", str(pid), "-o", "comm="],
            stderr=subprocess.DEVNULL,
            timeout=1.0,
        ).decode("utf-8", errors="ignore").strip()
        return out
    except Exception:
        return ""


def load_user_whitelist(config_path: str = None) -> Set[str]:
    """
    Loads optional user whitelist from ~/.config/mac-health/config.json.
    Returns a set of process names.
    """
    path = config_path or DEFAULT_CONFIG_PATH
    if not os.path.isfile(path):
        return set()

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return {str(item).strip() for item in data if item}
            elif isinstance(data, dict):
                wl = data.get("whitelist") or data.get("user_whitelist") or []
                if isinstance(wl, list):
                    return {str(item).strip() for item in wl if item}
                elif isinstance(wl, dict):
                    return {str(k).strip() for k in wl.keys() if k}
    except Exception:
        pass
    return set()


def save_user_whitelist(whitelist: Set[str], config_path: str = None) -> bool:
    """
    Saves user whitelist to config file.
    """
    path = config_path or DEFAULT_CONFIG_PATH
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        config_data = {}
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    if isinstance(loaded, dict):
                        config_data = loaded
            except Exception:
                config_data = {}

        config_data["whitelist"] = sorted(list(whitelist))
        with open(path, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2)
        return True
    except Exception:
        return False


def is_action_permitted(pid: int, comm: str = "", config_path: str = None) -> Tuple[bool, str]:
    """
    Evaluates whether a remediation action is permitted on the specified process.

    Returns:
        (True, "Action permitted.") if action is safe to proceed.
        (False, reason_string) if action must be blocked.
    """
    # Strict rule: Never permit actions on kernel_task (0) or launchd (1) or negative PIDs
    if pid <= 1:
        return False, f"Protected system process: PID {pid} is an essential system init/kernel process (PID <= 1)."

    clean_comm = (comm or "").strip()
    if not clean_comm:
        clean_comm = _get_comm_for_pid(pid)

    base_comm = os.path.basename(clean_comm)

    # Check immutable system whitelist
    if base_comm in SYSTEM_WHITELIST or clean_comm in SYSTEM_WHITELIST:
        matched = base_comm if base_comm in SYSTEM_WHITELIST else clean_comm
        return False, f"Protected system process: '{matched}' is in the immutable system whitelist."

    # Check user whitelist
    user_wl = load_user_whitelist(config_path=config_path)
    if base_comm in user_wl or clean_comm in user_wl:
        matched = base_comm if base_comm in user_wl else clean_comm
        return False, f"Protected user process: '{matched}' is in user whitelist."

    return True, "Action permitted."


def get_system_whitelist() -> frozenset[str]:
    """Returns the immutable system whitelist."""
    return SYSTEM_WHITELIST
