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
from typing import Tuple, Set, Optional, Dict, Any

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


def load_user_whitelist(config_path: Optional[str] = None) -> Set[str]:
    """
    Loads optional user whitelist from ~/.config/mac-health/config.json or MAC_HEALTH_CONFIG.
    Returns a set of process names.
    """
    from config import get_config_path
    path = config_path or get_config_path()
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
                    items = set()
                    if "exact_matches" in wl or "substring_patterns" in wl:
                        for em in wl.get("exact_matches", []):
                            if em:
                                items.add(str(em).strip())
                        for sp in wl.get("substring_patterns", []):
                            if sp:
                                items.add(str(sp).strip())
                    else:
                        items = {str(k).strip() for k in wl.keys() if k}
                    return items
    except Exception:
        pass
    return set()


def save_user_whitelist(whitelist: Set[str], config_path: Optional[str] = None) -> bool:
    """
    Saves user whitelist to config file.
    """
    from config import get_config_path
    path = config_path or get_config_path()
    try:
        parent_dir = os.path.dirname(os.path.abspath(path))
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
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
            f.write("\n")
        return True
    except Exception:
        return False


def is_whitelisted(comm: str, pid: int = -1, cfg: Optional[Dict[str, Any]] = None) -> bool:
    """
    Evaluates whether a process is whitelisted against remediation actions.

    Rules:
    - If PID <= 1 (and pid != -1): return True (kernel_task or launchd).
    - If base comm or clean comm in SYSTEM_WHITELIST: return True.
    - If cfg is provided:
      - Check cfg.get("whitelist", {}).get("exact_matches", []): return True if matched.
      - Check cfg.get("whitelist", {}).get("substring_patterns", []): return True if any pattern in comm.lower().
    - Return False otherwise.
    """
    if pid != -1 and pid <= 1:
        return True

    clean_comm = (comm or "").strip()
    if not clean_comm and pid > 1:
        clean_comm = _get_comm_for_pid(pid)
    base_comm = os.path.basename(clean_comm)

    # Immutable system whitelist check
    if base_comm in SYSTEM_WHITELIST or clean_comm in SYSTEM_WHITELIST:
        return True

    # User / Config whitelist check
    if cfg is not None and isinstance(cfg, dict):
        wl = cfg.get("whitelist", {})
        if isinstance(wl, dict):
            exact_matches = wl.get("exact_matches", [])
            if clean_comm in exact_matches or base_comm in exact_matches or comm in exact_matches:
                return True
            substring_patterns = wl.get("substring_patterns", [])
            comm_lower = clean_comm.lower()
            base_lower = base_comm.lower()
            raw_lower = (comm or "").lower()
            for pattern in substring_patterns:
                pat_str = str(pattern).lower()
                if pat_str and (pat_str in raw_lower or pat_str in comm_lower or pat_str in base_lower):
                    return True
        elif isinstance(wl, list):
            if clean_comm in wl or base_comm in wl or comm in wl:
                return True

    return False


def is_action_permitted(pid: int, comm: str = "", config_path: Optional[str] = None) -> Tuple[bool, str]:
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

    # Check full config patterns if available
    try:
        from config import load_config
        cfg = load_config(config_path=config_path)
        if is_whitelisted(clean_comm, pid=pid, cfg=cfg):
            return False, f"Protected user process: '{clean_comm}' matches whitelist pattern."
    except Exception:
        pass

    return True, "Action permitted."


def get_system_whitelist() -> frozenset[str]:
    """Returns the immutable system whitelist."""
    return SYSTEM_WHITELIST
