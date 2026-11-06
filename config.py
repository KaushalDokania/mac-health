#!/usr/bin/env python3
"""
mac-health v2.0 - Centralized Configuration Management.
Zero external dependencies — standard macOS Python 3.

Manages persistent user configuration for autonomous watchdog, thresholds,
remediation policies, notifications, and protected process whitelists.
Default path: ~/.config/mac-health/config.json
Override via: MAC_HEALTH_CONFIG environment variable
"""

import os
import sys
import json
from typing import Dict, Any, Optional

DEFAULT_CONFIG_PATH = os.path.expanduser("~/.config/mac-health/config.json")


def get_config_path() -> str:
    """
    Returns the absolute path to the configuration file.
    Prefers the MAC_HEALTH_CONFIG environment variable if set,
    falling back to ~/.config/mac-health/config.json.
    """
    env_path = os.environ.get("MAC_HEALTH_CONFIG")
    if env_path and env_path.strip():
        return os.path.abspath(os.path.expanduser(env_path.strip()))
    return DEFAULT_CONFIG_PATH


def get_default_config() -> Dict[str, Any]:
    """
    Returns a fresh dictionary containing the default v2.0.0 configuration schema.
    """
    return {
        "version": "2.0.0",
        "auto_tame": {
            "enabled": False,
            "sustained_cpu_threshold_pct": 90.0,
            "duration_threshold_minutes": 15,
            "action": "tame_to_ecores",
        },
        "notifications": {
            "enabled": True,
            "sound": True,
            "cooldown_minutes": 30,
        },
        "whitelist": {
            "exact_matches": ["loginwindow", "WindowServer", "kernel_task", "launchd"],
            "substring_patterns": ["antigravity", "cursor", "docker", "ollama", "cargo build"],
        },
    }


def _deep_merge_config(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively merges user configuration over default configuration
    to guarantee all expected keys and nested structures exist safely.
    """
    merged = base.copy()
    for key, val in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(val, dict):
            merged[key] = _deep_merge_config(merged[key], val)
        else:
            merged[key] = val
    return merged


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Loads configuration from the specified path (or get_config_path()).
    Safely falls back to default configuration if the file does not exist,
    cannot be opened, or contains malformed JSON.
    """
    path = config_path or get_config_path()
    defaults = get_default_config()

    if not os.path.isfile(path):
        return defaults

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return _deep_merge_config(defaults, data)
    except Exception:
        pass

    return defaults


def save_config(cfg: Dict[str, Any], config_path: Optional[str] = None) -> bool:
    """
    Saves configuration dictionary to file with indentation.
    Automatically creates parent directory if it does not exist.
    Returns True on success, False on error.
    """
    path = config_path or get_config_path()
    try:
        parent_dir = os.path.dirname(os.path.abspath(path))
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
            f.write("\n")
        return True
    except Exception:
        return False


def reset_config_to_defaults(config_path: Optional[str] = None) -> bool:
    """
    Resets the configuration to default v2.0.0 settings and saves it to disk.
    """
    defaults = get_default_config()
    return save_config(defaults, config_path=config_path)


def format_config_view(cfg: Optional[Dict[str, Any]] = None) -> str:
    """
    Formats a clean, human-readable view of current configuration settings.
    """
    if cfg is None:
        cfg = load_config()

    version = cfg.get("version", "2.0.0")
    auto_tame = cfg.get("auto_tame", {})
    notif = cfg.get("notifications", {})
    wl = cfg.get("whitelist", {})

    at_enabled = "Enabled" if auto_tame.get("enabled") else "Disabled (Monitoring Only)"
    cpu_thresh = auto_tame.get("sustained_cpu_threshold_pct", 90.0)
    duration_min = auto_tame.get("duration_threshold_minutes", 15)
    action = auto_tame.get("action", "tame_to_ecores")

    notif_enabled = "Enabled" if notif.get("enabled") else "Disabled"
    notif_sound = "Yes" if notif.get("sound") else "No"
    cooldown = notif.get("cooldown_minutes", 30)

    if isinstance(wl, dict):
        exact = ", ".join(wl.get("exact_matches", [])) or "None"
        substrings = ", ".join(wl.get("substring_patterns", [])) or "None"
    elif isinstance(wl, list):
        exact = ", ".join(str(x) for x in wl) or "None"
        substrings = "None"
    else:
        exact = "None"
        substrings = "None"

    lines = [
        f"mac-health Configuration (v{version})",
        "━" * 56,
        f"Autonomous Watchdog (Auto-Tame): {at_enabled}",
        f"  • Sustained CPU Threshold : {cpu_thresh}%",
        f"  • Duration Limit          : {duration_min} minutes",
        f"  • Remediation Action      : {action}",
        "",
        f"macOS Notifications           : {notif_enabled}",
        f"  • Notification Audio      : {notif_sound}",
        f"  • Alert Cooldown          : {cooldown} minutes",
        "",
        f"Protected Process Whitelist   :",
        f"  • Exact Matches           : {exact}",
        f"  • Substring Patterns      : {substrings}",
        "━" * 56,
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    print(format_config_view())
