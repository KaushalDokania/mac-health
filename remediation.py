#!/usr/bin/env python3
"""
mac-health v2.0 - Tiered Remediation Engine.
Zero external dependencies — standard macOS Python 3.

Tier 1: Apple Silicon QoS Clamping (taskpolicy + renice)
        Clamps runaway processes to Efficiency cores (PRIO_DARWIN_BG),
        leaving 100% Performance cores free for developer IDEs and builds.
Tier 2: Freeze & Resume (SIGSTOP / SIGCONT)
        Safely halts execution with open socket/lock checks and auto-resume safety timer.
Tier 3: Launchd Shield & Tree Termination (SIGTERM / SIGKILL)
        Inspects launchd hierarchy to prevent crash/respawn storms,
        then cleanly cascades termination down the process group.
Unified Memory: Ollama model eviction via REST API.
"""

import os
import sys
import time
import json
import signal
import threading
import subprocess
import urllib.request
from typing import Tuple, List, Dict, Optional, Any

from safety import is_action_permitted

FROZEN_RECORDS_FILE = "/tmp/mac_health_frozen.json"
OLLAMA_DEFAULT_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")


# ==============================================================================
# Helper / Process Inspection Utilities
# ==============================================================================

def get_comm_for_pid(pid: int) -> str:
    """Gets the command name or path for a given PID."""
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


def get_process_ppid(pid: int) -> Optional[int]:
    """Gets the parent PID (PPID) for a given PID."""
    if pid <= 0:
        return None
    try:
        out = subprocess.check_output(
            ["ps", "-p", str(pid), "-o", "ppid="],
            stderr=subprocess.DEVNULL,
            timeout=1.0,
        ).decode("utf-8", errors="ignore").strip()
        return int(out) if out else None
    except Exception:
        return None


def is_process_alive(pid: int) -> bool:
    """Checks whether a PID exists and is currently running."""
    if pid <= 0:
        return False
    # If it is a direct child of the current process, reap zombie if exited
    try:
        pid_reaped, _ = os.waitpid(pid, os.WNOHANG)
        if pid_reaped == pid:
            return False
    except ChildProcessError:
        pass
    except Exception:
        pass

    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _fallback_get_open_descriptors_and_locks(pid: int) -> Dict[str, Any]:
    """
    Fallback descriptor and socket inspection using standard macOS lsof.
    Used if diagnostics.py is unavailable.
    """
    try:
        res = subprocess.run(
            ["lsof", "-Pan", "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=2.0,
        )
        sockets = []
        locks = []
        total_files = 0
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                total_files += 1
                lower = line.lower()
                if "listen" in lower or "established" in lower or "udp" in lower or "tcp" in lower:
                    sockets.append(line.strip())
                if "lock" in lower or " lk " in lower or "txt" in lower:
                    locks.append(line.strip())
        return {
            "sockets": sockets,
            "locks": locks,
            "has_locks": len(locks) > 0,
            "file_count": total_files,
        }
    except Exception:
        return {"sockets": [], "locks": [], "has_locks": False, "file_count": 0}


# Safely import diagnostics descriptor helper or fallback
try:
    from diagnostics import get_open_descriptors_and_locks
except ImportError:
    get_open_descriptors_and_locks = _fallback_get_open_descriptors_and_locks


# ==============================================================================
# Tier 1: Apple Silicon QoS Clamping (E-Cores)
# ==============================================================================

def tame_process_to_ecores(pid: int) -> bool:
    """
    Restricts a runaway process strictly to Apple Silicon Efficiency cores (E-cores).
    - `taskpolicy -b -p <PID>`: Sets Background QoS (PRIO_DARWIN_BG)
    - `taskpolicy -d throttle -p <PID>`: Throttles disk I/O throughput
    - `renice +19 -p <PID>`: Lowers standard CPU scheduling priority
    Leaves 100% of Performance cores (P-cores) available for developer tasks.
    Returns True on success, False if blocked by safety whitelist or failed.
    """
    comm = get_comm_for_pid(pid)
    permitted, reason = is_action_permitted(pid, comm)
    if not permitted:
        sys.stderr.write(f"Safety Shield: Cannot tame PID {pid} ({comm}): {reason}\n")
        return False

    success = False

    # 1. Background QoS (Darwin BG -> Efficiency cores)
    try:
        r1 = subprocess.run(
            ["taskpolicy", "-b", "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=2.0,
        )
        if r1.returncode == 0:
            success = True
    except Exception:
        pass

    # 2. Disk I/O throttling
    try:
        r2 = subprocess.run(
            ["taskpolicy", "-d", "throttle", "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=2.0,
        )
        if r2.returncode == 0:
            success = True
    except Exception:
        pass

    # 3. CPU renice to lowest priority (+19)
    try:
        r3 = subprocess.run(
            ["renice", "+19", "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=2.0,
        )
        if r3.returncode == 0:
            success = True
    except Exception:
        pass

    return success


# ==============================================================================
# Tier 2: Freeze & Resume (SIGSTOP / SIGCONT) with Auto-Resume Safety
# ==============================================================================

def _load_frozen_records() -> Dict[str, Any]:
    """Loads state of currently frozen processes."""
    if os.path.exists(FROZEN_RECORDS_FILE):
        try:
            with open(FROZEN_RECORDS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except Exception:
            pass
    return {}


def _save_frozen_records(data: Dict[str, Any]) -> None:
    """Persists frozen processes state."""
    try:
        with open(FROZEN_RECORDS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def freeze_process(pid: int, auto_resume_seconds: Optional[float] = None) -> Tuple[bool, str]:
    """
    Suspends a runaway process via SIGSTOP after inspecting open sockets and locks.
    Records frozen state in /tmp/mac_health_frozen.json.
    Optionally starts an auto-resume safety timer to prevent permanent freezes.

    Returns:
        (True, status_message) or (False, error_reason)
    """
    comm = get_comm_for_pid(pid)
    permitted, reason = is_action_permitted(pid, comm)
    if not permitted:
        return False, f"Safety Shield: {reason}"

    # Check open sockets / locks before freezing
    desc_info = get_open_descriptors_and_locks(pid)
    warning_note = ""
    if isinstance(desc_info, dict) and desc_info.get("has_locks", False):
        warning_note = " (Warning: process holds active file/socket locks)"

    try:
        os.kill(pid, signal.SIGSTOP)
    except ProcessLookupError:
        return False, f"Process {pid} not found."
    except PermissionError:
        return False, f"Permission denied to freeze PID {pid}."
    except Exception as e:
        return False, f"Failed to freeze PID {pid}: {e}"

    # Record frozen entry
    frozen_records = _load_frozen_records()
    frozen_records[str(pid)] = {
        "pid": pid,
        "comm": comm,
        "frozen_at": time.time(),
        "has_locks": desc_info.get("has_locks", False) if isinstance(desc_info, dict) else False,
        "auto_resume_seconds": auto_resume_seconds,
    }
    _save_frozen_records(frozen_records)

    # Auto-resume timer
    if auto_resume_seconds and auto_resume_seconds > 0:
        def _safety_auto_resume():
            time.sleep(auto_resume_seconds)
            current = _load_frozen_records()
            if str(pid) in current:
                unfreeze_process(pid)

        timer_thread = threading.Thread(target=_safety_auto_resume, daemon=True)
        timer_thread.start()

    msg = f"Process {pid} ({comm or 'unknown'}) suspended via SIGSTOP{warning_note}."
    return True, msg


def unfreeze_process(pid: int) -> bool:
    """
    Resumes a previously frozen process via SIGCONT and cleans up frozen state.
    Returns True on success, False otherwise.
    """
    try:
        os.kill(pid, signal.SIGCONT)
    except ProcessLookupError:
        # Process already gone, clean up record
        frozen_records = _load_frozen_records()
        if str(pid) in frozen_records:
            del frozen_records[str(pid)]
            _save_frozen_records(frozen_records)
        return True
    except PermissionError:
        return False
    except Exception:
        return False

    frozen_records = _load_frozen_records()
    if str(pid) in frozen_records:
        del frozen_records[str(pid)]
        _save_frozen_records(frozen_records)

    return True


def get_frozen_processes() -> Dict[str, Any]:
    """Returns currently recorded frozen processes."""
    return _load_frozen_records()


def auto_resume_frozen_processes(max_age_seconds: float = 300.0) -> List[int]:
    """
    Safety sweep: unfreezes any processes that have been frozen longer than max_age_seconds.
    Returns list of resumed PIDs.
    """
    records = _load_frozen_records()
    now = time.time()
    resumed = []
    for pid_str, info in list(records.items()):
        try:
            pid = int(pid_str)
            frozen_at = info.get("frozen_at", now)
            age = now - frozen_at
            allowed_duration = info.get("auto_resume_seconds") or max_age_seconds
            if age >= allowed_duration:
                if unfreeze_process(pid):
                    resumed.append(pid)
        except Exception:
            continue
    return resumed


# ==============================================================================
# Tier 3: Launchd Shield & Tree Termination
# ==============================================================================

def is_managed_by_launchd(pid: int) -> Tuple[bool, Optional[str]]:
    """
    Detects if a PID is managed by launchd (PPID == 1 or listed in launchctl list).
    Returns (is_managed, service_label_or_None).
    """
    # 1. Check launchctl list
    try:
        proc = subprocess.run(
            ["launchctl", "list"],
            capture_output=True,
            text=True,
            timeout=1.5,
        )
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 3 and parts[0] == str(pid):
                    return True, parts[2]
    except Exception:
        pass

    # 2. Check PPID == 1
    ppid = get_process_ppid(pid)
    if ppid == 1:
        return True, None

    return False, None


def _bootout_launchd_service(service_label: str) -> bool:
    """Attempts to cleanly bootout a launchd service to prevent respawn storm."""
    uid = os.getuid()
    for domain in [f"gui/{uid}/{service_label}", f"system/{service_label}"]:
        try:
            res = subprocess.run(
                ["launchctl", "bootout", domain],
                capture_output=True,
                timeout=1.5,
            )
            if res.returncode == 0:
                return True
        except Exception:
            pass
    return False


def terminate_process_tree(pid: int, force: bool = False, timeout: float = 2.5) -> bool:
    """
    Terminates a process and its child hierarchy safely.
    1. Checks Safety Shield whitelist.
    2. Checks launchd shield: if service is registered in launchctl, boots out service
       or warns before kill to prevent infinite respawn loops.
    3. Sends SIGTERM to children (pkill -TERM -P) and parent.
    4. Waits up to timeout (default 2.5s). If still alive or force=True, escalates
       to SIGKILL (pkill -KILL -P) and parent SIGKILL.

    Returns True if termination succeeded or process is dead, False if blocked/failed.
    """
    comm = get_comm_for_pid(pid)
    permitted, reason = is_action_permitted(pid, comm)
    if not permitted:
        sys.stderr.write(f"Safety Shield: Refusing to terminate PID {pid} ({comm}): {reason}\n")
        return False

    # Launchd Shield: check if managed by launchd
    is_launchd, service_label = is_managed_by_launchd(pid)
    if is_launchd:
        if service_label:
            # Clean bootout through launchctl to prevent respawn loops
            _bootout_launchd_service(service_label)

    # 1. Graceful SIGTERM cascade to child tree and parent
    try:
        subprocess.run(["pkill", "-TERM", "-P", str(pid)], capture_output=True, timeout=1.0)
    except Exception:
        pass

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    except Exception:
        pass

    if force:
        # Immediate SIGKILL escalation
        try:
            subprocess.run(["pkill", "-KILL", "-P", str(pid)], capture_output=True, timeout=1.0)
        except Exception:
            pass
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except Exception:
            pass
        return not is_process_alive(pid)

    # Wait up to timeout (2.5s) for graceful exit
    start_time = time.time()
    while time.time() - start_time < timeout:
        if not is_process_alive(pid):
            return True
        time.sleep(0.1)

    # Escalate to SIGKILL if still running
    try:
        subprocess.run(["pkill", "-KILL", "-P", str(pid)], capture_output=True, timeout=1.0)
    except Exception:
        pass

    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return True
    except Exception:
        pass

    # Final check
    return not is_process_alive(pid)


# ==============================================================================
# Unified Memory: Ollama Model Eviction
# ==============================================================================

def unload_ollama_model(model_name: str, host: Optional[str] = None) -> bool:
    """
    Releases Apple Silicon unified memory by evicting an active Ollama model.
    Sends POST {"model": model_name, "keep_alive": 0} to Ollama HTTP REST API
    with a 2.0s timeout. Does NOT invoke ollama CLI (prevents auto-launching Ollama.app).
    Returns True on success, False otherwise.
    """
    target_host = host or OLLAMA_DEFAULT_HOST
    if not target_host.startswith(("http://", "https://")):
        target_host = "http://" + target_host
    url = f"{target_host.rstrip('/')}/api/generate"

    payload = json.dumps({"model": model_name, "keep_alive": 0}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "mac-health",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


# ==============================================================================
# Triage Process Inspection & Candidate Ranking
# ==============================================================================

def get_triage_candidates(sort_by: str = "composite", limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Gathers running processes via `ps -eo pid,ppid,%cpu,rss,comm` and computes
    composite runaway scores:
        composite = cpu_pct + (3.0 * ram_gb)
    Sorts by:
        - 'composite': runaway impact (CPU + RAM combined)
        - 'cpu': highest %CPU
        - 'memory' (or 'ram'): highest RAM consumption (GB)

    Returns a list of candidate dictionaries.
    """
    candidates = []
    try:
        out = subprocess.check_output(
            ["ps", "-eo", "pid,ppid,%cpu,rss,comm"],
            stderr=subprocess.DEVNULL,
            timeout=3.0,
        ).decode("utf-8", errors="ignore")
    except Exception:
        return []

    lines = [line.strip() for line in out.splitlines()[1:] if line.strip()]
    for line in lines:
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        try:
            pid = int(parts[0])
            ppid = int(parts[1])
            cpu_pct = float(parts[2])
            rss_kb = float(parts[3])
            comm = parts[4]

            ram_gb = rss_kb / (1024.0 * 1024.0)
            composite = cpu_pct + (3.0 * ram_gb)
            base_comm = os.path.basename(comm)

            permitted, _ = is_action_permitted(pid, comm)
            is_protected = not permitted

            candidates.append({
                "pid": pid,
                "ppid": ppid,
                "cpu_pct": round(cpu_pct, 1),
                "rss_kb": round(rss_kb, 1),
                "ram_gb": round(ram_gb, 3),
                "comm": comm,
                "base_comm": base_comm,
                "composite": round(composite, 2),
                "is_protected": is_protected,
            })
        except Exception:
            continue

    sort_key = sort_by.lower()
    if sort_key == "cpu":
        candidates.sort(key=lambda x: x["cpu_pct"], reverse=True)
    elif sort_key in ("memory", "ram", "rss"):
        candidates.sort(key=lambda x: x["ram_gb"], reverse=True)
    else:  # default 'composite'
        candidates.sort(key=lambda x: x["composite"], reverse=True)

    if limit and limit > 0:
        return candidates[:limit]
    return candidates
