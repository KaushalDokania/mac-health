#!/usr/bin/env python3
"""
mac-health v2.0 - Diagnostics & Process Lineage Engine
Zero external dependencies — standard macOS Python 3 library only.

Provides:
  1. SIP unprivileged thread sampling fallback ladder:
     - Tier A: /usr/bin/sample <PID> 0.5 -mayDie
     - Tier B: ps -M -O state,pri,wq -p <PID> (thread-state analysis)
     - Tier C: Instant CPU delta across 250ms (core saturation rate)
  2. Recursive process lineage tree resolver up to PID 1 (launchd) or PID 0 (kernel_task).
     Annotates parent apps (Cursor.app, Code.app, iTerm2.app, Terminal.app, tmux, antigravity)
     and flags daemon/agent status if parent is launchd.
  3. Process execution context (args, cwd, git repository and branch).
  4. Open file descriptors, socket extraction (established/listening), and lock detection
     (.lock, .git/index.lock, *.wal, flock).
  5. System daemon diagnostics for WindowServer (Skylight logs, top GUI consumers)
     and mds_stores (Spotlight indexing paths and developer dir detection).
"""

import os
import sys
import re
import time
import json
import subprocess
from typing import Optional, Dict, List, Any, Tuple

__all__ = [
    # Sampling & Fallback Ladder
    "sample_process",
    "sample_tier_a",
    "sample_tier_b",
    "sample_tier_c",
    "measure_cpu_delta",
    "parse_sample_output",
    "parse_ps_m_output",
    "parse_ps_time",
    
    # Process Lineage Tree
    "resolve_process_lineage",
    "annotate_app",
    "get_process_info",
    
    # Execution Context
    "get_process_execution_context",
    "get_process_args",
    "get_process_cwd",
    "get_git_context",
    "parse_lsof_cwd",
    
    # Open Descriptors & Locks
    "get_process_descriptors_and_locks",
    "parse_lsof_descriptors",
    
    # System Daemon Diagnostics
    "diagnose_windowserver",
    "diagnose_mds_stores",
    "parse_mds_stores_paths",
    
    # Comprehensive Process Doctor
    "diagnose_process",
]

# ---------------------------------------------------------------------------
# Utility & Helper Functions
# ---------------------------------------------------------------------------

def run_command(
    cmd_list: List[str],
    timeout: Optional[float] = None,
    cwd: Optional[str] = None
) -> Tuple[int, str, str]:
    """
    Safely executes a system command and returns (exit_code, stdout, stderr).
    Catches common OS/permission/timeout errors gracefully.
    """
    try:
        proc = subprocess.run(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            cwd=cwd,
            errors="replace"
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout.decode("utf-8", errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        stderr = e.stderr.decode("utf-8", errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
        return -1, stdout, stderr or "Command timed out"
    except (PermissionError, FileNotFoundError, OSError) as e:
        return 127, "", str(e)


def parse_ps_time(time_str: str) -> float:
    """
    Parses macOS ps time formats into total seconds.
    Supported formats:
      - '0:00.08' (minutes:seconds.hundredths)
      - '01:23.45'
      - '01:02:03.45' (hours:minutes:seconds.hundredths)
      - '2-01:02:03' (days-hours:minutes:seconds)
      - '12.34' (seconds only)
    """
    time_str = (time_str or "").strip()
    if not time_str or time_str == "-":
        return 0.0

    days = 0.0
    if "-" in time_str:
        day_part, time_str = time_str.split("-", 1)
        try:
            days = float(day_part)
        except ValueError:
            days = 0.0

    parts = time_str.split(":")
    try:
        if len(parts) == 3:
            h, m, s = parts
            return days * 86400.0 + float(h) * 3600.0 + float(m) * 60.0 + float(s)
        elif len(parts) == 2:
            m, s = parts
            return days * 86400.0 + float(m) * 60.0 + float(s)
        elif len(parts) == 1:
            return days * 86400.0 + float(parts[0])
    except ValueError:
        return 0.0

    return 0.0


# ---------------------------------------------------------------------------
# Tier A, B, C: SIP Unprivileged Thread Sampling Fallback Ladder
# ---------------------------------------------------------------------------

def parse_sample_output(sample_output: str, max_symbols: int = 10) -> List[Dict[str, Any]]:
    """
    Parses /usr/bin/sample output text to extract top symbols and their sample counts.
    Checks the 'Sort by top of stack, same collapsed' section first,
    falling back to leaf stack frames from the 'Call graph' section.
    """
    symbols: List[Dict[str, Any]] = []
    if not sample_output:
        return symbols

    # Section 1: "Sort by top of stack, same collapsed (when >= 5):"
    m = re.search(
        r"Sort by top of stack, same collapsed.*?\n(.*?)(?:\n\n|\n[A-Z]|\Z)",
        sample_output,
        re.DOTALL
    )
    if m:
        for line in m.group(1).splitlines():
            line = line.strip()
            if not line:
                continue
            sm = re.match(r"^(.*?)\s{2,}(\d+)$", line)
            if sm:
                sym_name = re.sub(r"\s+", " ", sm.group(1).strip())
                count = int(sm.group(2))
                symbols.append({"symbol": sym_name, "count": count})
                if len(symbols) >= max_symbols:
                    break

    # Section 2: If no symbols found in collapsed section, parse Call graph leaf nodes
    if not symbols:
        call_graph_match = re.search(r"Call graph:\n(.*?)(?:\n\n|\n[A-Z]|\Z)", sample_output, re.DOTALL)
        if call_graph_match:
            lines = call_graph_match.group(1).splitlines()
            for line in lines:
                # Matches: count symbol_name (in library) + offset [address]
                gm = re.match(r"^\s*(\d+)\s+([^\+\[]+?)(?:\s+\+\s+\d+)?(?:\s+\[0x[0-9a-fA-F]+\])?\s*$", line)
                if gm:
                    count = int(gm.group(1))
                    sym = re.sub(r"\s+", " ", gm.group(2).strip())
                    if not sym.startswith("Thread_") and not sym.startswith("DispatchQueue_") and sym != "???":
                        symbols.append({"symbol": sym, "count": count})

            # Sort by sample count descending and take unique symbols
            seen = set()
            unique_symbols = []
            for s in sorted(symbols, key=lambda x: x["count"], reverse=True):
                if s["symbol"] not in seen:
                    seen.add(s["symbol"])
                    unique_symbols.append(s)
                    if len(unique_symbols) >= max_symbols:
                        break
            symbols = unique_symbols

    return symbols


def sample_tier_a(pid: int, timeout: float = 1.5) -> Optional[Dict[str, Any]]:
    """
    Tier A: Runs `/usr/bin/sample <PID> 0.5 -mayDie` with 1.5s timeout.
    Returns parsed symbols if privileged and successful, or None if restricted by SIP / permissions.
    """
    cmd = ["/usr/bin/sample", str(pid), "0.5", "-mayDie"]
    code, stdout, stderr = run_command(cmd, timeout=timeout)

    # Check for permission error / SIP or non-zero exit code
    combined = f"{stdout}\n{stderr}"
    if code != 0 or "do not have appropriate privileges" in combined or "try running with `sudo`" in combined:
        return None

    symbols = parse_sample_output(stdout)
    if not symbols and "Analysis of sampling" not in stdout:
        return None

    top_symbol = symbols[0]["symbol"] if symbols else None
    return {
        "tier": "A",
        "method": "sample",
        "success": True,
        "pid": pid,
        "symbols": symbols,
        "top_symbol": top_symbol,
        "symbol_count": len(symbols),
    }


def parse_ps_m_output(ps_output: str) -> Dict[str, Any]:
    """
    Parses `ps -M -O state,pri,wq -p <PID>` output.
    Counts:
      - running threads ('R')
      - disk wait / uninterruptible wait threads ('U' or 'D')
      - sleeping threads ('S' or 'I')
      - other threads ('T', 'Z', etc.)
    """
    lines = [l for l in (ps_output or "").strip().splitlines() if l.strip()]
    if not lines:
        return {
            "running": 0,
            "disk_wait": 0,
            "sleeping": 0,
            "other": 0,
            "total": 0,
            "threads": [],
        }

    # Strip header line if present
    data_lines = lines[1:] if ("PID" in lines[0] and "STAT" in lines[0]) else lines

    running = 0
    disk_wait = 0
    sleeping = 0
    other = 0
    threads = []

    for line in data_lines:
        # Regex 1: matches '%CPU STAT PRI' e.g. '0.0 S 31T'
        m = re.search(r"\s+(\d+\.\d+)\s+([A-Za-z\+\<\>]+)\s+(\d+[A-Za-z])", line)
        if not m:
            # Regex 2: matches 'PID STAT PRI WQ' e.g. '1 S 31T 2'
            m = re.search(r"\s+(\d+)\s+([A-Za-z\+\<\>]+)\s+(\d+[A-Za-z])\s+([\d\-]+)", line)

        state_char = ""
        pri = ""
        wq = "-"
        if m:
            state_raw = m.group(2)
            state_char = state_raw[0].upper()
            pri = m.group(3)
            if len(m.groups()) >= 4:
                wq = m.group(4)
        else:
            # Fallback token extraction
            tokens = line.split()
            for tok in tokens:
                if len(tok) <= 3 and tok[0] in "RSUIDTZ":
                    state_char = tok[0].upper()
                    break

        if state_char == "R":
            running += 1
        elif state_char in ("U", "D"):
            disk_wait += 1
        elif state_char in ("S", "I"):
            sleeping += 1
        else:
            other += 1

        threads.append({
            "state": state_char or "S",
            "pri": pri,
            "wq": wq,
            "is_running": (state_char == "R"),
            "is_disk_wait": (state_char in ("U", "D")),
            "is_sleeping": (state_char in ("S", "I")),
        })

    return {
        "running": running,
        "disk_wait": disk_wait,
        "sleeping": sleeping,
        "other": other,
        "total": len(data_lines),
        "threads": threads,
    }


def sample_tier_b(pid: int) -> Optional[Dict[str, Any]]:
    """
    Tier B: Fallback to unprivileged thread-state analysis via `ps -M -O state,pri,wq -p <PID>`.
    Counts running (`R`), disk wait (`U`), sleeping (`S`).
    """
    cmd = ["ps", "-M", "-O", "state,pri,wq", "-p", str(pid)]
    code, stdout, stderr = run_command(cmd)

    if code != 0 or not stdout.strip():
        return None

    counts = parse_ps_m_output(stdout)
    return {
        "tier": "B",
        "method": "ps_threads",
        "success": True,
        "pid": pid,
        "thread_counts": {
            "running": counts["running"],
            "disk_wait": counts["disk_wait"],
            "sleeping": counts["sleeping"],
            "other": counts["other"],
            "total": counts["total"],
        },
        "threads": counts["threads"],
        "fallback_reason": "SIP/privilege restricted Tier A; used thread-state analysis",
    }


def measure_cpu_delta(pid: int, interval: float = 0.25) -> Dict[str, Any]:
    """
    Tier C: Measures instant CPU delta across `interval` seconds (default 250ms)
    to report core saturation rate and CPU utilization percentage.
    """
    cmd = ["ps", "-o", "utime=,stime=", "-p", str(pid)]

    # Sample 0
    t0 = time.time()
    code0, out0, _ = run_command(cmd)
    if code0 != 0 or not out0.strip():
        return {
            "tier": "C",
            "method": "cpu_delta",
            "success": False,
            "pid": pid,
            "cpu_percent": 0.0,
            "core_saturation_rate": 0.0,
            "interval_sec": interval,
            "error": f"Failed to inspect CPU time for PID {pid}",
        }

    toks0 = out0.strip().split()
    cpu_t0 = parse_ps_time(toks0[0]) + (parse_ps_time(toks0[1]) if len(toks0) > 1 else 0.0)

    time.sleep(interval)

    # Sample 1
    t1 = time.time()
    code1, out1, _ = run_command(cmd)
    if code1 != 0 or not out1.strip():
        return {
            "tier": "C",
            "method": "cpu_delta",
            "success": False,
            "pid": pid,
            "cpu_percent": 0.0,
            "core_saturation_rate": 0.0,
            "interval_sec": interval,
            "error": f"Process exited or disappeared during interval",
        }

    toks1 = out1.strip().split()
    cpu_t1 = parse_ps_time(toks1[0]) + (parse_ps_time(toks1[1]) if len(toks1) > 1 else 0.0)

    elapsed = max(0.001, t1 - t0)
    cpu_time_used = max(0.0, cpu_t1 - cpu_t0)

    # Saturation: 1.0 = 100% of 1 core
    core_saturation = cpu_time_used / elapsed
    cpu_percent = core_saturation * 100.0

    return {
        "tier": "C",
        "method": "cpu_delta",
        "success": True,
        "pid": pid,
        "cpu_percent": round(cpu_percent, 2),
        "core_saturation_rate": round(core_saturation, 3),
        "interval_sec": round(elapsed, 4),
        "fallback_reason": "Thread sampling fallback Tier C instant CPU delta",
    }


def sample_tier_c(pid: int, interval: float = 0.25) -> Dict[str, Any]:
    """Alias for measure_cpu_delta as Tier C."""
    return measure_cpu_delta(pid, interval=interval)


def sample_process(pid: int, timeout: float = 1.5, cpu_interval: float = 0.25) -> Dict[str, Any]:
    """
    Executes the SIP Unprivileged Thread Sampling Fallback Ladder:
      1. Tier A: /usr/bin/sample <PID> 0.5 -mayDie (timeout 1.5s)
      2. Tier B: ps -M -O state,pri,wq -p <PID> (counts R, U, S)
      3. Tier C: Instant CPU delta across 250ms (core saturation rate)
    """
    # Try Tier A
    tier_a = sample_tier_a(pid, timeout=timeout)
    if tier_a is not None:
        return tier_a

    # Fallback to Tier B
    tier_b = sample_tier_b(pid)
    if tier_b is not None:
        return tier_b

    # Fallback to Tier C
    return sample_tier_c(pid, interval=cpu_interval)


# ---------------------------------------------------------------------------
# Process Lineage Tree Resolver
# ---------------------------------------------------------------------------

def annotate_app(comm: str, args: str = "") -> Optional[str]:
    """
    Annotates parent applications like Cursor.app, Code.app, iTerm2.app,
    Terminal.app, tmux, antigravity, or any standard macOS .app bundle.
    """
    combined = f"{comm or ''} {args or ''}".strip()
    if not combined:
        return None

    # Specific known developer tools & terminals
    if re.search(r"Cursor(?:\.app)?\b", combined):
        return "Cursor.app"
    if re.search(r"(?:Visual Studio Code|Code Helper|(?:\b|/)code(?:\.app)?\b)", combined):
        return "Code.app"
    if re.search(r"iTerm(?:2)?(?:\.app)?\b", combined):
        return "iTerm2.app"
    if re.search(r"(?:/Applications(?:/Utilities)?/)?Terminal\.app|\bTerminal\b", combined):
        return "Terminal.app"
    if re.search(r"\btmux\b", combined):
        return "tmux"
    if re.search(r"\bantigravity\b", combined):
        return "antigravity"

    # Generic macOS Application Bundle (.app)
    app_match = re.search(r"/([^/]+\.app)(?:/|$)", combined)
    if app_match:
        return app_match.group(1)

    return None


def get_process_info(pid: int) -> Optional[Dict[str, Any]]:
    """
    Fetches PPID, comm, and user for a single PID via `ps -o ppid=,comm=,user= -p <PID>`.
    """
    cmd = ["ps", "-o", "ppid=,comm=,user=", "-p", str(pid)]
    code, stdout, stderr = run_command(cmd)
    if code != 0 or not stdout.strip():
        return None

    line = stdout.strip().splitlines()[0].strip()
    tokens = line.split()
    if len(tokens) < 3:
        return None

    try:
        ppid = int(tokens[0])
    except ValueError:
        return None

    user = tokens[-1]
    comm = " ".join(tokens[1:-1])

    is_launchd = (pid == 1 or "launchd" in comm)
    app = annotate_app(comm)

    return {
        "pid": pid,
        "ppid": ppid,
        "comm": comm,
        "user": user,
        "app": app,
        "is_launchd": is_launchd,
    }


def resolve_process_lineage(pid: int, max_depth: int = 50) -> Dict[str, Any]:
    """
    Climbs parent PPIDs recursively up to PID 1 (launchd) or PID 0 (kernel_task).
    Annotates parent applications and flags daemon/agent status if parent is launchd.
    """
    lineage: List[Dict[str, Any]] = []
    visited = set()
    current_pid = pid

    for _ in range(max_depth):
        if current_pid in visited:
            break
        visited.add(current_pid)

        info = get_process_info(current_pid)
        if not info:
            break

        lineage.append(info)

        ppid = info["ppid"]
        # Stop at launchd or kernel_task
        if current_pid <= 1 or ppid == 0 or ppid == current_pid:
            break

        current_pid = ppid

    # Immediate parent check for daemon/agent
    is_daemon_or_agent = False
    if len(lineage) > 1 and lineage[1]["is_launchd"]:
        is_daemon_or_agent = True
    elif len(lineage) == 1 and lineage[0]["ppid"] == 1:
        is_daemon_or_agent = True

    # Identify closest parent app annotation
    parent_app = None
    for node in lineage[1:]:
        if node.get("app"):
            parent_app = node["app"]
            break

    root_ancestor = lineage[-1] if lineage else None

    return {
        "pid": pid,
        "lineage": lineage,
        "depth": len(lineage),
        "parent_app": parent_app,
        "is_daemon_or_agent": is_daemon_or_agent,
        "root_ancestor": root_ancestor,
    }


# ---------------------------------------------------------------------------
# Execution Context
# ---------------------------------------------------------------------------

def get_process_args(pid: int) -> Optional[str]:
    """Retrieves full process arguments via `ps -ww -o args= -p <PID>`."""
    cmd = ["ps", "-ww", "-o", "args=", "-p", str(pid)]
    code, stdout, _ = run_command(cmd)
    if code == 0 and stdout.strip():
        return stdout.strip()
    return None


def parse_lsof_cwd(lsof_output: str) -> Optional[str]:
    """Parses cwd path from `lsof -a -p <PID> -d cwd -Fn` output."""
    if not lsof_output:
        return None
    for line in lsof_output.splitlines():
        if line.startswith("n/") or (line.startswith("n") and len(line) > 1):
            return line[1:].strip()
    return None


def get_process_cwd(pid: int) -> Optional[str]:
    """Retrieves current working directory via `lsof -a -p <PID> -d cwd -Fn`."""
    cmd = ["lsof", "-a", "-p", str(pid), "-d", "cwd", "-Fn"]
    code, stdout, _ = run_command(cmd)
    if code == 0 and stdout.strip():
        return parse_lsof_cwd(stdout)
    return None


def get_git_context(cwd: Optional[str]) -> Optional[Dict[str, Any]]:
    """
    If cwd has .git (or is within a git repository / worktree),
    extracts the repository name and current branch via `git rev-parse`.
    """
    if not cwd or not os.path.exists(cwd):
        return None

    # Check if directory or parent contains .git
    git_check = os.path.join(cwd, ".git")
    if not os.path.exists(git_check):
        # Also check git rev-parse directly in case cwd is a subdirectory
        code_toplevel, out_toplevel, _ = run_command(
            ["git", "-C", cwd, "rev-parse", "--show-toplevel"],
            timeout=1.5
        )
        if code_toplevel != 0 or not out_toplevel.strip():
            return None
        repo_root = out_toplevel.strip()
    else:
        repo_root = cwd

    # Get branch
    code_branch, out_branch, _ = run_command(
        ["git", "-C", cwd, "rev-parse", "--abbrev-ref", "HEAD"],
        timeout=1.5
    )
    branch = out_branch.strip() if code_branch == 0 else "HEAD"

    # Get toplevel if not determined
    if repo_root == cwd:
        code_top, out_top, _ = run_command(
            ["git", "-C", cwd, "rev-parse", "--show-toplevel"],
            timeout=1.5
        )
        if code_top == 0 and out_top.strip():
            repo_root = out_top.strip()

    repo_name = os.path.basename(repo_root)

    return {
        "is_repo": True,
        "branch": branch,
        "repo_name": repo_name,
        "repo_root": repo_root,
    }


def get_process_execution_context(pid: int) -> Dict[str, Any]:
    """
    Retrieves full execution context for a process:
      - Command line arguments
      - Working directory (cwd)
      - Git repo & branch (if inside a git repository)
    """
    args = get_process_args(pid)
    cwd = get_process_cwd(pid)
    git_info = get_git_context(cwd) if cwd else None

    return {
        "pid": pid,
        "args": args,
        "cwd": cwd,
        "git": git_info,
    }


# ---------------------------------------------------------------------------
# Open Descriptors & Locks
# ---------------------------------------------------------------------------

def parse_lsof_descriptors(lsof_output: str) -> Dict[str, Any]:
    """
    Parses `lsof -a -p <PID> -Fn -Ft` output.
    Extracts:
      - Count of open file descriptors (numeric FDs)
      - Established and listening TCP/UDP sockets (remote IP, port)
      - Locks: .lock, .git/index.lock, *.wal, flock
    """
    descriptors: List[Dict[str, str]] = []
    curr_fd: Optional[str] = None
    curr_type = ""
    curr_name = ""

    for line in (lsof_output or "").splitlines():
        if not line:
            continue
        tag = line[0]
        val = line[1:]
        if tag == "f":
            if curr_fd is not None:
                descriptors.append({"fd": curr_fd, "type": curr_type, "name": curr_name})
            curr_fd = val
            curr_type = ""
            curr_name = ""
        elif tag == "t":
            curr_type = val
        elif tag == "n":
            curr_name = val

    if curr_fd is not None:
        descriptors.append({"fd": curr_fd, "type": curr_type, "name": curr_name})

    # Count numeric file descriptors (POSIX fds 0, 1, 2, ...)
    numeric_fds = [d for d in descriptors if d["fd"].isdigit()]
    fd_count = len(numeric_fds)

    sockets: List[Dict[str, Any]] = []
    locks: List[Dict[str, Any]] = []

    for d in descriptors:
        name = d["name"]
        ftype = d["type"]
        fd = d["fd"]

        # 1. Socket Extraction (TCP / UDP)
        is_socket_type = ftype in ("IPv4", "IPv6", "inet", "inet6")
        has_net_addr = bool(re.search(r"(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost|\*|\[[0-9a-fA-F:]+\]):\d+", name))
        if ftype not in ("PIPE", "unix", "CHR", "REG", "DIR") and (is_socket_type or has_net_addr):
            sock_entry: Dict[str, Any] = {
                "fd": fd,
                "family": ftype if ftype in ("IPv4", "IPv6") else ("IPv6" if ":" in name and "[" in name else "IPv4"),
                "raw_name": name,
            }

            if "->" in name and ":" in name:
                # Established socket: local->remote
                local_part, remote_part = name.split("->", 1)
                sock_entry["status"] = "ESTABLISHED"
                sock_entry["local"] = local_part
                sock_entry["remote"] = remote_part

                if ":" in remote_part:
                    r_ip, r_port = remote_part.rsplit(":", 1)
                    sock_entry["remote_ip"] = r_ip
                    sock_entry["remote_port"] = int(r_port) if r_port.isdigit() else r_port
                else:
                    sock_entry["remote_ip"] = remote_part
                    sock_entry["remote_port"] = None

                if ":" in local_part:
                    l_ip, l_port = local_part.rsplit(":", 1)
                    sock_entry["local_ip"] = l_ip
                    sock_entry["local_port"] = int(l_port) if l_port.isdigit() else l_port
            else:
                # Listening or bound socket
                sock_entry["status"] = "LISTEN"
                sock_entry["local"] = name
                sock_entry["remote"] = None
                sock_entry["remote_ip"] = None
                sock_entry["remote_port"] = None

                if ":" in name:
                    l_ip, l_port = name.rsplit(":", 1)
                    # Strip trailing space or flag like '(LISTEN)'
                    l_port_clean = l_port.split()[0]
                    sock_entry["local_ip"] = l_ip
                    sock_entry["local_port"] = int(l_port_clean) if l_port_clean.isdigit() else l_port_clean

            sockets.append(sock_entry)

        # 2. Lock Detection
        # Detect: .lock, .git/index.lock, *.wal, flock
        lock_type = None
        lower_name = name.lower()

        if ".git/index.lock" in name or name.endswith("/index.lock") or name.endswith("index.lock"):
            lock_type = "git_index_lock"
        elif name.endswith(".lock") or ".lock" in name:
            lock_type = "file_lock"
        elif name.endswith(".wal") or "-wal" in name or ".wal" in name:
            lock_type = "sqlite_wal_lock"
        elif "flock" in lower_name or "flock" in ftype.lower():
            lock_type = "flock"

        if lock_type:
            locks.append({
                "fd": fd,
                "path": name,
                "lock_type": lock_type,
            })

    return {
        "fd_count": fd_count,
        "total_descriptors": len(descriptors),
        "sockets": sockets,
        "socket_count": len(sockets),
        "locks": locks,
        "has_locks": len(locks) > 0,
        "descriptors": descriptors,
    }


def get_process_descriptors_and_locks(pid: int) -> Dict[str, Any]:
    """
    Queries `lsof -a -p <PID> -Fn -Ft` to extract:
      - Open descriptor count
      - Established and listening sockets (remote IP, port)
      - Detected locks (.lock, .git/index.lock, *.wal, flock)
    """
    cmd = ["lsof", "-a", "-p", str(pid), "-Fn", "-Ft"]
    code, stdout, stderr = run_command(cmd)

    if code != 0 and not stdout.strip():
        return {
            "pid": pid,
            "fd_count": 0,
            "total_descriptors": 0,
            "sockets": [],
            "socket_count": 0,
            "locks": [],
            "has_locks": False,
            "descriptors": [],
            "error": stderr.strip() or f"Failed to run lsof for PID {pid}",
        }

    res = parse_lsof_descriptors(stdout)
    res["pid"] = pid
    return res


# ---------------------------------------------------------------------------
# System Daemon Diagnostics: WindowServer & mds_stores
# ---------------------------------------------------------------------------

def diagnose_windowserver() -> Dict[str, Any]:
    """
    WindowServer Diagnostic:
      - Inspects WindowServer process CPU% and memory%
      - Inspects Skylight / WindowServer unified logs or diagnostic reports
      - Analyzes top GUI consumers causing redraw/window load
    """
    # 1. Locate WindowServer PID and stats
    cmd_ps = ["ps", "-Aceo", "pid,pcpu,pmem,comm"]
    code, stdout, _ = run_command(cmd_ps)

    ws_pid = None
    ws_cpu = 0.0
    ws_mem = 0.0
    gui_consumers: List[Dict[str, Any]] = []

    if code == 0 and stdout:
        for line in stdout.strip().splitlines()[1:]:
            parts = line.strip().split(None, 3)
            if len(parts) < 4:
                continue
            try:
                pid = int(parts[0])
                pcpu = float(parts[1])
                pmem = float(parts[2])
                comm = parts[3]
            except ValueError:
                continue

            if "WindowServer" in comm:
                ws_pid = pid
                ws_cpu = pcpu
                ws_mem = pmem
            else:
                # Check if it's a GUI consumer (.app bundle or known app)
                app_name = annotate_app(comm)
                if app_name or ".app" in comm:
                    gui_consumers.append({
                        "pid": pid,
                        "comm": comm,
                        "app_name": app_name or os.path.basename(comm),
                        "cpu_percent": pcpu,
                        "mem_percent": pmem,
                    })

    # Sort GUI consumers by CPU utilization
    gui_consumers.sort(key=lambda x: x["cpu_percent"], reverse=True)
    top_gui_consumers = gui_consumers[:10]

    # 2. Inspect Skylight / WindowServer logs
    # Try /usr/bin/log show with brief window
    skylight_entries: List[str] = []
    log_available = False

    cmd_log = [
        "/usr/bin/log", "show",
        "--predicate", 'process == "WindowServer" || subsystem contains "com.apple.SkyLight"',
        "--last", "5m",
        "--style", "compact"
    ]
    code_log, out_log, _ = run_command(cmd_log, timeout=2.0)
    if code_log == 0 and out_log.strip():
        log_available = True
        for l in out_log.strip().splitlines()[-20:]:
            skylight_entries.append(l.strip())

    # Fallback to checking crash / diagnostic reports
    if not skylight_entries:
        report_dirs = [
            "/Library/Logs/DiagnosticReports",
            os.path.expanduser("~/Library/Logs/DiagnosticReports"),
        ]
        for r_dir in report_dirs:
            if os.path.exists(r_dir):
                try:
                    for f in os.listdir(r_dir):
                        if "WindowServer" in f or "SkyLight" in f:
                            skylight_entries.append(f"Diagnostic report found: {f}")
                            log_available = True
                except (PermissionError, OSError):
                    pass

    status = "HEALTHY"
    if ws_cpu > 70.0:
        status = "HIGH_LOAD"
    elif ws_pid is None:
        status = "UNKNOWN"

    return {
        "daemon": "WindowServer",
        "pid": ws_pid,
        "cpu_percent": ws_cpu,
        "mem_percent": ws_mem,
        "status": status,
        "skylight_logs": {
            "available": log_available,
            "entries": skylight_entries,
            "summary": f"{len(skylight_entries)} Skylight log entries inspected",
        },
        "top_gui_consumers": top_gui_consumers,
    }


def parse_mds_stores_paths(lsof_output: str) -> Dict[str, Any]:
    """
    Parses `lsof -c mds_stores -Fn` output.
    Detects active Spotlight indexing paths and identifies large developer dirs
    (node_modules, .git, target/, vendor/, Pods/, __pycache__, build/, dist/).
    """
    all_paths: List[str] = []
    for line in (lsof_output or "").splitlines():
        if line.startswith("n/"):
            all_paths.append(line[1:].strip())

    dev_patterns = [
        "node_modules",
        ".git",
        "target/",
        "target",
        "vendor",
        "Pods",
        "__pycache__",
        ".venv",
        "venv",
        "build",
        "dist",
    ]

    detected_developer_dirs: List[Dict[str, str]] = []
    seen_matched_dirs = set()

    for path in all_paths:
        for pat in dev_patterns:
            pat_boundary = f"/{pat}/" if not pat.endswith("/") else f"/{pat}"
            if pat_boundary in path or path.endswith(f"/{pat}") or f"/{pat}/" in path:
                # Extract the directory prefix up to the matched pattern
                idx = path.find(f"/{pat}")
                matched_dir = path[:idx + len(pat) + 1] if idx != -1 else path
                if matched_dir not in seen_matched_dirs:
                    seen_matched_dirs.add(matched_dir)
                    detected_developer_dirs.append({
                        "pattern": pat.rstrip("/"),
                        "path": path,
                        "matched_dir": matched_dir,
                    })

    thrashing = len(detected_developer_dirs) > 0
    status = "INDEXING_DEV_DIRS" if thrashing else "NORMAL"

    return {
        "indexing_paths": all_paths,
        "path_count": len(all_paths),
        "detected_developer_dirs": detected_developer_dirs,
        "thrashing_detected": thrashing,
        "status": status,
    }


def diagnose_mds_stores() -> Dict[str, Any]:
    """
    mds_stores Diagnostic:
      - Inspects mds_stores process CPU% and memory%
      - Inspects Spotlight indexing paths via `lsof -c mds_stores -Fn`
      - Detects thrashing in large developer dirs (node_modules, .git, target/)
    """
    # 1. Locate mds_stores process
    cmd_ps = ["ps", "-Aceo", "pid,pcpu,pmem,comm"]
    code_ps, stdout_ps, _ = run_command(cmd_ps)

    mds_pid = None
    mds_cpu = 0.0
    mds_mem = 0.0

    if code_ps == 0 and stdout_ps:
        for line in stdout_ps.strip().splitlines()[1:]:
            parts = line.strip().split(None, 3)
            if len(parts) >= 4 and "mds_stores" in parts[3]:
                try:
                    mds_pid = int(parts[0])
                    mds_cpu = float(parts[1])
                    mds_mem = float(parts[2])
                    break
                except ValueError:
                    pass

    # 2. Inspect indexing paths via lsof
    cmd_lsof = ["lsof", "-c", "mds_stores", "-Fn"]
    code_lsof, stdout_lsof, _ = run_command(cmd_lsof, timeout=3.0)

    # If mds_stores returns empty, also probe mdworker
    if not stdout_lsof.strip():
        cmd_worker = ["lsof", "-c", "mdworker", "-Fn"]
        _, stdout_worker, _ = run_command(cmd_worker, timeout=2.0)
        stdout_lsof = stdout_worker or ""

    parsed = parse_mds_stores_paths(stdout_lsof)
    if mds_pid is None:
        parsed["status"] = "NOT_RUNNING"

    return {
        "daemon": "mds_stores",
        "pid": mds_pid,
        "cpu_percent": mds_cpu,
        "mem_percent": mds_mem,
        "indexing_paths": parsed["indexing_paths"],
        "path_count": parsed["path_count"],
        "detected_developer_dirs": parsed["detected_developer_dirs"],
        "thrashing_detected": parsed["thrashing_detected"],
        "status": parsed["status"],
    }


# ---------------------------------------------------------------------------
# Comprehensive Process Doctor
# ---------------------------------------------------------------------------

def diagnose_process(pid: int) -> Dict[str, Any]:
    """
    Performs a comprehensive diagnostic evaluation of a process:
      1. Lineage tree resolution (up to launchd / kernel_task)
      2. Execution context (args, cwd, git repository & branch)
      3. Open descriptors, network sockets, and file locks
      4. SIP unprivileged thread sampling (Tiers A -> B -> C)
    """
    lineage_info = resolve_process_lineage(pid)
    execution_context = get_process_execution_context(pid)
    descriptors_info = get_process_descriptors_and_locks(pid)
    thread_sampling = sample_process(pid)

    return {
        "pid": pid,
        "lineage": lineage_info,
        "execution_context": execution_context,
        "descriptors": descriptors_info,
        "thread_sampling": thread_sampling,
        "timestamp": time.time(),
    }


if __name__ == "__main__":
    target_pid = int(sys.argv[1]) if len(sys.argv) > 1 else os.getpid()
    print(f"=== Diagnosing PID {target_pid} ===")
    res = diagnose_process(target_pid)
    print(json.dumps(res, indent=2))
