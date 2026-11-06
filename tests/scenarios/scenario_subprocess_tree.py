#!/usr/bin/env python3
"""
Synthetic Developer Scenario: 3-Level Subprocess Hierarchy.
Spawns Grandparent -> Parent -> Child hierarchy to test tree termination.

ADR-006: Every process in the hierarchy strictly enforces a 15-second hardware
watchdog timer (threading.Timer + signal.alarm fallback) to guarantee zero
rogue process leakage even if parent/grandparent processes exit unexpectedly.
"""

import os
import sys
import json
import time
import signal
import argparse
import threading
import subprocess

DEFAULT_WATCHDOG_SECONDS = 15.0


def setup_watchdog(timeout: float = DEFAULT_WATCHDOG_SECONDS, role: str = "process") -> threading.Timer:
    """Sets up a hardware watchdog timer and signal.alarm to guarantee self-destruction."""
    def _self_destruct():
        try:
            sys.stderr.write(f"[WATCHDOG] Subprocess tree {role} (PID {os.getpid()}) self-destructing after {timeout}s.\n")
            sys.stderr.flush()
        except Exception:
            pass
        os._exit(0)

    timer = threading.Timer(timeout, _self_destruct)
    timer.daemon = True
    timer.start()

    if hasattr(signal, "alarm"):
        try:
            signal.signal(signal.SIGALRM, lambda s, f: os._exit(0))
            signal.alarm(max(1, int(timeout)))
        except Exception:
            pass

    return timer


def run_child(watchdog_sec: float):
    """Child process (leaf node)."""
    setup_watchdog(watchdog_sec, role="child")

    def _sig_handler(signum, frame):
        os._exit(0)

    try:
        signal.signal(signal.SIGTERM, _sig_handler)
        signal.signal(signal.SIGINT, _sig_handler)
    except Exception:
        pass

    ready_msg = json.dumps({
        "scenario": "subprocess_tree",
        "level": "child",
        "pid": os.getpid(),
    })
    sys.stdout.write(ready_msg + "\n")
    sys.stdout.flush()

    initial_ppid = os.getppid()
    while True:
        if os.getppid() != initial_ppid or os.getppid() == 1:
            os._exit(0)
        time.sleep(0.05)


def run_parent(watchdog_sec: float):
    """Parent process (middle node). Spawns Child."""
    setup_watchdog(watchdog_sec, role="parent")

    child_proc = subprocess.Popen(
        [sys.executable, os.path.abspath(__file__), "--level", "child", "--watchdog", str(watchdog_sec)],
        stdout=subprocess.PIPE,
        text=True,
    )

    child_pid = None
    line = child_proc.stdout.readline()
    if line.strip():
        try:
            data = json.loads(line.strip())
            child_pid = data.get("pid")
        except Exception:
            pass
    if child_pid is None:
        child_pid = child_proc.pid

    def _sig_handler(signum, frame):
        try:
            child_proc.kill()
        except Exception:
            pass
        os._exit(0)

    try:
        signal.signal(signal.SIGTERM, _sig_handler)
        signal.signal(signal.SIGINT, _sig_handler)
    except Exception:
        pass

    ready_msg = json.dumps({
        "scenario": "subprocess_tree",
        "level": "parent",
        "pid": os.getpid(),
        "child_pid": child_pid,
    })
    sys.stdout.write(ready_msg + "\n")
    sys.stdout.flush()

    initial_ppid = os.getppid()
    while True:
        if os.getppid() != initial_ppid or os.getppid() == 1:
            os._exit(0)
        time.sleep(0.05)


def run_grandparent(watchdog_sec: float):
    """Grandparent process (root node). Spawns Parent."""
    setup_watchdog(watchdog_sec, role="grandparent")

    parent_proc = subprocess.Popen(
        [sys.executable, os.path.abspath(__file__), "--level", "parent", "--watchdog", str(watchdog_sec)],
        stdout=subprocess.PIPE,
        text=True,
    )

    parent_pid = None
    child_pid = None
    line = parent_proc.stdout.readline()
    if line.strip():
        try:
            data = json.loads(line.strip())
            parent_pid = data.get("pid")
            child_pid = data.get("child_pid")
        except Exception:
            pass
    if parent_pid is None:
        parent_pid = parent_proc.pid

    def _sig_handler(signum, frame):
        try:
            parent_proc.kill()
        except Exception:
            pass
        os._exit(0)

    try:
        signal.signal(signal.SIGTERM, _sig_handler)
        signal.signal(signal.SIGINT, _sig_handler)
    except Exception:
        pass

    ready_msg = json.dumps({
        "scenario": "subprocess_tree",
        "level": "grandparent",
        "pid": os.getpid(),
        "grandparent_pid": os.getpid(),
        "parent_pid": parent_pid,
        "child_pid": child_pid,
        "status": "running",
        "watchdog_seconds": watchdog_sec,
    })
    sys.stdout.write(ready_msg + "\n")
    sys.stdout.flush()

    initial_ppid = os.getppid()
    while True:
        if os.getppid() != initial_ppid or os.getppid() == 1:
            os._exit(0)
        time.sleep(0.05)


def main():
    parser = argparse.ArgumentParser(description="Synthetic Subprocess Tree Hierarchy")
    parser.add_argument(
        "--level",
        type=str,
        choices=["grandparent", "parent", "child"],
        default="grandparent",
        help="Process role in the 3-level tree hierarchy",
    )
    parser.add_argument("--watchdog", type=float, default=DEFAULT_WATCHDOG_SECONDS, help="Watchdog timeout in seconds")
    args = parser.parse_args()

    if args.level == "grandparent":
        run_grandparent(args.watchdog)
    elif args.level == "parent":
        run_parent(args.watchdog)
    elif args.level == "child":
        run_child(args.watchdog)


if __name__ == "__main__":
    main()
