#!/usr/bin/env python3
"""
Synthetic Developer Scenario: CPU Spinner.
Spawns worker threads spinning CPU intensive calculations.

ADR-006: Strictly self-destructing with a 15-second hardware watchdog timer
(threading.Timer + signal.alarm fallback) to guarantee zero rogue process leakage.
"""

import os
import sys
import json
import time
import signal
import argparse
import threading

DEFAULT_WATCHDOG_SECONDS = 15.0


def setup_watchdog(timeout: float = DEFAULT_WATCHDOG_SECONDS) -> threading.Timer:
    """Sets up a hardware watchdog timer and signal.alarm to guarantee self-destruction."""
    def _self_destruct():
        try:
            sys.stderr.write(f"[WATCHDOG] CPU spinner {os.getpid()} self-destructing after {timeout}s.\n")
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


def main():
    parser = argparse.ArgumentParser(description="Synthetic CPU Spinner")
    parser.add_argument("--threads", type=int, default=2, help="Number of worker threads spinning CPU")
    parser.add_argument("--watchdog", type=float, default=DEFAULT_WATCHDOG_SECONDS, help="Watchdog timeout in seconds")
    args = parser.parse_args()

    # 1. Arm 15s self-destruct watchdog immediately
    watchdog = setup_watchdog(args.watchdog)

    stop_event = threading.Event()

    def _sig_handler(signum, frame):
        stop_event.set()
        os._exit(0)

    try:
        signal.signal(signal.SIGTERM, _sig_handler)
        signal.signal(signal.SIGINT, _sig_handler)
    except Exception:
        pass

    # 2. Spawn worker threads spinning CPU
    def _spin():
        acc = 0
        while not stop_event.is_set():
            acc = (acc + 1) % 1000000
            _ = sum(i * i for i in range(200))

    worker_threads = []
    for _ in range(max(1, args.threads)):
        t = threading.Thread(target=_spin, daemon=True)
        t.start()
        worker_threads.append(t)

    # 3. Notify readiness via stdout
    ready_msg = json.dumps({
        "scenario": "cpu_spinner",
        "pid": os.getpid(),
        "threads": len(worker_threads),
        "status": "running",
        "watchdog_seconds": args.watchdog,
    })
    sys.stdout.write(ready_msg + "\n")
    sys.stdout.flush()

    # 4. Wait until watchdog triggers or termination signal received
    try:
        stop_event.wait(timeout=args.watchdog)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()


if __name__ == "__main__":
    main()
