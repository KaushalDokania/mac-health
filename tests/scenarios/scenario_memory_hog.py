#!/usr/bin/env python3
"""
Synthetic Developer Scenario: Memory Hog.
Allocates a sizable memory payload (default 500MB) to simulate memory pressure.

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
_MEMORY_CHUNKS = []


def setup_watchdog(timeout: float = DEFAULT_WATCHDOG_SECONDS) -> threading.Timer:
    """Sets up a hardware watchdog timer and signal.alarm to guarantee self-destruction."""
    def _self_destruct():
        try:
            sys.stderr.write(f"[WATCHDOG] Memory hog {os.getpid()} self-destructing after {timeout}s.\n")
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
    parser = argparse.ArgumentParser(description="Synthetic Memory Hog")
    parser.add_argument("--mb", type=int, default=500, help="Target memory allocation in megabytes (MB)")
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

    # 2. Allocate memory payload and touch pages to inflate RSS
    chunk_size = 10 * 1024 * 1024  # 10 MB per chunk
    num_chunks = max(1, args.mb // 10)
    for _ in range(num_chunks):
        # Fill bytearray to force OS page allocation
        chunk = bytearray(b"\xbb" * chunk_size)
        _MEMORY_CHUNKS.append(chunk)

    # 3. Notify readiness via stdout
    ready_msg = json.dumps({
        "scenario": "memory_hog",
        "pid": os.getpid(),
        "allocated_mb": args.mb,
        "chunk_count": len(_MEMORY_CHUNKS),
        "status": "allocated",
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
