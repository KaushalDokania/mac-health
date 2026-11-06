#!/usr/bin/env python3
"""
Synthetic Developer Scenario: File Lock & Bound Network Socket.
Binds a local TCP port (127.0.0.1) and holds an active file lock (.lock).

ADR-006: Strictly self-destructing with a 15-second hardware watchdog timer
(threading.Timer + signal.alarm fallback) to guarantee zero rogue process leakage.
"""

import os
import sys
import json
import time
import fcntl
import socket
import signal
import tempfile
import argparse
import threading

DEFAULT_WATCHDOG_SECONDS = 15.0

_OPEN_SOCKET = None
_LOCK_FILE_OBJ = None
_TEMP_DIR = None


def setup_watchdog(timeout: float = DEFAULT_WATCHDOG_SECONDS) -> threading.Timer:
    """Sets up a hardware watchdog timer and signal.alarm to guarantee self-destruction."""
    def _self_destruct():
        try:
            sys.stderr.write(f"[WATCHDOG] File lock scenario {os.getpid()} self-destructing after {timeout}s.\n")
            sys.stderr.flush()
        except Exception:
            pass
        _cleanup()
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


def _cleanup():
    global _OPEN_SOCKET, _LOCK_FILE_OBJ, _TEMP_DIR
    if _OPEN_SOCKET:
        try:
            _OPEN_SOCKET.close()
        except Exception:
            pass
        _OPEN_SOCKET = None

    if _LOCK_FILE_OBJ:
        try:
            fcntl.flock(_LOCK_FILE_OBJ.fileno(), fcntl.LOCK_UN)
            _LOCK_FILE_OBJ.close()
        except Exception:
            pass
        _LOCK_FILE_OBJ = None

    if _TEMP_DIR and os.path.exists(_TEMP_DIR):
        try:
            for root, dirs, files in os.walk(_TEMP_DIR, topdown=False):
                for name in files:
                    os.unlink(os.path.join(root, name))
                for name in dirs:
                    os.rmdir(os.path.join(root, name))
            os.rmdir(_TEMP_DIR)
        except Exception:
            pass
        _TEMP_DIR = None


def main():
    global _OPEN_SOCKET, _LOCK_FILE_OBJ, _TEMP_DIR

    parser = argparse.ArgumentParser(description="Synthetic File Lock & Socket Service")
    parser.add_argument("--port", type=int, default=0, help="Port to bind (0 for ephemeral)")
    parser.add_argument("--lock-name", type=str, default="service.lock", help="Name of lock file")
    parser.add_argument("--watchdog", type=float, default=DEFAULT_WATCHDOG_SECONDS, help="Watchdog timeout in seconds")
    args = parser.parse_args()

    # 1. Arm 15s self-destruct watchdog immediately
    watchdog = setup_watchdog(args.watchdog)

    stop_event = threading.Event()

    def _sig_handler(signum, frame):
        stop_event.set()
        _cleanup()
        os._exit(0)

    try:
        signal.signal(signal.SIGTERM, _sig_handler)
        signal.signal(signal.SIGINT, _sig_handler)
    except Exception:
        pass

    # 2. Bind local TCP listening socket
    _OPEN_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _OPEN_SOCKET.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _OPEN_SOCKET.bind(("127.0.0.1", args.port))
    _OPEN_SOCKET.listen(5)
    bound_port = _OPEN_SOCKET.getsockname()[1]

    # 3. Create temp directory and acquire active file lock
    _TEMP_DIR = tempfile.mkdtemp(prefix="mac_health_lock_")
    lock_file_path = os.path.join(_TEMP_DIR, args.lock_name)
    _LOCK_FILE_OBJ = open(lock_file_path, "w+")
    _LOCK_FILE_OBJ.write(f"pid={os.getpid()}\nport={bound_port}\n")
    _LOCK_FILE_OBJ.flush()
    fcntl.flock(_LOCK_FILE_OBJ.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    # 4. Notify readiness via stdout
    ready_msg = json.dumps({
        "scenario": "file_lock",
        "pid": os.getpid(),
        "port": bound_port,
        "lock_file": lock_file_path,
        "status": "locked",
        "watchdog_seconds": args.watchdog,
    })
    sys.stdout.write(ready_msg + "\n")
    sys.stdout.flush()

    # 5. Wait until watchdog triggers or termination signal received
    try:
        stop_event.wait(timeout=args.watchdog)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        _cleanup()


if __name__ == "__main__":
    main()
