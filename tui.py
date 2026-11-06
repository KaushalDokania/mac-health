#!/usr/bin/env python3
"""
mac-health v2.0 - Zero-Dependency Single-Key TUI Engine.
Zero external dependencies — standard macOS Python 3.

Features:
- Instant single-keystroke input via termios/tty raw mode.
- Bulletproof terminal cleanup guaranteeing restoration of terminal modes
  under all exit scenarios (including Ctrl+C / KeyboardInterrupt).
- Full ANSI sequence decoding (Arrow keys, Space, Enter, Escape).
- Interactive process triage interface with real-time remediation hotkeys.
"""

import os
import sys
import tty
import termios
import select
import signal
from typing import Optional, List, Dict, Any, Tuple

from safety import is_action_permitted, SYSTEM_WHITELIST
from remediation import (
    tame_process_to_ecores,
    freeze_process,
    unfreeze_process,
    terminate_process_tree,
    unload_ollama_model,
    get_triage_candidates,
    get_frozen_processes,
    is_managed_by_launchd,
)

# Terminal Styling & Colors
IS_TTY = sys.stdout.isatty()

def c(text: str, code: str) -> str:
    if not IS_TTY:
        return text
    return f"\033[{code}m{text}\033[0m"

BOLD = "1"
DIM = "2"
ITALIC = "3"
UNDERLINE = "4"
RED = "31"
GREEN = "32"
YELLOW = "33"
BLUE = "34"
MAGENTA = "35"
CYAN = "36"
WHITE = "37"
GRAY = "90"
BG_BLUE = "44"
BG_RED = "41"
BG_GRAY = "100"

def clear_screen() -> str:
    return "\033[2J\033[H" if IS_TTY else "\n"

def hide_cursor() -> None:
    if IS_TTY:
        sys.stdout.write("\033[?25l")
        sys.stdout.flush()

def show_cursor() -> None:
    if IS_TTY:
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()

def get_terminal_size() -> Tuple[int, int]:
    try:
        size = os.get_terminal_size()
        return size.columns, size.lines
    except Exception:
        return 80, 24


# ==============================================================================
# Single-Key Input Engine (termios / tty)
# ==============================================================================

def decode_ansi_sequence(fd: int) -> str:
    """
    Decodes multibyte ANSI escape sequences into human-readable key names.
    Supports arrows, home, end, page up, page down, and raw escape.
    Handles whether the leading escape byte (\x1b) was already consumed or not.
    """
    rlist, _, _ = select.select([fd], [], [], 0.05)
    if not rlist:
        return "Escape"

    seq1 = os.read(fd, 1).decode("latin1", errors="ignore")
    # If the leading escape character was passed into fd, consume it and read next
    if seq1 == "\x1b":
        rlist2, _, _ = select.select([fd], [], [], 0.05)
        if not rlist2:
            return "Escape"
        seq1 = os.read(fd, 1).decode("latin1", errors="ignore")

    if seq1 == "[":
        rlist2, _, _ = select.select([fd], [], [], 0.05)
        if not rlist2:
            return "Escape"
        seq2 = os.read(fd, 1).decode("latin1", errors="ignore")
        if seq2 == "A":
            return "Up"
        elif seq2 == "B":
            return "Down"
        elif seq2 == "C":
            return "Right"
        elif seq2 == "D":
            return "Left"
        elif seq2 == "H":
            return "Home"
        elif seq2 == "F":
            return "End"
        elif seq2 in ("5", "6"):
            # PageUp (\x1b[5~) / PageDown (\x1b[6~)
            select.select([fd], [], [], 0.02)
            try:
                os.read(fd, 1)  # consume trailing ~
            except Exception:
                pass
            return "PageUp" if seq2 == "5" else "PageDown"
        return f"Escape[{seq2}"
    elif seq1 == "O":  # SS3 application cursor
        rlist2, _, _ = select.select([fd], [], [], 0.05)
        if not rlist2:
            return "Escape"
        seq2 = os.read(fd, 1).decode("latin1", errors="ignore")
        mapping = {"A": "Up", "B": "Down", "C": "Right", "D": "Left"}
        return mapping.get(seq2, f"EscapeO{seq2}")

    return "Escape"


def get_single_keystroke(raise_ctrl_c: bool = False) -> str:
    """
    Reads a single keypress from standard input without requiring Enter.
    Safely handles raw terminal mode via termios.tcgetattr and guarantees
    restoration via a strict `finally: termios.tcsetattr` block.

    Supports:
        - Arrow keys: 'Up', 'Down', 'Left', 'Right'
        - Action keys: 'Enter', 'Space', 'Escape', 'Backspace', 'Tab'
        - 'Ctrl+C' (gracefully returns 'Ctrl+C' or raises KeyboardInterrupt)
        - Normal characters ('q', 't', '1', etc.)
    """
    if not sys.stdin.isatty():
        # Non-interactive / pipe / test fallback
        ch = sys.stdin.read(1)
        if not ch:
            return ""
        if ch in ("\r", "\n"):
            return "Enter"
        if ch == " ":
            return "Space"
        if ch == "\x03":
            if raise_ctrl_c:
                raise KeyboardInterrupt
            return "Ctrl+C"
        return ch

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch_bytes = os.read(fd, 1)
        if not ch_bytes:
            return ""
        ch = ch_bytes.decode("latin1", errors="ignore")

        if ch == "\x03":  # Ctrl+C
            if raise_ctrl_c:
                raise KeyboardInterrupt
            return "Ctrl+C"
        elif ch == "\x04":  # Ctrl+D
            return "Ctrl+D"
        elif ch in ("\r", "\n"):
            return "Enter"
        elif ch == " ":
            return "Space"
        elif ch in ("\x7f", "\x08"):
            return "Backspace"
        elif ch == "\t":
            return "Tab"
        elif ch == "\x1b":
            return decode_ansi_sequence(fd)
        return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


# ==============================================================================
# UI Formatting & Triage Table Rendering
# ==============================================================================

def format_process_row(
    proc: Dict[str, Any],
    is_selected: bool,
    is_frozen: bool,
    width: int,
) -> str:
    """Renders a single process row for the interactive triage table."""
    pid = str(proc["pid"]).rjust(6)
    cpu = f"{proc['cpu_pct']:.1f}%".rjust(6)
    ram = f"{proc['ram_gb']:.2f} GB".rjust(8)
    score = f"{proc['composite']:.1f}".rjust(6)

    # Launchd shield indicator
    is_launchd, _ = is_managed_by_launchd(proc["pid"])
    launchd_tag = " [launchd]" if is_launchd else "          "

    # Status indicator
    if is_frozen:
        status_tag = c(" [FROZEN] ", f"{WHITE};{BG_BLUE};{BOLD}")
    elif proc["is_protected"]:
        status_tag = c(" [SHIELD] ", f"{WHITE};{BG_RED};{BOLD}")
    else:
        status_tag = "          "

    # Command basename
    comm = proc["base_comm"][:24].ljust(24)

    row_content = f"{pid} │ {cpu} │ {ram} │ {score} │ {comm} │{launchd_tag}│{status_tag}"

    if is_selected:
        return c(f" ▶ {row_content}", f"{BOLD};{YELLOW}")
    return f"   {row_content}"


def render_triage_view(
    candidates: List[Dict[str, Any]],
    selected_index: int,
    sort_by: str,
    status_message: str = "",
) -> str:
    """Renders full triage dashboard view."""
    width, _ = get_terminal_size()
    border = "─" * min(width - 2, 84)

    lines = []
    lines.append(clear_screen().rstrip())
    lines.append(c("🍎 mac-health v2.0 ── Runaway Process Triage & Remediation Engine", f"{BOLD};{CYAN}"))
    lines.append(c(f"Active Sort: {sort_by.upper()} (Composite = CPU% + 3.0×RAM) │ Press 'h' for Help", DIM))
    lines.append(border)
    lines.append(c("    PID   │  %CPU  │   RAM    │ SCORE  │ PROCESS                  │ LAUNCHD  │ STATUS", BOLD))
    lines.append(border)

    frozen_dict = get_frozen_processes()

    if not candidates:
        lines.append(c("   No runaway candidate processes detected. System healthy.", GREEN))
    else:
        # Display up to 12 rows
        max_rows = 12
        start_row = max(0, min(selected_index - 5, len(candidates) - max_rows))
        visible = candidates[start_row : start_row + max_rows]

        for i, proc in enumerate(visible):
            idx = start_row + i
            is_frozen = str(proc["pid"]) in frozen_dict
            lines.append(format_process_row(proc, idx == selected_index, is_frozen, width))

    lines.append(border)

    # Hotkeys action menu
    lines.append(
        c("[1/T]", BOLD) + " Tame (E-Core)  " +
        c("[2/F]", BOLD) + " Freeze  " +
        c("[3/U]", BOLD) + " Unfreeze  " +
        c("[4/K]", BOLD) + " Kill Tree  " +
        c("[5/O]", BOLD) + " Unload Ollama"
    )
    lines.append(
        c("[S]", BOLD) + " Toggle Sort   " +
        c("[R]", BOLD) + " Refresh  " +
        c("[↑/↓]", BOLD) + " Navigate  " +
        c("[Q/ESC]", BOLD) + " Quit"
    )

    if status_message:
        lines.append(border)
        lines.append(status_message)

    return "\n".join(lines)


# ==============================================================================
# Interactive Control Loop
# ==============================================================================

def run_triage_tui() -> None:
    """
    Main interactive TUI loop.
    Guarantees clean cursor and terminal state upon exit.
    """
    sort_modes = ["composite", "cpu", "memory"]
    sort_idx = 0
    selected_idx = 0
    status_msg = ""

    hide_cursor()
    try:
        while True:
            sort_by = sort_modes[sort_idx]
            candidates = get_triage_candidates(sort_by=sort_by, limit=20)
            if candidates:
                selected_idx = max(0, min(selected_idx, len(candidates) - 1))
            else:
                selected_idx = 0

            view = render_triage_view(candidates, selected_idx, sort_by, status_msg)
            sys.stdout.write(view + "\n")
            sys.stdout.flush()

            # Wait for single keypress
            key = get_single_keystroke()
            status_msg = ""  # Clear message on next key

            if key in ("q", "Q", "Escape", "Ctrl+C", "Ctrl+D"):
                break
            elif key == "Up":
                selected_idx = max(0, selected_idx - 1)
            elif key == "Down":
                if candidates:
                    selected_idx = min(len(candidates) - 1, selected_idx + 1)
            elif key in ("s", "S"):
                sort_idx = (sort_idx + 1) % len(sort_modes)
                status_msg = c(f"ℹ️ Sort mode switched to: {sort_modes[sort_idx].upper()}", CYAN)
            elif key in ("r", "R"):
                status_msg = c("🔄 Process list refreshed.", GREEN)
            elif key in ("1", "t", "T"):
                if candidates:
                    target = candidates[selected_idx]
                    status_msg = _handle_tame(target)
            elif key in ("2", "f", "F"):
                if candidates:
                    target = candidates[selected_idx]
                    status_msg = _handle_freeze(target)
            elif key in ("3", "u", "U"):
                if candidates:
                    target = candidates[selected_idx]
                    status_msg = _handle_unfreeze(target)
            elif key in ("4", "k", "K"):
                if candidates:
                    target = candidates[selected_idx]
                    status_msg = _handle_kill(target)
            elif key in ("5", "o", "O"):
                status_msg = _handle_ollama()
    finally:
        show_cursor()
        if IS_TTY:
            sys.stdout.write("\n" + c("Exited mac-health Triage.", DIM) + "\n")


def _handle_tame(target: Dict[str, Any]) -> str:
    pid = target["pid"]
    comm = target["base_comm"]
    permitted, reason = is_action_permitted(pid, comm)
    if not permitted:
        return c(f"🛡️ SAFETY SHIELD BLOCKED: {reason}", RED)

    success = tame_process_to_ecores(pid)
    if success:
        return c(f"⚡ PID {pid} ({comm}) tamed to Apple Silicon Efficiency cores.", GREEN)
    return c(f"⚠️ Failed to tame PID {pid} ({comm}). Check privileges.", YELLOW)


def _handle_freeze(target: Dict[str, Any]) -> str:
    pid = target["pid"]
    comm = target["base_comm"]
    permitted, reason = is_action_permitted(pid, comm)
    if not permitted:
        return c(f"🛡️ SAFETY SHIELD BLOCKED: {reason}", RED)

    ok, msg = freeze_process(pid, auto_resume_seconds=300.0)
    if ok:
        return c(f"❄️ {msg} (Safety auto-resume: 5 min)", BLUE)
    return c(f"⚠️ {msg}", YELLOW)


def _handle_unfreeze(target: Dict[str, Any]) -> str:
    pid = target["pid"]
    comm = target["base_comm"]
    ok = unfreeze_process(pid)
    if ok:
        return c(f"☀️ Resumed PID {pid} ({comm}) via SIGCONT.", GREEN)
    return c(f"⚠️ Failed to resume PID {pid} ({comm}).", YELLOW)


def _handle_kill(target: Dict[str, Any]) -> str:
    pid = target["pid"]
    comm = target["base_comm"]
    permitted, reason = is_action_permitted(pid, comm)
    if not permitted:
        return c(f"🛡️ SAFETY SHIELD BLOCKED: {reason}", RED)

    ok = terminate_process_tree(pid, force=False)
    if ok:
        return c(f"💀 Successfully terminated PID {pid} ({comm}) tree.", GREEN)
    return c(f"⚠️ Failed to terminate PID {pid} ({comm}).", RED)


def _handle_ollama() -> str:
    # Attempt to unload common models or default
    models = ["llama3", "llama3.1", "qwen2.5-coder", "deepseek-r1", "mistral"]
    unloaded = []
    for m in models:
        if unload_ollama_model(m):
            unloaded.append(m)
    if unloaded:
        return c(f"🧠 Evicted Ollama models ({', '.join(unloaded)}) to free unified memory.", GREEN)
    return c("ℹ️ No active Ollama models responding or already evicted.", YELLOW)


if __name__ == "__main__":
    try:
        run_triage_tui()
    except KeyboardInterrupt:
        show_cursor()
        sys.exit(0)
