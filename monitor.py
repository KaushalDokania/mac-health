#!/usr/bin/env python3
"""
mac-health: Universal Apple Silicon (M1/M2/M3/M4) Health & Workstation Monitor.
Clean, modern terminal layout immune to ANSI code and font-width misalignment.
Dynamically adapts thresholds and headers to your specific Mac (RAM, Cores, Chip).

Zero external dependencies — standard macOS Python 3.
"""

import os
import sys
import re
import time
import subprocess
from datetime import datetime

# Dynamic Hardware Detection
def run_cmd(cmd_list):
    try:
        return subprocess.check_output(cmd_list, stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
    except Exception:
        return ""

def get_system_specs():
    chip = run_cmd(['sysctl', '-n', 'machdep.cpu.brand_string']).strip() or "Apple Silicon"
    ncpu = int(run_cmd(['sysctl', '-n', 'hw.ncpu']).strip() or "10")
    total_ram_bytes = int(run_cmd(['sysctl', '-n', 'hw.memsize']).strip() or "17179869184")
    total_ram_gb = total_ram_bytes / (1024**3)
    return chip, ncpu, total_ram_gb

CHIP_NAME, NCPU, TOTAL_RAM_GB = get_system_specs()

# Adaptive Alert Thresholds (Zero-Noise Developer Policy)
# Scaled dynamically to your Mac's core count and RAM size
SWAP_WARN_MB = max(2048.0, TOTAL_RAM_GB * 1024 * 0.15)    # 15% of total RAM
SWAP_CRIT_MB = max(4096.0, TOTAL_RAM_GB * 1024 * 0.28)    # 28% of total RAM
LOAD_WARN = max(4.0, float(NCPU) * 0.85)                  # 85% utilization
SUSTAINED_LOAD_WARN = max(5.0, float(NCPU) * 1.0)         # 100% saturation for 15+ mins
POLL_INTERVAL_SEC = 120

COOLDOWN_FILE = "/tmp/macmonitor_cooldown.json"
COOLDOWN_DURATIONS = {
    "swap_crit": 1800,    # 30 mins
    "swap_warn": 1800,    # 30 mins
    "cpu_runaway": 3600,  # 1 hour
    "cpu_throttle": 1800, # 30 mins
    "batt_warn": 2700,    # 45 mins
}

def load_cooldowns():
    try:
        import json
        if os.path.exists(COOLDOWN_FILE):
            with open(COOLDOWN_FILE, 'r') as f:
                return json.load(f)
    except Exception:
        pass
    return {}

def save_cooldown(alert_key):
    try:
        import json
        data = load_cooldowns()
        data[alert_key] = time.time()
        with open(COOLDOWN_FILE, 'w') as f:
            json.dump(data, f)
    except Exception:
        pass

# ANSI Colors
IS_TTY = sys.stdout.isatty()

def c(text, code):
    if not IS_TTY:
        return text
    return f"\033[{code}m{text}\033[0m"

BOLD = "1"
DIM = "2"
RED = "31"
GREEN = "32"
YELLOW = "33"
BLUE = "34"
MAGENTA = "35"
CYAN = "36"
WHITE = "37"

def strip_ansi(s):
    return re.sub(r'\x1b\[[0-9;]*m', '', s)

def vlen(s):
    return len(strip_ansi(s))

def vpad(s, width, align="left"):
    curr_len = vlen(s)
    pad = max(0, width - curr_len)
    if align == "right":
        return (" " * pad) + s
    return s + (" " * pad)

def make_bar(percent, width=15, invert=False):
    percent = max(0.0, min(100.0, percent))
    filled = int(round(width * (percent / 100.0)))
    empty = width - filled
    bar = "█" * filled + "░" * empty
    
    if invert:
        color = GREEN if percent < 60 else (YELLOW if percent < 85 else RED)
    else:
        color = GREEN if percent > 50 else (YELLOW if percent > 25 else RED)
    return c(f"[{bar}]", color)

def get_memory_info():
    swap_raw = run_cmd(['sysctl', 'vm.swapusage'])
    used_match = re.search(r'used\s*=\s*([\d\.]+)M', swap_raw)
    total_match = re.search(r'total\s*=\s*([\d\.]+)M', swap_raw)
    swap_used_mb = float(used_match.group(1)) if used_match else 0.0
    swap_total_mb = float(total_match.group(1)) if total_match else 0.0

    mp_raw = run_cmd(['memory_pressure'])
    free_pct_match = re.search(r'System-wide memory free percentage:\s*(\d+)%', mp_raw)
    free_pct = int(free_pct_match.group(1)) if free_pct_match else 50

    page_size_match = re.search(r'page size of (\d+)', mp_raw)
    page_size = int(page_size_match.group(1)) if page_size_match else 16384

    wired_match = re.search(r'Pages wired down:\s*(\d+)', mp_raw)
    wired_gb = (int(wired_match.group(1)) * page_size) / (1024**3) if wired_match else 0.0

    avail_gb = (TOTAL_RAM_GB * free_pct) / 100.0

    return {
        "total_gb": TOTAL_RAM_GB,
        "avail_gb": avail_gb,
        "free_pct": free_pct,
        "wired_gb": wired_gb,
        "swap_used_mb": swap_used_mb,
        "swap_total_mb": swap_total_mb,
    }

def get_cpu_and_thermals():
    load_raw = run_cmd(['sysctl', '-n', 'vm.loadavg'])
    loads = load_raw.strip('{}\n ').split()
    load1 = float(loads[0]) if loads else 0.0
    load5 = float(loads[1]) if len(loads) > 1 else 0.0
    load15 = float(loads[2]) if len(loads) > 2 else 0.0

    uptime_raw = run_cmd(['uptime']).strip()
    up_match = re.search(r'up\s+([^,]+)', uptime_raw)
    up_str = up_match.group(1).strip() if up_match else "recent"

    therm_raw = run_cmd(['pmset', '-g', 'therm'])
    throttled = "CPU_Speed_Limit" in therm_raw and not "CPU_Speed_Limit = 100" in therm_raw

    return {
        "load1": load1,
        "load5": load5,
        "load15": load15,
        "uptime_str": up_str,
        "throttled": throttled,
    }

def get_battery_info():
    raw = run_cmd(['pmset', '-g', 'batt'])
    is_ac = "AC Power" in raw
    pct_match = re.search(r'(\d+)%', raw)
    pct = int(pct_match.group(1)) if pct_match else None
    
    prof = run_cmd(['system_profiler', 'SPPowerDataType'])
    cycle_match = re.search(r'Cycle Count:\s*(\d+)', prof)
    condition_match = re.search(r'Condition:\s*([^\n]+)', prof)
    capacity_match = re.search(r'Maximum Capacity:\s*(\d+)%', prof)
    
    return {
        "is_ac": is_ac,
        "percent": pct,
        "cycles": int(cycle_match.group(1)) if cycle_match else None,
        "condition": condition_match.group(1).strip() if condition_match else "Normal",
        "capacity": int(capacity_match.group(1)) if capacity_match else None,
    }

def get_disk_info():
    raw = run_cmd(['df', '-h', '/'])
    lines = raw.strip().split('\n')
    if len(lines) > 1:
        parts = lines[1].split()
        if len(parts) >= 5:
            return {
                "size": parts[1],
                "used": parts[2],
                "avail": parts[3],
                "pct_used": int(parts[4].replace('%', ''))
            }
    return {"size": "Unknown", "used": "0G", "avail": "0G", "pct_used": 0}

def get_top_processes():
    raw_mem = run_cmd(['ps', '-Aceo', 'pid,pmem,rss,comm'])
    mem_procs = []
    if raw_mem:
        lines = [line.strip() for line in raw_mem.split('\n')[1:] if line.strip()]
        parsed = []
        for line in lines:
            parts = line.split(None, 3)
            if len(parts) == 4:
                try:
                    pid, pmem, rss, comm = parts[0], parts[1], float(parts[2]), os.path.basename(parts[3])
                    parsed.append((rss, pid, pmem, comm))
                except Exception:
                    continue
        parsed.sort(key=lambda x: x[0], reverse=True)
        mem_procs = [(p[1], p[2], p[0]/1024, p[3]) for p in parsed[:5]]

    raw_cpu = run_cmd(['ps', '-Aceo', 'pid,pcpu,comm'])
    cpu_procs = []
    if raw_cpu:
        lines = [line.strip() for line in raw_cpu.split('\n')[1:] if line.strip()]
        parsed = []
        for line in lines:
            parts = line.split(None, 2)
            if len(parts) == 3:
                try:
                    pid, pcpu, comm = parts[0], float(parts[1]), os.path.basename(parts[2])
                    parsed.append((pcpu, pid, comm))
                except Exception:
                    continue
        parsed.sort(key=lambda x: x[0], reverse=True)
        cpu_procs = [(p[1], p[0], p[2]) for p in parsed[:5]]

    return mem_procs, cpu_procs

def get_developer_services():
    docker_running = False
    docker_out = run_cmd(['docker', 'info'])
    if "Server Version" in docker_out:
        docker_running = True
    
    ollama_running = False
    ollama_models = []
    # Query Ollama REST API directly. DO NOT invoke `ollama` CLI as Ollama CLI auto-launches Ollama.app on macOS!
    try:
        import urllib.request
        import json
        host = os.environ.get('OLLAMA_HOST', '127.0.0.1:11434')
        if not host.startswith(('http://', 'https://')):
            host = 'http://' + host
        req = urllib.request.Request(f"{host.rstrip('/')}/api/ps", headers={"User-Agent": "mac-health"})
        with urllib.request.urlopen(req, timeout=0.3) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode('utf-8'))
                ollama_running = True
                for model in data.get("models", []):
                    name = model.get("name")
                    if name:
                        ollama_models.append(name)
    except Exception:
        # Passively ignore: server is not active or port is closed — do not wake up Ollama
        ollama_running = False
        ollama_models = []

    return {
        "docker_active": docker_running,
        "ollama_active": ollama_running,
        "ollama_models": ollama_models
    }

def format_dashboard():
    mem = get_memory_info()
    cpu = get_cpu_and_thermals()
    batt = get_battery_info()
    disk = get_disk_info()
    dev = get_developer_services()
    mem_procs, cpu_procs = get_top_processes()

    swap_badge = c("CLEAN (0.0 MB)", GREEN) if mem['swap_used_mb'] == 0 else (
        c(f"HIGH ({mem['swap_used_mb']:.1f} MB)", YELLOW) if mem['swap_used_mb'] < SWAP_CRIT_MB else c(f"CRITICAL ({mem['swap_used_mb']:.1f} MB)", RED)
    )
    load_badge = c("OK", GREEN) if cpu['load1'] < LOAD_WARN else c("BUSY", YELLOW)
    therm_badge = c("Nominal (No throttling)", GREEN) if not cpu['throttled'] else c("THROTTLED", RED)
    power_src = c("AC Power (Connected)", GREEN) if batt['is_ac'] else c("Battery (Unplugged)", YELLOW)
    batt_cond = c("Healthy", GREEN) if batt['condition'] == "Normal" else c("Service Recommended", YELLOW)

    orb_status = c("Active (OrbStack)", GREEN) if dev['docker_active'] else c("Inactive / Idle", DIM)
    ollama_status = c(f"Active ({', '.join(dev['ollama_models']) or 'Loaded'})", GREEN) if dev['ollama_active'] else c("Idle (Unloaded)", DIM)

    L = []
    div = c("━" * 62, CYAN)
    subdiv = c("─" * 62, DIM)

    # Header
    L.append("")
    L.append(f" {c(f' {CHIP_NAME} ({NCPU} Cores, {TOTAL_RAM_GB:.0f}GB)', BOLD)} {c('•', DIM)} {datetime.now().strftime('%H:%M:%S')}")
    L.append(f" {div}")

    # Unified Memory
    avail_str = f"({mem['avail_gb']:.1f} GB free of {mem['total_gb']:.1f} GB)"
    L.append(f" {c('UNIFIED MEMORY (RAM)', BOLD)}")
    L.append(f"  • Available RAM : {mem['free_pct']}% {make_bar(mem['free_pct'], 16)} {c(avail_str, DIM)}")
    L.append(f"  • Wired Kernel  : {mem['wired_gb']:.2f} GB {c('(OS & hardware reserved)', DIM)}")
    L.append(f"  • Active Swap   : {swap_badge}")
    L.append("")

    # Storage & CPU
    load_sub = f"(5m: {cpu['load5']:.2f}, 15m: {cpu['load15']:.2f} | Uptime: {cpu['uptime_str']})"
    L.append(f" {c('SYSTEM & HARDWARE VITALS', BOLD)}")
    L.append(f"  • System Disk   : {disk['avail']} Free / {disk['size']} ({disk['pct_used']}% used) {make_bar(disk['pct_used'], 12, invert=True)}")
    L.append(f"  • CPU Load (1m) : {cpu['load1']:.2f} [{load_badge}] {c(load_sub, DIM)}")
    L.append(f"  • Thermal State : {therm_badge}")
    L.append(f"  • Power Source  : {power_src}")
    if batt['capacity']:
        L.append(f"  • Battery State : {batt['capacity']}% Max Capacity (Cycle {batt['cycles']}) [{batt_cond}]")
    L.append("")

    # Developer Runtimes
    L.append(f" {c('DEVELOPER RUNTIMES', BOLD)}")
    L.append(f"  • Container Engine (Docker) : {orb_status}")
    L.append(f"  • Local AI Engine (Ollama)  : {ollama_status}")

    # Top Processes
    if mem_procs or cpu_procs:
        L.append("")
        L.append(f" {subdiv}")
        L.append(f"  {c('TOP MEMORY PROCESSES', BOLD):<36} {c('TOP CPU CONSUMERS', BOLD)}")
        for i in range(max(len(mem_procs), len(cpu_procs))):
            col1 = f"  • {mem_procs[i][3][:16]:<16} {mem_procs[i][2]:>6.1f} MB" if i < len(mem_procs) else ""
            col2 = f"• {cpu_procs[i][2][:16]:<16} {cpu_procs[i][1]:>5.1f}%" if i < len(cpu_procs) else ""
            L.append(f"{vpad(col1, 35)} {col2}")

    L.append(f" {div}")
    L.append("")
    return "\n".join(L)

def send_notification(title, subtitle, message, alert_key):
    cooldowns = load_cooldowns()
    last = cooldowns.get(alert_key, 0)
    limit = COOLDOWN_DURATIONS.get(alert_key, 1800)
    
    if (time.time() - last) < limit:
        return
        
    save_cooldown(alert_key)
    script = f'display notification "{message}" with title "{title}" subtitle "{subtitle}"'
    subprocess.run(['osascript', '-e', script], stderr=subprocess.DEVNULL)

def check_and_alert():
    mem = get_memory_info()
    cpu = get_cpu_and_thermals()
    batt = get_battery_info()

    if mem["swap_used_mb"] >= SWAP_CRIT_MB:
        send_notification("Mac Memory Critical", f"Swap at {mem['swap_used_mb']:.0f} MB", "High risk of UI freeze. Check background apps.", "swap_crit")
    elif mem["swap_used_mb"] >= SWAP_WARN_MB:
        send_notification("Mac Memory Warning", f"Swap at {mem['swap_used_mb']:.0f} MB", "RAM full, swapping to SSD.", "swap_warn")

    if cpu["load15"] >= SUSTAINED_LOAD_WARN:
        send_notification("Mac CPU Runaway Process", f"15-Min Load: {cpu['load15']:.1f}", f"A task has pegged CPU continuously across all {NCPU} cores for over 15 minutes.", "cpu_runaway")
    elif cpu["throttled"]:
        send_notification("Mac Thermal Warning", "SoC Throttled", "Apple Silicon clock speed is being reduced due to heat.", "cpu_throttle")

    if not batt["is_ac"] and batt["condition"] != "Normal" and batt["percent"] and batt["percent"] < 30:
        send_notification("Mac Power Warning", f"Battery at {batt['percent']}% (Degraded)", "Plug into AC power to prevent CPU power throttling.", "batt_warn")

def main():
    args = sys.argv[1:]
    if "--daemon" in args or "-d" in args:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Watchdog daemon active for {CHIP_NAME} ({NCPU} Cores, {TOTAL_RAM_GB:.0f}GB)...", flush=True)
        while True:
            try:
                check_and_alert()
            except Exception as e:
                pass
            time.sleep(POLL_INTERVAL_SEC)
    elif "--watch" in args or "-w" in args:
        try:
            while True:
                print("\033[H\033[J", end="")
                print(format_dashboard())
                print(c(" [Press Ctrl+C to exit live watch]", DIM))
                time.sleep(2)
        except KeyboardInterrupt:
            print("\nExited live watch.")
    else:
        print(format_dashboard())
        check_and_alert()

if __name__ == '__main__':
    main()
