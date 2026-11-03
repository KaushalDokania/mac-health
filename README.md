# mac-health 

A lightweight, zero-dependency system health dashboard and background watchdog for Apple Silicon Macs (**M1, M2, M3, M4** / Pro / Max / Ultra).

Designed for software engineers, local AI builders, and power users who need to keep their Macs running smoothly without UI beachballs, swap thrashing, or thermal throttling.

```text
  Apple M1 Pro (10 Cores, 16GB) • 22:25:10
 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 UNIFIED MEMORY (RAM)
  • Available RAM : 72% [███████████░░░░░] (11.5 GB free of 16.0 GB)
  • Wired Kernel  : 2.11 GB (OS & hardware reserved)
  • Active Swap   : CLEAN (0.0 MB)

 SYSTEM & HARDWARE VITALS
  • System Disk   : 371Gi Free / 460Gi (4% used) [░░░░░░░░░░░░]
  • CPU Load (1m) : 2.45 [OK] (5m: 3.12, 15m: 3.40 | Uptime: 2:45)
  • Thermal State : Nominal (No throttling)
  • Power Source  : AC Power (Connected)
  • Battery State : 76% Max Capacity (Cycle 1081) [Service Recommended]

 DEVELOPER RUNTIMES
  • Container Engine (Docker) : Inactive / Idle
  • Local AI Engine (Ollama)  : Idle (Unloaded)

 ──────────────────────────────────────────────────────────────
  TOP MEMORY PROCESSES               TOP CPU CONSUMERS
  • Google Chrome Helper  412.3 MB   • Antigravity Helper 28.8%
  • Google Chrome Helper  398.1 MB   • language_server     4.1%
  • Antigravity           390.3 MB   • WindowServer        3.9%
 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## ✨ Features

- **Unified Memory & Swap Watchdog**: Monitors Apple Silicon's shared DRAM bus. Warns you *before* memory spills onto the NVMe SSD and causes UI freezing.
- **Hardware-Adaptive**: Automatically detects your Mac chip (M1, M2, M3, M4), physical core count, and RAM size, dynamically scaling thresholds.
- **Zero-Noise Developer Policy**: Ignores normal 30-second compilation bursts and model verifications. Only alerts on genuine 15+ minute infinite loops or active thermal throttling.
- **Silent Background LaunchAgent**: Runs quietly in the background via macOS `launchd` (< 5 MB RAM, 0.0% CPU) with automatic system boot integration.
- **Developer Runtime Aware**: Displays live status for container engines (OrbStack/Docker) and local AI runtimes (Ollama).
- **Zero Third-Party Dependencies**: Written in pure Python 3 using standard macOS system tools (`sysctl`, `pmset`, `df`, `ps`).

---

## 🚀 Quickstart (One-Line Install)

Clone and run the automated installer:

```bash
git clone https://github.com/<your-username>/mac-health.git
cd mac-health
./setup.sh
```

**What `setup.sh` does:**
1. Installs `mac-health` and `mh` binaries into `~/.local/bin/`.
2. Adds `mh` (dashboard) and `mhw` (live watch) aliases to `~/.zshrc`.
3. Registers the background watchdog LaunchAgent with `launchd`.
4. Runs your first health report.

---

## 🛠 Usage

```bash
# Instant snapshot dashboard
mh

# Live 2-second refreshing HUD (press Ctrl+C to exit)
mhw

# Run the multicore compute & dynamic memory ramp stress test
python3 stress-test.py

# Inspect top 15 memory and CPU processes
./identify-hogs.sh
```

---

## 📦 Repository Structure

```text
mac-health/
├── monitor.py          # Core universal dashboard & background watchdog engine
├── setup.sh            # Universal one-click installer for any Mac
├── install-daemon.sh   # Background launchd service manager (install/status/uninstall)
├── stress-test.py      # Multicore compute burst and memory allocation benchmark
├── identify-hogs.sh    # Fast terminal process inspector
├── .gitignore          # Clean macOS/Python ignore rules
├── LICENSE             # MIT License
└── README.md           # Documentation & quickstart
```

---

## 🛑 Uninstallation

To cleanly remove `mac-health` from your system:

```bash
cd mac-health
./install-daemon.sh uninstall
rm -f ~/.local/bin/mac-health ~/.local/bin/mh
```

---

## 📄 License

MIT License. Open source and free for personal and commercial use.
