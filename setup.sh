#!/usr/bin/env bash
# ==============================================================================
# mac-health Universal One-Click Setup Script
# Works on any Apple Silicon Mac (M1, M2, M3, M4, Pro/Max/Ultra)
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$HOME/.local/bin"
ZSHRC="$HOME/.zshrc"

echo "🚀 Installing mac-health on $(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m)..."

# 1. Ensure ~/.local/bin exists
mkdir -p "$BIN_DIR"

# 2. Make scripts executable
chmod +x "$SCRIPT_DIR/monitor.py"
chmod +x "$SCRIPT_DIR/install-daemon.sh"
chmod +x "$SCRIPT_DIR/stress-test.py" 2>/dev/null || true

# 3. Create symlinks in ~/.local/bin
ln -sf "$SCRIPT_DIR/monitor.py" "$BIN_DIR/mac-health"
ln -sf "$SCRIPT_DIR/monitor.py" "$BIN_DIR/mh"
echo "✅ Installed 'mac-health' and 'mh' commands to $BIN_DIR"

# 4. Configure ~/.zshrc PATH and Aliases
touch "$ZSHRC"
if ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' "$ZSHRC" && ! grep -q 'export PATH="\$HOME/.local/bin:\$PATH"' "$ZSHRC"; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$ZSHRC"
    echo "✅ Added ~/.local/bin to PATH in ~/.zshrc"
fi

if ! grep -q 'alias mh="mac-health"' "$ZSHRC"; then
    cat << 'EOF' >> "$ZSHRC"

# mac-health CLI Aliases
alias mh="mac-health"
alias mhw="mac-health --watch"
alias health="mac-health"
EOF
    echo "✅ Added 'mh', 'mhw', and 'health' aliases to ~/.zshrc"
fi

# 5. Install the background watchdog daemon (launchd)
echo "📦 Setting up background health watchdog LaunchAgent..."
"$SCRIPT_DIR/install-daemon.sh" install

echo ""
echo "=================================================================="
echo "🎉 Setup Complete! Your Mac is now monitored."
echo "   • Type 'mh' in any new terminal to view your health dashboard."
echo "   • Type 'mhw' for live 2-second real-time watch mode."
echo "   • Background daemon is running silently in the background."
echo "=================================================================="
echo ""

# Run initial status
"$SCRIPT_DIR/monitor.py"
