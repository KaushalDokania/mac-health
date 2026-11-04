#!/usr/bin/env bash
# ==============================================================================
# mac-health Universal One-Click Setup Script
# Works on any Apple Silicon Mac (M1, M2, M3, M4, Pro/Max/Ultra)
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
BIN_DIR="$HOME/.local/bin"
ZSHRC="$HOME/.zshrc"
REPO_URL="https://github.com/KaushalDokania/mac-health.git"

echo "🚀 Installing mac-health on $(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m)..."

# If running via `curl ... | bash` or outside a git clone, clone/update to ~/.local/share/mac-health
if [ ! -f "$SCRIPT_DIR/monitor.py" ]; then
    INSTALL_DIR="$HOME/.local/share/mac-health"
    mkdir -p "$HOME/.local/share"
    if [ -d "$INSTALL_DIR/.git" ]; then
        echo "📦 Updating existing repository in $INSTALL_DIR..."
        git -C "$INSTALL_DIR" pull --ff-only || {
            echo "⚠️ Git pull failed. Re-cloning fresh..."
            rm -rf "$INSTALL_DIR"
            git clone "$REPO_URL" "$INSTALL_DIR"
        }
    else
        echo "📦 Cloning mac-health into $INSTALL_DIR..."
        git clone "$REPO_URL" "$INSTALL_DIR"
    fi
    SCRIPT_DIR="$INSTALL_DIR"
fi

# 1. Ensure ~/.local/bin exists
mkdir -p "$BIN_DIR"

# 2. Make scripts executable
chmod +x "$SCRIPT_DIR/monitor.py"
chmod +x "$SCRIPT_DIR/install-daemon.sh"
chmod +x "$SCRIPT_DIR/stress-test.py" 2>/dev/null || true
chmod +x "$SCRIPT_DIR/identify-hogs.sh" 2>/dev/null || true

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
echo "   • Type 'mh upgrade' anytime to update to the latest version."
echo "   • Background daemon is running silently in the background."
echo "=================================================================="
echo ""

# Run initial status
"$SCRIPT_DIR/monitor.py"
