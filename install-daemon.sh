#!/usr/bin/env bash
# Install / Uninstall macOS user agent for mac-health-monitor

PLIST_NAME="com.user.macmonitor"
PLIST_PATH="$HOME/Library/LaunchAgents/${PLIST_NAME}.plist"
SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/monitor.py"

case "$1" in
  install)
    mkdir -p "$HOME/Library/LaunchAgents"
    cat <<EOF > "$PLIST_PATH"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${PLIST_NAME}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>-u</string>
        <string>${SCRIPT_PATH}</string>
        <string>--daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/tmp/macmonitor.err</string>
    <key>StandardOutPath</key>
    <string>/tmp/macmonitor.out</string>
</dict>
</plist>
EOF
    launchctl unload "$PLIST_PATH" 2>/dev/null || true
    launchctl load "$PLIST_PATH"
    echo "✅ Health monitor daemon installed and started as a background launch agent."
    echo "Logs are available at /tmp/macmonitor.out and /tmp/macmonitor.err"
    ;;
  uninstall)
    launchctl unload "$PLIST_PATH" 2>/dev/null || true
    rm -f "$PLIST_PATH"
    echo "🛑 Health monitor daemon uninstalled."
    ;;
  status)
    launchctl list | grep "$PLIST_NAME" || echo "Daemon is not currently active."
    ;;
  *)
    echo "Usage: $0 {install|uninstall|status}"
    exit 1
    ;;
esac
