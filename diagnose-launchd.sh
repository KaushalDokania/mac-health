#!/usr/bin/env bash
echo "============================================================"
echo "          SERVICES CRASHING OR IN RESTART LOOPS             "
echo "============================================================"
echo "Checking launchctl for failing services (exit code != 0)..."
launchctl list 2>/dev/null | awk '$2 != "0" && $2 != "-" {print $0}'

echo ""
echo "============================================================"
echo "          FULL COMMAND PATHS OF ACTIVE PROCESSES            "
echo "============================================================"
for pid in 1772 65007 28934 65850 65348 3064; do
  if ps -p $pid > /dev/null 2>&1; then
    printf "PID %-7s: " "$pid"
    ps -p $pid -o command=
  fi
done
echo "============================================================"
