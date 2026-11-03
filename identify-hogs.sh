#!/usr/bin/env bash
# Lists the top 15 memory and top 10 CPU consumers on macOS
echo "============================================================"
echo "          TOP 15 PROCESSES BY MEMORY USAGE (RAM)            "
echo "============================================================"
printf "%-8s %-8s %-12s %s\n" "PID" "%MEM" "RSS (MB)" "COMMAND"
ps -Aceo pid,pmem,rss,comm 2>/dev/null | sort -k3 -nr | head -n 16 | tail -n 15 | awk '{printf "%-8s %-8s %-12.1f %s\n", $1, $2, $3/1024, $4}'

echo ""
echo "============================================================"
echo "          TOP 10 PROCESSES BY CPU CONSUMPTION              "
echo "============================================================"
printf "%-8s %-8s %s\n" "PID" "%CPU" "COMMAND"
ps -Aceo pid,pcpu,comm 2>/dev/null | sort -k2 -nr | head -n 11 | tail -n 10
echo "============================================================"
