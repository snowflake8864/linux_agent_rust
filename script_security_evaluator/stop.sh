#!/bin/bash
# 停止 Security Evaluator 所有相关进程（不依赖 systemd / service）
set -e

PID_FILE=/var/run/security-evaluator.pid
MONITOR_PID_FILE=/var/run/security-evaluator-monitor.pid

echo "========================================"
echo "Stopping Security Evaluator..."
echo "========================================"

# 1. systemd 服务
HAS_SYSTEMD=false
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    if systemctl is-active security-evaluator.service >/dev/null 2>&1; then
        echo "→ Stopping systemd service..."
        systemctl stop security-evaluator.service 2>/dev/null && echo "  ✅ systemd service stopped" || echo "  ⚠️  systemd stop failed"
        HAS_SYSTEMD=true
    fi
fi

# 2. init.d 服务
if [ "$HAS_SYSTEMD" = false ] && command -v service >/dev/null 2>&1; then
    if [ -f /etc/init.d/security-evaluator ]; then
        echo "→ Stopping init.d service..."
        service security-evaluator stop 2>/dev/null && echo "  ✅ init.d service stopped" || echo "  ⚠️  init.d stop failed"
    fi
fi

# 3. monitor 进程
if [ -f "$MONITOR_PID_FILE" ]; then
    MONITOR_PID=$(cat "$MONITOR_PID_FILE" 2>/dev/null)
    if [ -n "$MONITOR_PID" ] && [ -d "/proc/$MONITOR_PID" ]; then
        echo "→ Stopping monitor (PID: $MONITOR_PID)..."
        kill -TERM -$MONITOR_PID 2>/dev/null || true
        sleep 1
        kill -9 -$MONITOR_PID 2>/dev/null || true
        kill -9 $MONITOR_PID 2>/dev/null || true
        rm -f "$MONITOR_PID_FILE"
        echo "  ✅ monitor stopped"
    else
        rm -f "$MONITOR_PID_FILE"
    fi
fi
pkill -9 -f "security-evaluator.monitor" 2>/dev/null || true

# 4. 主进程
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE" 2>/dev/null)
    if [ -n "$PID" ] && [ -d "/proc/$PID" ]; then
        echo "→ Stopping main process (PID: $PID)..."
        kill -15 $PID 2>/dev/null
        sleep 2
        if [ -d "/proc/$PID" ]; then
            kill -9 $PID 2>/dev/null || true
        fi
        echo "  ✅ main process stopped"
    fi
    rm -f "$PID_FILE"
fi

# 5. 兜底清理
REMAINING=$(pgrep -f "security-evaluator" 2>/dev/null || true)
if [ -n "$REMAINING" ]; then
    echo "→ Force cleaning remaining processes..."
    pkill -15 -f "security-evaluator" 2>/dev/null || true
    sleep 1
    pkill -9 -f "security-evaluator" 2>/dev/null || true
fi

sleep 1
FINAL=$(pgrep -f "security-evaluator" 2>/dev/null || true)
if [ -z "$FINAL" ]; then
    echo ""
    echo "✅ Security Evaluator 已全部停止"
else
    echo ""
    echo "⚠️ 仍有残留进程: $FINAL，请手动检查"
fi

rm -f "$PID_FILE" 2>/dev/null || true
rm -f "$MONITOR_PID_FILE" 2>/dev/null || true
