#!/bin/bash
set -e

echo "Start packaging security-evaluator..."

VERSION="1.0.0_B1"
OUTPUT_DIR="output_security_evaluator"
INSTALLER_NAME="${OUTPUT_DIR}/security-evaluator-installer-${VERSION}.sh"

# ====== 1. Clean and create dirs ======
rm -rf package_security_evaluator "$OUTPUT_DIR"
mkdir -p package_security_evaluator/opt/osec/{x86_64-unknown-linux-musl,aarch64-unknown-linux-musl}
mkdir -p package_security_evaluator/opt/osec/log
mkdir -p "$OUTPUT_DIR"

# ====== 2. Copy binaries ======
echo "Copying binaries..."

if [ -f target/x86_64-unknown-linux-musl/release/security-evaluator ]; then
    cp target/x86_64-unknown-linux-musl/release/security-evaluator package_security_evaluator/opt/osec/x86_64-unknown-linux-musl/
    echo "✅ Copied x86_64 binary"
else
    echo "⚠️  x86_64 binary not found, skipping"
fi

if [ -f target/aarch64-unknown-linux-musl/release/security-evaluator ]; then
    cp target/aarch64-unknown-linux-musl/release/security-evaluator package_security_evaluator/opt/osec/aarch64-unknown-linux-musl/
    echo "✅ Copied aarch64 binary"
else
    echo "⚠️  aarch64 binary not found, skipping"
fi

# ====== 3. Copy configuration files ======
echo "Copying configuration files..."

cp -f script_security_evaluator/guardian_audit.conf package_security_evaluator/opt/osec/
cp -f script_security_evaluator/guardian_audit.ini package_security_evaluator/opt/osec/

# ====== 4. Copy service files ======
echo "Copying service files..."

cp -f script_security_evaluator/security-evaluator.service package_security_evaluator/opt/osec/
cp -f script_security_evaluator/security-evaluator.init package_security_evaluator/opt/osec/
chmod +x package_security_evaluator/opt/osec/security-evaluator.init
cp -f script_security_evaluator/security-evaluator.monitor package_security_evaluator/opt/osec/
chmod +x package_security_evaluator/opt/osec/security-evaluator.monitor
cp -f script_security_evaluator/stop.sh package_security_evaluator/
chmod +x package_security_evaluator/stop.sh

# ====== 5. Generate install script ======
cat > "package_security_evaluator/install.sh" << 'INSTALLEOF'
#!/bin/bash
set -e

echo "========================================"
echo "Installing Security Evaluator"
echo "========================================"

ARCH=$(uname -m)
case $ARCH in
    x86_64)   ARCH_DIR="x86_64-unknown-linux-musl" ;;
    aarch64|arm64) ARCH_DIR="aarch64-unknown-linux-musl" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

echo "Architecture: $ARCH ($ARCH_DIR)"

echo "Creating directories..."
mkdir -p /opt/osec/log
mkdir -p /opt/osec/log/backupdir

echo "Installing binary..."
cp -f opt/osec/$ARCH_DIR/security-evaluator /opt/osec/security-evaluator
chmod +x /opt/osec/security-evaluator

echo "Installing configuration..."
if [ ! -f /opt/osec/guardian_audit.conf ]; then
    cp -f opt/osec/guardian_audit.conf /opt/osec/guardian_audit.conf
    echo "  - Created guardian_audit.conf (log config)"
else
    echo "  - guardian_audit.conf already exists, skipping"
fi

if [ ! -f /opt/osec/guardian_audit.ini ]; then
    cp -f opt/osec/guardian_audit.ini /opt/osec/guardian_audit.ini
    echo "  - Created guardian_audit.ini (business config)"
else
    echo "  - guardian_audit.ini already exists, skipping"
fi

# Handle external config.ini
if [ -f "$SCRIPT_DIR/config.ini" ]; then
    echo "Found config.ini, deploying to /opt/config.ini ..."
    cp -f "$SCRIPT_DIR/config.ini" /opt/config.ini
    chmod 644 /opt/config.ini
    chown root:root /opt/config.ini
elif [ -f "$ORIG_DIR/config.ini" ]; then
    echo "Found config.ini, deploying to /opt/config.ini ..."
    cp -f "$ORIG_DIR/config.ini" /opt/config.ini
    chmod 644 /opt/config.ini
    chown root:root /opt/config.ini
fi

# Update guardian_audit.ini from /opt/config.ini
if [ -f /opt/config.ini ]; then
    RAW_URL=$(grep -E '^[[:space:]]*URL' /opt/config.ini | cut -d= -f2 | tr -d ' ' | tr -d '\r')
    RAW_URL=${RAW_URL// /}
    CLEAN_URL=$(echo "$RAW_URL" | sed -E 's#^https?://##')
    if [[ "$CLEAN_URL" == *:* ]]; then
        NEW_IP=${CLEAN_URL%%:*}
        NEW_PORT=${CLEAN_URL##*:}
    else
        NEW_IP=$CLEAN_URL
        CONFIG_PORT=$(sed -nr 's/^[[:space:]]*PORT[[:space:]]*=[[:space:]]*([0-9]+).*$/\1/p' /opt/config.ini | tr -d '\r')
        if [ -n "$CONFIG_PORT" ]; then
            NEW_PORT=$CONFIG_PORT
        elif [[ "$RAW_URL" == https://* ]]; then
            NEW_PORT="443"
        else
            NEW_PORT="80"
        fi
    fi
    NEW_USERID=$(sed -nr 's/^[[:space:]]*USER_ID[[:space:]]*=[[:space:]]*(.*)$/\1/p' /opt/config.ini | tr -d '\r')

    if [ -f /opt/osec/guardian_audit.ini ]; then
        sed -i "s|^[[:space:]]*SERVERIPPORT[[:space:]]*=.*|SERVERIPPORT=$NEW_IP:$NEW_PORT|" /opt/osec/guardian_audit.ini
        sed -i "s|^[[:space:]]*USER_ID[[:space:]]*=.*|USER_ID=$NEW_USERID|" /opt/osec/guardian_audit.ini
        echo "guardian_audit.ini updated from /opt/config.ini"
    fi
fi

# Install stop.sh
echo "Installing stop script..."
cp -f stop.sh /opt/osec/stop.sh
chmod +x /opt/osec/stop.sh
echo "  - stop.sh installed to /opt/osec/stop.sh"

# Detect init system and install service
echo "Installing service..."
HAS_SYSTEMD=false
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    HAS_SYSTEMD=true
fi

if [ "$HAS_SYSTEMD" = true ]; then
    echo "  -> Using systemd"
    cp -f opt/osec/security-evaluator.service /etc/systemd/system/security-evaluator.service
    systemctl daemon-reload
    systemctl enable security-evaluator.service
    if systemctl start security-evaluator.service; then
        echo "  - Service started (systemd)"
    else
        echo "  ! Service enabled but failed to start:"
        systemctl status security-evaluator.service --no-pager 2>&1 || true
    fi
elif command -v service >/dev/null 2>&1; then
    echo "  -> Using SysV init (/etc/init.d/)"
    cp -f opt/osec/security-evaluator.init /etc/init.d/security-evaluator
    chmod +x /etc/init.d/security-evaluator

    if command -v chkconfig >/dev/null 2>&1; then
        chkconfig --add security-evaluator 2>/dev/null || true
        chkconfig security-evaluator on 2>/dev/null || true
        echo "  - Service registered (chkconfig)"
    elif command -v update-rc.d >/dev/null 2>&1; then
        update-rc.d security-evaluator defaults 2>/dev/null || true
        echo "  - Service registered (update-rc.d)"
    fi

    if service security-evaluator start; then
        echo "  - Service started (init.d)"
    else
        echo "  ! Service enabled but failed to start"
    fi
else
    echo "  -> No systemd or service command, using monitor script"
    cp -f opt/osec/security-evaluator.monitor /opt/osec/security-evaluator.monitor
    chmod +x /opt/osec/security-evaluator.monitor
    mkdir -p /opt/osec/log

    if [ -d /etc/init.d ]; then
        cp -f opt/osec/security-evaluator.init /etc/init.d/security-evaluator
        chmod +x /etc/init.d/security-evaluator
    fi

    RC_LINE="/opt/osec/security-evaluator.monitor start"
    if [ -f /etc/rc.local ] && ! grep -qF "security-evaluator.monitor" /etc/rc.local; then
        sed -i '/^exit 0$/d' /etc/rc.local
        echo "$RC_LINE" >> /etc/rc.local
        echo "exit 0" >> /etc/rc.local
        chmod +x /etc/rc.local
        echo "  - Auto-start added to /etc/rc.local"
    fi

    if /opt/osec/security-evaluator.monitor start; then
        echo "  - Monitor started"
    else
        echo "  ! Monitor failed to start, run manually: /opt/osec/security-evaluator.monitor start"
    fi
fi

echo ""
echo "========================================"
echo "Installation completed!"
echo "========================================"
echo ""
echo "Next steps:"
echo "  1. Edit /opt/osec/guardian_audit.ini to configure server, user ID, and device info"
echo "  2. Service is already running. Check status:"
if [ "$HAS_SYSTEMD" = true ]; then
    echo "     systemctl status security-evaluator"
else
    echo "     cat /opt/osec/log/security-evaluator-monitor.log"
fi
echo "  3. Check logs:"
echo "     tail -f /opt/osec/log/guardian_audit.log"
echo "  4. Stop service:"
echo "     /opt/osec/stop.sh"
echo ""

INSTALLEOF

# ====== 6. Generate uninstall script ======
cat > "package_security_evaluator/uninstall.sh" << 'UNINSTALLEOF'
#!/bin/bash

echo "========================================"
echo "Uninstalling Security Evaluator"
echo "========================================"

# Stop service
echo "Stopping service..."

if command -v systemctl >/dev/null 2>&1 && [ -f /etc/systemd/system/security-evaluator.service ]; then
    systemctl stop security-evaluator 2>/dev/null || true
    systemctl disable security-evaluator 2>/dev/null || true
    rm -f /etc/systemd/system/security-evaluator.service
    systemctl daemon-reload
    echo "  - Stopped (systemd)"
elif [ -f /etc/init.d/security-evaluator ]; then
    /etc/init.d/security-evaluator stop 2>/dev/null || true
    if command -v chkconfig >/dev/null 2>&1; then
        chkconfig --del security-evaluator 2>/dev/null || true
    elif command -v update-rc.d >/dev/null 2>&1; then
        update-rc.d -f security-evaluator remove 2>/dev/null || true
    fi
    rm -f /etc/init.d/security-evaluator
    echo "  - Stopped (SysV init)"
else
    pkill -9 -f "security-evaluator" 2>/dev/null || true
    echo "  - Stopped (force kill)"
fi

# Also run stop.sh if available
if [ -f /opt/osec/stop.sh ]; then
    bash /opt/osec/stop.sh 2>/dev/null || true
fi

# Remove files
echo "Removing files..."
rm -f /opt/osec/security-evaluator
rm -f /opt/osec/security-evaluator.monitor
rm -f /opt/osec/stop.sh
rm -f /var/run/security-evaluator.pid
rm -f /var/run/security-evaluator-monitor.pid

if [ -f /etc/rc.local ]; then
    sed -i '/security-evaluator\.monitor/d' /etc/rc.local
fi

echo ""
echo "Configuration files kept:"
echo "  - /opt/osec/guardian_audit.conf"
echo "  - /opt/osec/guardian_audit.ini"
echo "  - /opt/osec/log/guardian_audit.log"
echo ""
echo "To remove completely, run:"
echo "  sudo rm -f /opt/osec/guardian_audit.conf"
echo "  sudo rm -f /opt/osec/guardian_audit.ini"
echo "  sudo rm -rf /opt/osec/log/guardian_audit*"
echo ""

echo "========================================"
echo "Uninstallation completed!"
echo "========================================"
UNINSTALLEOF

# ====== 7. Make scripts executable ======
chmod +x package_security_evaluator/install.sh
chmod +x package_security_evaluator/uninstall.sh

# ====== 8. Create self-extracting installer ======
echo "Creating self-extracting installer..."

cat > "$INSTALLER_NAME" << 'HEADER'
#!/bin/bash
set -e

ORIG_DIR="$(pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TMPDIR=$(mktemp -d /tmp/security-evaluator.XXXXXX)
trap "rm -rf $TMPDIR" EXIT

extract_payload() {
    local start_marker="$1"
    local end_marker="$2"
    local start_line=$(grep -n "^${start_marker}$" "$0" | tail -1 | cut -d: -f1)
    local end_line=$(grep -n "^${end_marker}$" "$0" | tail -1 | cut -d: -f1)
    if [ -n "$start_line" ] && [ -n "$end_line" ] && [ "$end_line" -gt "$start_line" ]; then
        sed -n "$((start_line + 1)),$((end_line - 1))p" "$0" | base64 -d | tar xz -C "$TMPDIR"
    fi
}

echo "Extracting installer..."
extract_payload "===PAYLOAD_START===" "===PAYLOAD_END==="

echo "Running installer..."
cd "$TMPDIR"
ORIG_DIR="$ORIG_DIR" SCRIPT_DIR="$SCRIPT_DIR" bash install.sh
exit 0
HEADER

echo "" >> "$INSTALLER_NAME"
echo "===PAYLOAD_START===" >> "$INSTALLER_NAME"
cd package_security_evaluator && tar czf - . | base64 >> ../"$INSTALLER_NAME"
cd ..
echo "===PAYLOAD_END===" >> "$INSTALLER_NAME"

chmod +x "$INSTALLER_NAME"

echo ""
echo "========================================"
echo "Packaging completed!"
echo "========================================"
echo "Installer: $INSTALLER_NAME"
echo "Package directory: package_security_evaluator/"
echo ""
echo "Usage:"
echo "  sudo $INSTALLER_NAME"
echo "  sudo bash package_security_evaluator/install.sh"
echo "  sudo bash package_security_evaluator/uninstall.sh"
echo ""
