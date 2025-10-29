#!/bin/bash
set -e
echo "Start packaging osec..."

VERSION="3.0.2_T4"
OUTPUT_DIR="output"
INSTALLER_NAME="${OUTPUT_DIR}/osec-installer-${VERSION}.sh"
UPGRADE_NAME="${OUTPUT_DIR}/osec-upgrade-${VERSION}.sh"

# Clean up
rm -rf package/opt/osec "$OUTPUT_DIR"
mkdir -p package/opt/osec/{x86_64-unknown-linux-musl,aarch64-unknown-linux-musl}
mkdir -p package/opt/osec/log
mkdir -p "$OUTPUT_DIR"

# Copy binaries
cp target/x86_64-unknown-linux-musl/release/MagicArmor_0 package/opt/osec/x86_64-unknown-linux-musl/
cp target/x86_64-unknown-linux-musl/release/agent_manager package/opt/osec/x86_64-unknown-linux-musl/
# Uncomment for ARM if needed
# cp target/aarch64-unknown-linux-musl/release/MagicArmor_0 package/opt/osec/aarch64-unknown-linux-musl/
# cp target/aarch64-unknown-linux-musl/release/agent_manager package/opt/osec/aarch64-unknown-linux-musl/

# Copy config and service files
cp -f script/net_info.ini package/opt/osec/
cp -f script/osec.service package/opt/osec/
cp -f script/agent_manager.service package/opt/osec/
cp -f script/osec_backend.conf package/opt/osec/
cp -f script/agent_backend.conf package/opt/osec/
cp -f script/osecmonitor package/opt/osec/
cp -f script/osecservicecentos package/opt/osec/
cp -rf driver/osec_base.ko* package/opt/osec/
cp -f script/readme.txt package/opt/osec/

# Update version in net_info.ini
NET_INFO_FILE="package/opt/osec/net_info.ini"
sed -i '/^VERSION=/d' "$NET_INFO_FILE" 2>/dev/null || true
sed -i "/\[SERVERINFO\]/a VERSION=$VERSION" "$NET_INFO_FILE"

# ----------------------------
# Generate INSTALL script
# ----------------------------
cat > "package/install.sh" << EOF
#!/bin/bash
set -e
echo "Installing OSEC and Agent Manager..."

OSEC_VERSION="$VERSION"
ARCH=\$(uname -m)
case \$ARCH in
    x86_64|amd64) BIN_DIR="x86_64-unknown-linux-musl" ;;
    aarch64|arm64) BIN_DIR="aarch64-unknown-linux-musl" ;;
    *) echo "Unsupported architecture: \$ARCH"; exit 1 ;;
esac
echo "Detected architecture: \$ARCH"

# Extract payload
PAYLOAD_LINE=\$(awk '/^__PAYLOAD_BELOW__/ {print NR + 1; exit}' "\$0")
tail -n+\$PAYLOAD_LINE "\$0" | tar -xzf - -C /tmp || { echo "Extraction failed"; exit 1; }

INSTALL_DIR="/opt/osec"
mkdir -p "\$INSTALL_DIR"
cp -rf /tmp/opt/osec/* "\$INSTALL_DIR/"
chmod 755 "\$INSTALL_DIR" -R
chown -R root:root "\$INSTALL_DIR"

# --- Deploy MagicArmor_0 ---
if [ -f "\$INSTALL_DIR/\$BIN_DIR/MagicArmor_0" ]; then
    echo "Copying MagicArmor_0 binary..."
    cp -f "\$INSTALL_DIR/\$BIN_DIR/MagicArmor_0" "\$INSTALL_DIR/MagicArmor_0"
    chmod +x "\$INSTALL_DIR/MagicArmor_0"
else
    echo "ERROR: MagicArmor_0 binary missing!"
    exit 1
fi

# --- Deploy agent_manager ---
if [ -f "\$INSTALL_DIR/\$BIN_DIR/agent_manager" ]; then
    echo "Copying agent_manager binary..."
    cp -f "\$INSTALL_DIR/\$BIN_DIR/agent_manager" "\$INSTALL_DIR/agent_manager"
    chmod +x "\$INSTALL_DIR/agent_manager"
else
    echo "ERROR: agent_manager binary missing!"
    exit 1
fi

# --- Update net_info.ini ---
if [ -f /opt/config.ini ]; then
    echo "Updating net_info.ini from /opt/config.ini..."
    RAW_URL=\$(grep -E '^[[:space:]]*URL' /opt/config.ini | cut -d= -f2 | tr -d ' ')
    RAW_URL=\${RAW_URL// /}
    CLEAN_URL=\$(echo "\$RAW_URL" | sed -E 's#^https?://##')

    if [[ "\$CLEAN_URL" == *:* ]]; then
        NEW_IP=\${CLEAN_URL%%:*}
        NEW_PORT=\${CLEAN_URL##*:}
    else
        NEW_IP=\$CLEAN_URL
        CONFIG_PORT=\$(sed -nr 's/^[[:space:]]*PORT[[:space:]]*=[[:space:]]*([0-9]+).*$/\\1/p' /opt/config.ini)
        if [ -n "\$CONFIG_PORT" ]; then
            NEW_PORT=\$CONFIG_PORT
        elif [[ "\$RAW_URL" == https://* ]]; then
            NEW_PORT="443"
        else
            NEW_PORT="80"
        fi
    fi
    NEW_USERID=\$(sed -nr 's/^[[:space:]]*USER_ID[[:space:]]*=[[:space:]]*(.*)\$/\\1/p' /opt/config.ini)
else
    echo "Using default server config..."
    NEW_IP="192.168.10.251"
    NEW_PORT="10443"
    NEW_USERID="bRWiodd/UzhDCGABDNquwa3e/IjFoZMIFooVm0hRr6O54VMXdT7nbIBKaQgd88=jP="
fi

TARGET_FILE="\$INSTALL_DIR/net_info.ini"
if [ -f "\$TARGET_FILE" ]; then
    sed -i "s|^[[:space:]]*SERVER_IP[[:space:]]*=.*|SERVER_IP=\$NEW_IP|" "\$TARGET_FILE"
    sed -i "s|^[[:space:]]*SERVER_PORT[[:space:]]*=.*|SERVER_PORT=\$NEW_PORT|" "\$TARGET_FILE"
    sed -i "s|^[[:space:]]*USER_ID[[:space:]]*=.*|USER_ID=\$NEW_USERID|" "\$TARGET_FILE"
    sed -i "s|^[[:space:]]*SERVERIPPORT[[:space:]]*=.*|SERVERIPPORT=https://\$NEW_IP:\$NEW_PORT|" "\$TARGET_FILE"
    sed -i '/^[[:space:]]*VERSION[[:space:]]*=/d' "\$TARGET_FILE"
    sed -i "/\\[SERVERINFO\\]/a VERSION=\$OSEC_VERSION" "\$TARGET_FILE"
    echo "net_info.ini updated."
fi

# --- Deploy services (systemd) ---
if command -v systemctl >/dev/null 2>&1; then
    echo "Setting up services with systemd..."

    # Stop old services
    systemctl stop osec agent_manager 2>/dev/null || true

    # Install service files
    cp -f "\$INSTALL_DIR/osec.service" /etc/systemd/system/osec.service
    cp -f "\$INSTALL_DIR/agent_manager.service" /etc/systemd/system/agent_manager.service
    chmod 644 /etc/systemd/system/osec.service /etc/systemd/system/agent_manager.service

    systemctl daemon-reload

    # Start osec
    echo "Starting osec service..."
    systemctl enable osec --now
    if systemctl is-active --quiet osec; then
        echo "osec service started successfully."
    else
        echo "ERROR: osec failed to start!"
        journalctl -u osec -n 10 --no-pager
        exit 1
    fi

    # Start agent_manager
    echo "Starting agent_manager service..."  # <<< 关键打印
    systemctl enable agent_manager --now
    if systemctl is-active --quiet agent_manager; then
        echo "agent_manager service started successfully."  # <<< 关键打印
    else
        echo "ERROR: agent_manager failed to start!"
        echo "Check logs: journalctl -u agent_manager -n 20"
        journalctl -u agent_manager -n 20 --no-pager
        exit 1
    fi

else
     echo "systemd not found. Falling back to SysV init (e.g., CentOS 6)..."

    # Stop old processes
    pkill -f osecmonitor 2>/dev/null || true
    pkill -f MagicArmor_0 2>/dev/null || true
    pkill -f agent_manager 2>/dev/null || true
    sleep 1

    # Copy init script
    cp -f "\$INSTALL_DIR/osecservicecentos" /etc/init.d/osecservicecentos
    chmod +x /etc/init.d/osecservicecentos

    # Add to chkconfig and start
    if command -v chkconfig >/dev/null 2>&1; then
        chkconfig --add osecservicecentos
        chkconfig osecservicecentos on
    else
        echo "Warning: chkconfig not found. Service won't start on boot."
    fi

    # Start the service
    if command -v service >/dev/null 2>&1; then
        service osecservicecentos start
        echo "osecservicecentos started via SysV init."
    else
        echo "ERROR: 'service' command not found. Cannot start osecservicecentos."
        exit 1
    fi
fi

# Cleanup
rm -rf "\$INSTALL_DIR/x86_64-unknown-linux-musl" "\$INSTALL_DIR/aarch64-unknown-linux-musl"
echo "Installation completed!"
exit 0
__PAYLOAD_BELOW__
EOF

# ----------------------------
# Generate UPGRADE script (DO NOT TOUCH agent_manager)
# ----------------------------
cat > "package/upgrade.sh" << EOF
#!/bin/bash
set -e
echo "Upgrading OSEC to version $VERSION (agent_manager untouched)..."

OSEC_VERSION="$VERSION"
ARCH=\$(uname -m)
case \$ARCH in
    x86_64|amd64) BIN_DIR="x86_64-unknown-linux-musl" ;;
    aarch64|arm64) BIN_DIR="aarch64-unknown-linux-musl" ;;
    *) echo "Unsupported architecture: \$ARCH"; exit 1 ;;
esac

INSTALL_DIR="/opt/osec"
[ -d "\$INSTALL_DIR" ] || { echo "Not installed!"; exit 1; }

# Stop osec only
if command -v systemctl >/dev/null; then
    systemctl stop osec 2>/dev/null || true
else
    pkill -f osecmonitor 2>/dev/null || true
fi

# Kill MagicArmor_0 explicitly
pkill -f MagicArmor_0 2>/dev/null || true
sleep 1

# Unload kernel module
if lsmod | grep -q osec_base; then
    rmmod osec_base || { echo "Failed to unload osec_base"; exit 1; }
fi

# Extract payload
PAYLOAD_LINE=\$(awk '/^__PAYLOAD_BELOW__/ {print NR + 1; exit}' "\$0")
tail -n+\$PAYLOAD_LINE "\$0" | tar -xzf - -C /tmp || { echo "Extraction failed"; exit 1; }

# CRITICAL: Remove agent_manager files from payload
rm -f /tmp/opt/osec/agent_manager
rm -f /tmp/opt/osec/agent_manager.service
rm -rf "/tmp/opt/osec/\$BIN_DIR"

# Backup and restore net_info.ini
if [ -f "\$INSTALL_DIR/net_info.ini" ]; then
    cp "\$INSTALL_DIR/net_info.ini" "\$INSTALL_DIR/net_info.ini.bak"
fi

cp -rf /tmp/opt/osec/* "\$INSTALL_DIR/"

if [ -f "\$INSTALL_DIR/net_info.ini.bak" ]; then
    mv "\$INSTALL_DIR/net_info.ini.bak" "\$INSTALL_DIR/net_info.ini"
fi

# Update version in net_info.ini
if [ -f "\$INSTALL_DIR/net_info.ini" ]; then
    sed -i '/^[[:space:]]*VERSION[[:space:]]*=/d' "\$INSTALL_DIR/net_info.ini"
    sed -i "/\\[SERVERINFO\\]/a VERSION=\$OSEC_VERSION" "\$INSTALL_DIR/net_info.ini"
fi

# Deploy MagicArmor_0 only
cp -f "\$INSTALL_DIR/\$BIN_DIR/MagicArmor_0" "\$INSTALL_DIR/MagicArmor_0"
chmod +x "\$INSTALL_DIR/MagicArmor_0"


# Restart osec only
if command -v systemctl >/dev/null 2>&1; then
    echo "Restarting osec via systemd..."
    cp -f "\$INSTALL_DIR/osec.service" /etc/systemd/system/osec.service
    chmod 644 /etc/systemd/system/osec.service
    systemctl daemon-reload
    systemctl enable osec --now
    if ! systemctl is-active --quiet osec; then
        echo "ERROR: osec failed to start after upgrade!"
        journalctl -u osec -n 10 --no-pager
        exit 1
    fi
else
    echo "systemd not found. Restarting osec via SysV init (osecservicecentos)..."

    # Ensure init script exists
    if [ ! -f /etc/init.d/osecservicecentos ]; then
        echo "ERROR: /etc/init.d/osecservicecentos not found. Cannot restart service."
        exit 1
    fi

    # Stop
    if command -v service >/dev/null 2>&1; then
        service osecservicecentos stop 2>/dev/null || true
    else
        /etc/init.d/osecservicecentos stop 2>/dev/null || true
    fi

    sleep 1

    # Start
    if command -v service >/dev/null 2>&1; then
        service osecservicecentos start
    else
        /etc/init.d/osecservicecentos start
    fi

    echo "osec restarted via osecservicecentos."
fi

rm -rf "\$INSTALL_DIR/x86_64-unknown-linux-musl" "\$INSTALL_DIR/aarch64-unknown-linux-musl"
echo "Upgrade completed! (agent_manager was preserved)"
exit 0
__PAYLOAD_BELOW__
EOF

# ----------------------------
# Package
# ----------------------------
cd package
tar -czf /tmp/osec-payload.tar.gz opt/
cat install.sh /tmp/osec-payload.tar.gz > "../$INSTALLER_NAME"
cat upgrade.sh /tmp/osec-payload.tar.gz > "../$UPGRADE_NAME"
chmod +x "../$INSTALLER_NAME" "../$UPGRADE_NAME"
rm -f /tmp/osec-payload.tar.gz
cd ..

echo "✅ Installer:  $INSTALLER_NAME"
echo "✅ Upgrade:    $UPGRADE_NAME"
echo "💡 Usage:"
echo "   sudo ./$(basename "$INSTALLER_NAME")"
echo "   sudo ./$(basename "$UPGRADE_NAME")"
