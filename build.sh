#!/bin/bash
set -e

echo "Start packaging osec..."

VERSION="3.0.1_T5_B1"
OUTPUT_DIR="output"
INSTALLER_NAME="${OUTPUT_DIR}/osec-installer-${VERSION}.sh"

# Clean up
rm -rf package/opt/osec "$OUTPUT_DIR"
mkdir -p package/opt/osec/{x86_64-unknown-linux-musl,aarch64-unknown-linux-musl,mips64el-unknown-linux-gnuabi64,certs}
mkdir -p package/opt/osec/log
mkdir -p "$OUTPUT_DIR"

# Copy binaries
cp target/x86_64-unknown-linux-musl/release/MagicArmor_0 package/opt/osec/x86_64-unknown-linux-musl/
cp target/x86_64-unknown-linux-musl/release/MagicArmorAgent package/opt/osec/x86_64-unknown-linux-musl/
cp target/aarch64-unknown-linux-musl/release/MagicArmor_0 package/opt/osec/aarch64-unknown-linux-musl/
cp target/aarch64-unknown-linux-musl/release/MagicArmorAgent package/opt/osec/aarch64-unknown-linux-musl/
cp target/mips64el-unknown-linux-gnuabi64/release/MagicArmor_0 package/opt/osec/mips64el-unknown-linux-gnuabi64/
#cp target/mips64el-unknown-linux-gnuabi64/release/MagicArmorAgent package/opt/osec/mips64el-unknown-linux-gnuabi64/
cp certs/root-ca.pem package/opt/osec/certs/

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
# Generate unified install/upgrade script
# ----------------------------
cat > "package/install_or_upgrade.sh" << EOF
#!/bin/bash
set -e

# Detect mode: install (default) or upgrade (--upgrade)
MODE="install"
if [[ "\$1" == "--upgrade" ]]; then
    MODE="upgrade"
    shift
fi

if [[ "\$MODE" == "install" ]]; then
    echo "🚀 Installing OSEC and Agent Manager (version $VERSION)..."
else
    echo "⏫ Upgrading OSEC to version $VERSION (agent_manager untouched)..."
fi

# --- Secure Boot check (universal) ---
echo "🔍 Checking Secure Boot status..."
if [ -d /sys/firmware/efi ]; then
    if command -v mokutil >/dev/null 2>&1; then
        sb_state=\$(mokutil --sb-state 2>/dev/null | grep -i 'SecureBoot' | awk '{print \$2}')
        if [[ "\$sb_state" == "enabled" ]]; then
            echo "❌ Secure Boot is enabled. \$MODE not allowed."
            echo "👉 Please disable Secure Boot in BIOS/UEFI and retry."
            exit 1
        fi
    else
        sb_file=\$(find /sys/firmware/efi/efivars/ -maxdepth 1 -name 'SecureBoot-*' 2>/dev/null | head -n1)
        if [ -z "\$sb_file" ]; then
            sb_dir=\$(find /sys/firmware/efi/vars/ -name 'SecureBoot-*' -type d 2>/dev/null | head -n1)
            [ -n "\$sb_dir" ] && sb_file="\$sb_dir/data"
        fi

        if [ -f "\$sb_file" ]; then
            sb_value=\$(od -An -t u1 "\$sb_file" 2>/dev/null | awk '{if (NR==1) print \$2}')
            if [ "\$sb_value" = "1" ]; then
                echo "❌ Secure Boot is enabled. \$MODE not allowed."
                echo "👉 Please disable Secure Boot in BIOS/UEFI and retry."
                exit 1
            elif [ "\$sb_value" = "0" ]; then
                echo "✅ Secure Boot is disabled."
            else
                echo "⚠️ Unable to determine Secure Boot status (value: \$sb_value)"
            fi
        else
            echo "⚠️ Secure Boot variable not found (non-UEFI or efivars missing)"
        fi
    fi
else
    if [[ "\$MODE" == "install" ]]; then
        echo "❌ Legacy BIOS mode detected (no UEFI present)"
    fi
fi
# ------------------------------------

OSEC_VERSION="$VERSION"
ARCH=\$(uname -m)
case \$ARCH in
    x86_64|amd64) BIN_DIR="x86_64-unknown-linux-musl" ;;
    aarch64|arm64) BIN_DIR="aarch64-unknown-linux-musl" ;;
    mips64) BIN_DIR="mips64el-unknown-linux-gnuabi64" ;;
    *) echo "Unsupported architecture: \$ARCH"; exit 1 ;;
esac
echo "Detected architecture: \$ARCH"

INSTALL_DIR="/opt/osec"

# Only for install: check existence
if [[ "\$MODE" == "install" ]]; then
    # Extract payload
    PAYLOAD_LINE=\$(awk '/^__PAYLOAD_BELOW__/ {print NR + 1; exit}' "\$0")
    tail -n+\$PAYLOAD_LINE "\$0" | tar -xzf - -C /tmp || { echo "Extraction failed"; exit 1; }

    mkdir -p "\$INSTALL_DIR"
    cp -rf /tmp/opt/osec/* "\$INSTALL_DIR/"
    chmod 755 "\$INSTALL_DIR" -R
    chown -R root:root "\$INSTALL_DIR"
elif [[ "\$MODE" == "upgrade" ]]; then
    [ -d "\$INSTALL_DIR" ] || { echo "Not installed!"; exit 1; }

    if command -v systemctl >/dev/null; then
        systemctl stop osec 2>/dev/null || true
    else
        pkill -f osecmonitor 2>/dev/null || true
    fi
    pkill -f MagicArmor_0 2>/dev/null || true
    sleep 1
    if lsmod | grep -q osec_base; then
        rmmod osec_base || { echo "Failed to unload osec_base"; exit 1; }
    fi

    PAYLOAD_LINE=\$(awk '/^__PAYLOAD_BELOW__/ {print NR + 1; exit}' "\$0")
    tail -n+\$PAYLOAD_LINE "\$0" | tar -xzf - -C /tmp || { echo "Extraction failed"; exit 1; }

    # Backup config
    if [ -f "\$INSTALL_DIR/net_info.ini" ]; then
        cp "\$INSTALL_DIR/net_info.ini" "\$INSTALL_DIR/net_info.ini.bak"
    fi

    # Overwrite all files
    cp -rf /tmp/opt/osec/* "\$INSTALL_DIR/"

    # Restore config but update version
    if [ -f "\$INSTALL_DIR/net_info.ini.bak" ]; then
        mv "\$INSTALL_DIR/net_info.ini.bak" "\$INSTALL_DIR/net_info.ini"
    fi

    if [ -f "\$INSTALL_DIR/net_info.ini" ]; then
        sed -i '/^[[:space:]]*VERSION[[:space:]]*=/d' "\$INSTALL_DIR/net_info.ini"
        sed -i "/\\[SERVERINFO\\]/a VERSION=\$OSEC_VERSION" "\$INSTALL_DIR/net_info.ini"
    fi
fi

# --- Deploy binaries ---
if [ -f "\$INSTALL_DIR/\$BIN_DIR/MagicArmor_0" ]; then
    echo "Copying MagicArmor_0 binary..."
    cp -f "\$INSTALL_DIR/\$BIN_DIR/MagicArmor_0" "\$INSTALL_DIR/MagicArmor_0"
    chmod +x "\$INSTALL_DIR/MagicArmor_0"
else
    echo "ERROR: MagicArmor_0 binary missing!"
    exit 1
fi

# Only deploy agent_manager on install
if [[ "\$MODE" == "install" ]]; then
    if [ -f "\$INSTALL_DIR/\$BIN_DIR/MagicArmorAgent" ]; then
        echo "Copying MagicArmorAgent binary..."
        cp -f "\$INSTALL_DIR/\$BIN_DIR/MagicArmorAgent" "\$INSTALL_DIR/MagicArmorAgent"
        chmod +x "\$INSTALL_DIR/MagicArmorAgent"
    else
        echo "ERROR: MagicArmorAgent binary missing!"
        exit 1
    fi

    # Handle external config.ini (only install)
    if [ -f "./config.ini" ]; then
        echo "Found config.ini in script directory, deploying to /opt/config.ini ..."
        cp -f "./config.ini" /opt/config.ini
        chmod 644 /opt/config.ini
        chown root:root /opt/config.ini
    fi

    # Update net_info.ini from config.ini or default (only install)
    if [ -f /opt/config.ini ]; then
        echo "Updating net_info.ini from /opt/config.ini..."
        RAW_URL=\$(grep -E '^[[:space:]]*URL' /opt/config.ini | cut -d= -f2 | tr -d ' ' | tr -d '\r')
        RAW_URL=\${RAW_URL// /}
        CLEAN_URL=\$(echo "\$RAW_URL" | sed -E 's#^https?://##')

        if [[ "\$CLEAN_URL" == *:* ]]; then
            NEW_IP=\${CLEAN_URL%%:*}
            NEW_PORT=\${CLEAN_URL##*:}
        else
            NEW_IP=\$CLEAN_URL
            CONFIG_PORT=\$(sed -nr 's/^[[:space:]]*PORT[[:space:]]*=[[:space:]]*([0-9]+).*$/\\1/p' /opt/config.ini | tr -d '\r')
            if [ -n "\$CONFIG_PORT" ]; then
                NEW_PORT=\$CONFIG_PORT
            elif [[ "\$RAW_URL" == https://* ]]; then
                NEW_PORT="443"
            else
                NEW_PORT="80"
            fi
        fi
        NEW_USERID=\$(sed -nr 's/^[[:space:]]*USER_ID[[:space:]]*=[[:space:]]*(.*)\$/\\1/p' /opt/config.ini | tr -d '\r')
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
fi

# --- Deploy services ---
if command -v systemctl >/dev/null 2>&1; then
    echo "Setting up services with systemd..."
    if [[ "\$MODE" == "install" ]]; then
        systemctl stop osec agent_manager 2>/dev/null || true
        cp -f "\$INSTALL_DIR/osec.service" /etc/systemd/system/osec.service
        cp -f "\$INSTALL_DIR/agent_manager.service" /etc/systemd/system/agent_manager.service
        chmod 644 /etc/systemd/system/osec.service /etc/systemd/system/agent_manager.service
        systemctl daemon-reload
        systemctl enable osec --now
        systemctl enable agent_manager --now

        # Verify osec
        if ! systemctl is-active --quiet osec; then
            echo "ERROR: osec failed to start!"
            journalctl -u osec -n 10 --no-pager
            exit 1
        fi
        # Verify agent_manager
        if ! systemctl is-active --quiet agent_manager; then
            echo "ERROR: agent_manager failed to start!"
            journalctl -u agent_manager -n 20 --no-pager
            exit 1
        fi
        echo "osec and agent_manager services started successfully."
    else
        # Upgrade: only osec
        cp -f "\$INSTALL_DIR/osec.service" /etc/systemd/system/osec.service
        chmod 644 /etc/systemd/system/osec.service
        systemctl daemon-reload
        systemctl enable osec --now

        # Wait for osec to start
        for i in {1..10}; do
            if systemctl is-active --quiet osec; then
                echo "osec service started successfully after upgrade."
                break
            fi
            sleep 1
        done
        if ! systemctl is-active --quiet osec; then
            echo "ERROR: osec failed to start after upgrade!"
            journalctl -u osec -n 20 --no-pager
            exit 1
        fi
    fi
else
    echo "systemd not found. Falling back to SysV init..."
    pkill -f osecmonitor 2>/dev/null || true
    pkill -f MagicArmor_0 2>/dev/null || true
    if [[ "\$MODE" == "install" ]]; then
        pkill -f MagicArmorAgent 2>/dev/null || true
        sleep 1
        cp -f "\$INSTALL_DIR/osecservicecentos" /etc/init.d/osecservicecentos
        chmod +x /etc/init.d/osecservicecentos
        if command -v chkconfig >/dev/null 2>&1; then
            chkconfig --add osecservicecentos
            chkconfig osecservicecentos on
        fi
        if command -v service >/dev/null 2>&1; then
            service osecservicecentos start
        else
            /etc/init.d/osecservicecentos start
        fi
    else
        # Upgrade: restart existing service
        if [ ! -f /etc/init.d/osecservicecentos ]; then
            echo "ERROR: /etc/init.d/osecservicecentos not found. Cannot restart service."
            exit 1
        fi
        if command -v service >/dev/null 2>&1; then
            service osecservicecentos stop 2>/dev/null || true
            sleep 1
            service osecservicecentos start
        else
            /etc/init.d/osecservicecentos stop 2>/dev/null || true
            sleep 1
            /etc/init.d/osecservicecentos start
        fi
    fi
fi

# Cleanup architecture dirs
rm -rf "\$INSTALL_DIR/x86_64-unknown-linux-musl" "\$INSTALL_DIR/aarch64-unknown-linux-musl"
rm -rf "\$INSTALL_DIR/mips64el-unknown-linux-gnuabi64" "\$INSTALL_DIR/mips64el-unknown-linux-gnuabi64"

if [[ "\$MODE" == "install" ]]; then
    echo "✅ Installation completed!"
else
    echo "✅ Upgrade completed! (agent_manager preserved)"
fi
exit 0
__PAYLOAD_BELOW__
EOF

# ----------------------------
# Package
# ----------------------------
cd package
tar -czf /tmp/osec-payload.tar.gz opt/
cat install_or_upgrade.sh /tmp/osec-payload.tar.gz > "../$INSTALLER_NAME"
chmod +x "../$INSTALLER_NAME"
rm -f /tmp/osec-payload.tar.gz
cd ..

echo "✅ Unified installer: $INSTALLER_NAME"
echo "💡 Usage:"
echo "   sudo ./$(basename "$INSTALLER_NAME")           # Install"
echo "   sudo ./$(basename "$INSTALLER_NAME") --upgrade # Upgrade"
