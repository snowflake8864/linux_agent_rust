#!/bin/bash
set -e

echo "Start packaging osec..."

VERSION="3.0.1_T10"
OUTPUT_DIR="output"
INSTALLER_NAME="${OUTPUT_DIR}/osec-installer-${VERSION}.sh"

# ====== 1. Clean and create dirs ======
rm -rf package/opt/osec "$OUTPUT_DIR"
mkdir -p package/opt/osec/{x86_64-unknown-linux-musl,aarch64-unknown-linux-musl,mips64el-unknown-linux-gnuabi64,loongarch64-unknown-linux-musl,certs}
mkdir -p package/opt/osec/log
mkdir -p "$OUTPUT_DIR"

# ====== 2. Copy user-space binaries ======
echo "Copying binaries..."

# x86_64
cp target/x86_64-unknown-linux-musl/release/MagicArmor_0 package/opt/osec/x86_64-unknown-linux-musl/
cp target/x86_64-unknown-linux-musl/release/MagicArmorAgent package/opt/osec/x86_64-unknown-linux-musl/

# aarch64
cp target/aarch64-unknown-linux-musl/release/MagicArmor_0 package/opt/osec/aarch64-unknown-linux-musl/
cp target/aarch64-unknown-linux-musl/release/MagicArmorAgent package/opt/osec/aarch64-unknown-linux-musl/

# mips64el (no MagicArmorAgent)
cp target/mips64el-unknown-linux-gnuabi64/release/MagicArmor_0 package/opt/osec/mips64el-unknown-linux-gnuabi64/
cp target/mips64el-unknown-linux-gnuabi64/release/MagicArmorAgent package/opt/osec/mips64el-unknown-linux-gnuabi64/

# loongarch64 (no MagicArmorAgent)
cp target/loongarch64-unknown-linux-musl/release/MagicArmor_0 package/opt/osec/loongarch64-unknown-linux-musl/
cp target/loongarch64-unknown-linux-musl/release/MagicArmorAgent package/opt/osec/loongarch64-unknown-linux-musl/

# ====== 3. Copy architecture-specific kernel modules ======
echo "Copying kernel modules..."

cp driver/x86_64-unknown-linux-musl/osec_base.ko* package/opt/osec/x86_64-unknown-linux-musl/ 2>/dev/null || true
cp driver/aarch64-unknown-linux-musl/osec_base.ko* package/opt/osec/aarch64-unknown-linux-musl/ 2>/dev/null || true
cp driver/mips64el-unknown-linux-gnuabi64/osec_base.ko* package/opt/osec/mips64el-unknown-linux-gnuabi64/ 2>/dev/null || true
cp driver/loongarch64-unknown-linux-musl/osec_base.ko* package/opt/osec/loongarch64-unknown-linux-musl/ 2>/dev/null || true

# ====== 4. Copy common files ======
cp -f script/net_info.ini package/opt/osec/
cp -f script/osec.service package/opt/osec/
cp -f script/agent_manager.service package/opt/osec/
cp -f script/osec.init package/opt/osec/
cp -f script/agent_manager.init package/opt/osec/
cp -f script/osec_backend.conf package/opt/osec/
cp -f script/agent_backend.conf package/opt/osec/
cp -f script/osecmonitor package/opt/osec/
cp -f script/readme.txt package/opt/osec/
cp certs/root-ca.pem package/opt/osec/certs/

# Update version
NET_INFO_FILE="package/opt/osec/net_info.ini"
sed -i '/^VERSION=/d' "$NET_INFO_FILE" 2>/dev/null || true
sed -i "/\[SERVERINFO\]/a VERSION=$VERSION" "$NET_INFO_FILE"

# ====== 5. Generate install script ======
cat > "package/install_or_upgrade.sh" << EOF
#!/bin/bash
set -e

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

# --- Secure Boot check ---
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

OSEC_VERSION="$VERSION"
ARCH=\$(uname -m)
case \$ARCH in
    x86_64|amd64)       BIN_DIR="x86_64-unknown-linux-musl" ;;
    aarch64|arm64)      BIN_DIR="aarch64-unknown-linux-musl" ;;
    mips64)             BIN_DIR="mips64el-unknown-linux-gnuabi64" ;;
    loongarch64)        BIN_DIR="loongarch64-unknown-linux-musl" ;;
    *) echo "Unsupported architecture: \$ARCH"; exit 1 ;;
esac
echo "Detected architecture: \$ARCH"

INSTALL_DIR="/opt/osec"

if [[ "\$MODE" == "install" ]]; then
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

    if [ -f "\$INSTALL_DIR/net_info.ini" ]; then
        cp "\$INSTALL_DIR/net_info.ini" "\$INSTALL_DIR/net_info.ini.bak"
    fi
    cp -rf /tmp/opt/osec/* "\$INSTALL_DIR/"
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
# --- Deploy kernel module (keep original name) ---
COPIED_ANY=0
for f in "\$INSTALL_DIR/\$BIN_DIR"/osec_base.ko-*; do
    if [ -f "\$f" ]; then
        echo "Copying kernel module \$(basename "\$f") for \$ARCH..."
        cp -f "\$f" "\$INSTALL_DIR/"
        chmod 644 "\$INSTALL_DIR/\$(basename "\$f")"
        chown root:root "\$INSTALL_DIR/\$(basename "\$f")"
        COPIED_ANY=1
    fi
done

if [ "\$COPIED_ANY" = "0" ]; then
    echo "WARNING: No kernel module found matching 'osec_base.ko-*' in \$INSTALL_DIR/\$BIN_DIR. Skipping."
fi
# Only deploy agent_manager on install
if [[ "\$MODE" == "install" ]]; then
    if [ -f "\$INSTALL_DIR/\$BIN_DIR/MagicArmorAgent" ]; then
        echo "Copying MagicArmorAgent binary..."
        cp -f "\$INSTALL_DIR/\$BIN_DIR/MagicArmorAgent" "\$INSTALL_DIR/MagicArmorAgent"
        chmod +x "\$INSTALL_DIR/MagicArmorAgent"
    else
        echo "WARNING: MagicArmorAgent not available for \$ARCH. Skipping agent_manager."
    fi

    # Handle external config.ini
    if [ -f "./config.ini" ]; then
        echo "Found config.ini in script directory, deploying to /opt/config.ini ..."
        cp -f "./config.ini" /opt/config.ini
        chmod 644 /opt/config.ini
        chown root:root /opt/config.ini
    fi

    # Update net_info.ini
    if [ -f /opt/config.ini ]; then
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
        systemctl enable osec
        systemctl enable agent_manager
        systemctl start osec
        systemctl start agent_manager

        # systemd 环境不需要 monitor/init 脚本，删除
        rm -f "\$INSTALL_DIR/osec.monitor" 2>/dev/null || true
        rm -f "\$INSTALL_DIR/agent_manager.monitor" 2>/dev/null || true
        rm -f "\$INSTALL_DIR/osec.init" 2>/dev/null || true
        rm -f "\$INSTALL_DIR/agent_manager.init" 2>/dev/null || true

        # Verify
        if ! systemctl is-active --quiet osec; then
            echo "ERROR: osec failed to start!"
            journalctl -u osec -n 10 --no-pager
            exit 1
        fi
        if ! systemctl is-active --quiet agent_manager; then
            echo "ERROR: agent_manager failed to start!"
            journalctl -u agent_manager -n 20 --no-pager
            exit 1
        fi
        echo "osec and agent_manager services started successfully."
    else
        cp -f "\$INSTALL_DIR/osec.service" /etc/systemd/system/osec.service
        chmod 644 /etc/systemd/system/osec.service
        systemctl daemon-reload
        systemctl enable osec
        systemctl start osec
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
        cp -f "\$INSTALL_DIR/osec.init" /etc/init.d/osec
        chmod +x /etc/init.d/osec
        cp -f "\$INSTALL_DIR/agent_manager.init" /etc/init.d/agent_manager
        chmod +x /etc/init.d/agent_manager
        if command -v chkconfig >/dev/null 2>&1; then
            chkconfig --add osec
            chkconfig osec on
            chkconfig --add agent_manager
            chkconfig agent_manager on
        fi
        if command -v service >/dev/null 2>&1; then
            service osec start
            service agent_manager start
        else
            /etc/init.d/osec start
            /etc/init.d/agent_manager start
        fi
        echo "osec and agent_manager services started successfully."
    else
        if [ ! -f /etc/init.d/osec ]; then
            echo "ERROR: /etc/init.d/osec not found. Cannot restart service."
            exit 1
        fi
        if command -v service >/dev/null 2>&1; then
            service osec stop 2>/dev/null || true
            sleep 1
            service osec start
        else
            /etc/init.d/osec stop 2>/dev/null || true
            sleep 1
            /etc/init.d/osec start
        fi
        echo "osec service restarted after upgrade."
    fi
fi

# Cleanup architecture dirs
rm -rf "\$INSTALL_DIR/x86_64-unknown-linux-musl" \
       "\$INSTALL_DIR/aarch64-unknown-linux-musl" \
       "\$INSTALL_DIR/mips64el-unknown-linux-gnuabi64" \
       "\$INSTALL_DIR/loongarch64-unknown-linux-musl"

if [[ "\$MODE" == "install" ]]; then
    echo "✅ Installation completed!"
else
    echo "✅ Upgrade completed! (agent_manager preserved)"
fi
exit 0
__PAYLOAD_BELOW__
EOF

# ====== 6. Package ======
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
