#!/bin/bash
set -e

echo "Start packaging osec..."

VERSION="1.1.21"
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

cp driver.greatwall-guard/x86_64-unknown-linux-musl/osec_base.ko* package/opt/osec/x86_64-unknown-linux-musl/ 2>/dev/null || true
cp driver.greatwall-guard/aarch64-unknown-linux-musl/osec_base.ko* package/opt/osec/aarch64-unknown-linux-musl/ 2>/dev/null || true
cp driver.greatwall-guard/mips64el-unknown-linux-gnuabi64/osec_base.ko* package/opt/osec/mips64el-unknown-linux-gnuabi64/ 2>/dev/null || true
cp driver.greatwall-guard/loongarch64-unknown-linux-musl/osec_base.ko* package/opt/osec/loongarch64-unknown-linux-musl/ 2>/dev/null || true

# ====== 4. Copy common files ======
cp -f script/net_info.ini package/opt/osec/
cp -f script/osec.init package/opt/osec/
cp -f script/agent_manager.init package/opt/osec/
cp -f script/osec.monitor package/opt/osec/
cp -f script/agent_manager.monitor package/opt/osec/
cp -f script/osec_backend.conf package/opt/osec/
cp -f script/agent_backend.conf package/opt/osec/
cp -f script/osecmonitor package/opt/osec/
cp -f script/readme.txt package/opt/osec/
cp -f script/osec.service package/opt/osec/
cp -f script/agent_manager.service package/opt/osec/
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

# 日志文件
LOG_FILE="/var/log/osec_upgrade.log"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "========================================"
echo "[$(date)] $MODE started"
echo "========================================"
echo "[\$(date)] \$MODE started"
echo "========================================"

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
    
    # 停止服务（systemd 或 init.d）
    if command -v systemctl >/dev/null; then
        systemctl stop osec 2>/dev/null || true
    else
        # 停止新的 monitor
        [ -f "\$INSTALL_DIR/osec.monitor" ] && "\$INSTALL_DIR/osec.monitor" stop 2>/dev/null || true
        # 停止老的 osecmonitor
        pkill -9 -f osecmonitor 2>/dev/null || true
    fi
    
    # 杀掉所有相关进程
    pkill -9 -f MagicArmor_0 2>/dev/null || true
    pkill -9 -f MagicArmorAgent 2>/dev/null || true
    sleep 1
    
    # 清理老版本残留（无 systemd 环境）
    if [ ! -d /run/systemd/system ]; then
        # 清理老的 init.d 脚本
        if [ -f /etc/init.d/osecservicecentos ]; then
            chkconfig --del osecservicecentos 2>/dev/null || true
            rm -f /etc/init.d/osecservicecentos
        fi
        # 清理老的监控脚本
        rm -f "\$INSTALL_DIR/osecmonitor" 2>/dev/null || true
        # 清理老的 PID 文件
        rm -f /var/run/osec.pid 2>/dev/null || true
    fi
    
    # 卸载内核模块（带重试和详细日志）
    if lsmod | grep -q osec_base; then
        echo "[upgrade] 发现 osec_base 内核模块，准备卸载..."
        echo "[upgrade] 检查模块使用计数:"
        cat /proc/modules | grep osec_base || true
        
        # 先尝试正常卸载
        if rmmod osec_base 2>/dev/null; then
            echo "[upgrade] osec_base 模块已成功卸载"
        else
            echo "[upgrade] 正常卸载失败，检查是否有进程占用..."
            # 检查是否有进程占用
            lsof /dev/osec 2>/dev/null || true
            
            # 强制杀掉所有可能占用驱动的进程
            pkill -9 -f MagicArmor 2>/dev/null || true
            sleep 2
            
            # 再次尝试卸载
            if rmmod osec_base 2>/dev/null; then
                echo "[upgrade] osec_base 模块已成功卸载（第二次尝试）"
            else
                echo "[upgrade] 警告: 无法卸载 osec_base 模块，可能被其他进程占用"
                echo "[upgrade] 尝试强制卸载..."
                # 最后尝试：不检查错误，继续升级
                rmmod -f osec_base 2>/dev/null || true
                echo "[upgrade] 继续升级流程..."
            fi
        fi
    else
        echo "[upgrade] osec_base 模块未加载，跳过卸载"
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

# Cleanup architecture dirs (必须在 MagicArmor_0 启动前删除，否则驱动保护导致无法删除)
echo "Cleaning up architecture directories..."
rm -rf "\$INSTALL_DIR/x86_64-unknown-linux-musl" \
       "\$INSTALL_DIR/aarch64-unknown-linux-musl" \
       "\$INSTALL_DIR/mips64el-unknown-linux-gnuabi64" \
       "\$INSTALL_DIR/loongarch64-unknown-linux-musl"

# --- Deploy services (systemd preferred, fallback to init.d + monitor) ---
    echo "Setting up services..."
# 检测 systemd 是否可用
if [ -d /run/systemd/system ]; then
    # 使用 systemd
    echo "Using systemd..."
    UNIT_DIR=""
    # 按优先级遍历，但只选择可写的目录
    for d in /usr/lib/systemd/system /lib/systemd/system /etc/systemd/system; do
        if [ -d "\$d" ]; then
            # 尝试创建临时文件以测试可写性
            if touch "\$d/.systemd_writable_test" 2>/dev/null; then
                rm -f "\$d/.systemd_writable_test"
                UNIT_DIR="\$d"
                echo "Selected writable unit directory: \$d"
                break
            else
                echo "Directory \$d exists but is read-only, skipping..."
            fi
        fi
    done

    if [ -z "\$UNIT_DIR" ]; then
        echo "ERROR: No writable systemd unit directory found in searched paths." >&2
        exit 1
    fi

    # 复制 service 文件
    [ -f "\$INSTALL_DIR/osec.service" ] && cp -f "\$INSTALL_DIR/osec.service" "\$UNIT_DIR/" && chmod 644 "\$UNIT_DIR/osec.service"
    [ -f "\$INSTALL_DIR/agent_manager.service" ] && cp -f "\$INSTALL_DIR/agent_manager.service" "\$UNIT_DIR/" && chmod 644 "\$UNIT_DIR/agent_manager.service"
    systemctl daemon-reload 2>/dev/null || true

    if [[ "\$MODE" == "install" ]]; then
        # enable 服务
        if [ -f "\$UNIT_DIR/osec.service" ]; then
            systemctl enable osec 2>/dev/null || true
        else
            echo "ERROR: osec.service not found in \$UNIT_DIR"
            exit 1
        fi
        if [ -f "\$UNIT_DIR/agent_manager.service" ]; then
            systemctl enable agent_manager 2>/dev/null || true
        else
            echo "ERROR: agent_manager.service not found in \$UNIT_DIR"
            exit 1
        fi

        # 启动服务并检查结果
        echo "Starting osec service..."
        if systemctl start osec; then
            echo "osec service started."
        else
            echo "ERROR: osec service failed to start!"
            systemctl status osec --no-pager || true
            exit 1
        fi

        echo "Starting agent_manager service..."
        if systemctl start agent_manager; then
            echo "agent_manager service started."
        else
            echo "ERROR: agent_manager service failed to start!"
            systemctl status agent_manager --no-pager || true
            exit 1
        fi

        # systemd 环境不需要 monitor/init 脚本，删除
        rm -f "\$INSTALL_DIR/osec.monitor" "\$INSTALL_DIR/agent_manager.monitor" \
              "\$INSTALL_DIR/osec.init" "\$INSTALL_DIR/agent_manager.init" 2>/dev/null || true

        echo "osec and agent_manager services started successfully (systemd)."
    else
        # 升级模式：重启 osec 和 agent_manager
        [ -f "\$UNIT_DIR/osec.service" ] && systemctl restart osec 2>/dev/null || true
        [ -f "\$UNIT_DIR/agent_manager.service" ] && systemctl restart agent_manager 2>/dev/null || true
        echo "osec and agent_manager services restarted successfully (systemd)."
    fi
    else
        # 使用 init.d + monitor 脚本
        echo "Using init.d + monitor..."
        
        if [[ "\$MODE" == "install" ]]; then
            cp -f "\$INSTALL_DIR/osec.init" /etc/init.d/osec >/dev/null 2>&1
            cp -f "\$INSTALL_DIR/agent_manager.init" /etc/init.d/agent_manager >/dev/null 2>&1
            chmod +x /etc/init.d/osec /etc/init.d/agent_manager
            
            if command -v chkconfig >/dev/null 2>&1; then
                chkconfig --add osec >/dev/null 2>&1 || true
                chkconfig --add agent_manager >/dev/null 2>&1 || true
                chkconfig osec on >/dev/null 2>&1 || true
                chkconfig agent_manager on >/dev/null 2>&1 || true
            elif command -v update-rc.d >/dev/null 2>&1; then
                update-rc.d osec defaults >/dev/null 2>&1 || true
                update-rc.d agent_manager defaults >/dev/null 2>&1 || true
            fi
            
            service osec start >/dev/null 2>&1 || { echo "ERROR: osec failed to start!"; exit 1; }
            service agent_manager start >/dev/null 2>&1 || { echo "ERROR: agent_manager failed to start!"; exit 1; }
            echo "osec and agent_manager services started successfully (init.d)."
        else
            cp -f "\$INSTALL_DIR/osec.init" /etc/init.d/osec >/dev/null 2>&1
            cp -f "\$INSTALL_DIR/agent_manager.init" /etc/init.d/agent_manager >/dev/null 2>&1
            chmod +x /etc/init.d/osec /etc/init.d/agent_manager
            
            if command -v chkconfig >/dev/null 2>&1; then
                chkconfig --add osec >/dev/null 2>&1 || true
                chkconfig --add agent_manager >/dev/null 2>&1 || true
                chkconfig osec on >/dev/null 2>&1 || true
                chkconfig agent_manager on >/dev/null 2>&1 || true
            elif command -v update-rc.d >/dev/null 2>&1; then
                update-rc.d osec defaults >/dev/null 2>&1 || true
                update-rc.d agent_manager defaults >/dev/null 2>&1 || true
            fi
            
            service osec restart >/dev/null 2>&1 || { echo "ERROR: osec failed to restart!"; exit 1; }
            # agent_manager 可能还在运行，先尝试 restart，失败则 start
            service agent_manager restart 2>/dev/null || service agent_manager start 2>/dev/null || true
            echo "osec and agent_manager services restarted successfully (init.d)."
        fi
    fi

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
