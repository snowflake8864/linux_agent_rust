%define __strip /bin/true
%define _binaries_in_noarch_packages_terminate_build 0

Name: osec
Version: 3.0.1
Release: R8_B2
Summary: OSEC Linux Security Agent
License: Proprietary
Group: System/Security
BuildArch: noarch
AutoReqProv: no
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
Source0: package.tar.gz

%description
OSEC is a Linux security agent providing kernel-level protection and monitoring.

%prep
%setup -c package

%build
# No build step, binaries are pre-built

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/opt/osec
mkdir -p %{buildroot}/opt/osec/log
mkdir -p %{buildroot}/opt/osec/certs
mkdir -p %{buildroot}/etc/init.d

# Copy files from extracted package
cp -rf package/opt/osec/* %{buildroot}/opt/osec/
cp -f package/opt/osec/osec.init %{buildroot}/etc/init.d/osec
cp -f package/opt/osec/agent_manager.init %{buildroot}/etc/init.d/agent_manager

# Set permissions
chmod 755 %{buildroot}/opt/osec -R
chmod +x %{buildroot}/etc/init.d/osec
chmod +x %{buildroot}/etc/init.d/agent_manager

# Install systemd service files
mkdir -p %{buildroot}/usr/lib/systemd/system
cp -f package/opt/osec/osec.service %{buildroot}/usr/lib/systemd/system/
cp -f package/opt/osec/agent_manager.service %{buildroot}/usr/lib/systemd/system/

%files
%defattr(-,root,root,-)
/opt/osec/*
/etc/init.d/osec
/etc/init.d/agent_manager
/usr/lib/systemd/system/osec.service
/usr/lib/systemd/system/agent_manager.service

%post
# Post-install script
# Set ownership
chown -R root:root /opt/osec

# Similar to install logic
ARCH=$(uname -m)
case $ARCH in
    x86_64|amd64)       BIN_DIR="x86_64-unknown-linux-musl" ;;
    aarch64|arm64)      BIN_DIR="aarch64-unknown-linux-musl" ;;
    mips64)             BIN_DIR="mips64el-unknown-linux-gnuabi64" ;;
    loongarch64)        BIN_DIR="loongarch64-unknown-linux-musl" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

INSTALL_DIR="/opt/osec"

# Deploy binaries
if [ -f "$INSTALL_DIR/$BIN_DIR/MagicArmor_0" ]; then
    cp -f "$INSTALL_DIR/$BIN_DIR/MagicArmor_0" "$INSTALL_DIR/MagicArmor_0"
    chmod +x "$INSTALL_DIR/MagicArmor_0"
else
    echo "ERROR: MagicArmor_0 binary missing!"
    exit 1
fi

# Deploy kernel module
COPIED_ANY=0
for f in "$INSTALL_DIR/$BIN_DIR"/osec_base.ko-*; do
    if [ -f "$f" ]; then
        cp -f "$f" "$INSTALL_DIR/"
        chmod 644 "$INSTALL_DIR/$(basename "$f")"
        COPIED_ANY=1
    fi
done

if [ "$COPIED_ANY" = "0" ]; then
    echo "WARNING: No kernel module found for $ARCH"
fi

# Deploy agent_manager
if [ -f "$INSTALL_DIR/$BIN_DIR/MagicArmorAgent" ]; then
    cp -f "$INSTALL_DIR/$BIN_DIR/MagicArmorAgent" "$INSTALL_DIR/MagicArmorAgent"
    chmod +x "$INSTALL_DIR/MagicArmorAgent"
fi

# Handle external config.ini - update net_info.ini (VERSION by external script)
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
    NEW_USERID=$(sed -nr 's/^[[:space:]]*USER_ID[[:space:]]*=(.*)$/\1/p' /opt/config.ini | tr -d '\r')
    
    TARGET_FILE="$INSTALL_DIR/net_info.ini"
    if [ -f "$TARGET_FILE" ]; then
        sed -i "s|^[[:space:]]*SERVER_IP[[:space:]]*=.*|SERVER_IP=$NEW_IP|" "$TARGET_FILE"
        sed -i "s|^[[:space:]]*SERVER_PORT[[:space:]]*=.*|SERVER_PORT=$NEW_PORT|" "$TARGET_FILE"
        sed -i "s|^[[:space:]]*USER_ID[[:space:]]*=.*|USER_ID=$NEW_USERID|" "$TARGET_FILE"
        sed -i "s|^[[:space:]]*SERVERIPPORT[[:space:]]*=.*|SERVERIPPORT=https://$NEW_IP:$NEW_PORT|" "$TARGET_FILE"
    fi
fi

# Setup services using systemd
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable osec >/dev/null 2>&1 || true
    systemctl enable agent_manager >/dev/null 2>&1 || true
    systemctl start osec >/dev/null 2>&1 || true
    systemctl start agent_manager >/dev/null 2>&1 || true
elif command -v chkconfig >/dev/null 2>&1; then
    chkconfig --add osec >/dev/null 2>&1 || true
    chkconfig --add agent_manager >/dev/null 2>&1 || true
    chkconfig osec on >/dev/null 2>&1 || true
    chkconfig agent_manager on >/dev/null 2>&1 || true
    service osec start >/dev/null 2>&1 || true
    service agent_manager start >/dev/null 2>&1 || true
elif command -v update-rc.d >/dev/null 2>&1; then
    update-rc.d osec defaults >/dev/null 2>&1 || true
    update-rc.d agent_manager defaults >/dev/null 2>&1 || true
    service osec start >/dev/null 2>&1 || true
    service agent_manager start >/dev/null 2>&1 || true
fi

# Cleanup arch dirs
rm -rf "$INSTALL_DIR/x86_64-unknown-linux-musl" \
       "$INSTALL_DIR/aarch64-unknown-linux-musl" \
       "$INSTALL_DIR/mips64el-unknown-linux-gnuabi64" \
       "$INSTALL_DIR/loongarch64-unknown-linux-musl"

%preun
# Pre-uninstall script
if [ "$1" = "0" ]; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop osec >/dev/null 2>&1 || true
        systemctl stop agent_manager >/dev/null 2>&1 || true
    else
        service osec stop >/dev/null 2>&1 || true
        service agent_manager stop >/dev/null 2>&1 || true
    fi
fi

%postun
# Post-uninstall script
if [ "$1" = "0" ]; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable osec >/dev/null 2>&1 || true
        systemctl disable agent_manager >/dev/null 2>&1 || true
        rm -f /usr/lib/systemd/system/osec.service
        rm -f /usr/lib/systemd/system/agent_manager.service
        systemctl daemon-reload
    fi
    rm -rf /opt/osec
    rm -f /etc/init.d/osec
    rm -f /etc/init.d/agent_manager
elif [ "$1" = "1" ]; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl start osec >/dev/null 2>&1 || true
        systemctl start agent_manager >/dev/null 2>&1 || true
    fi
fi
