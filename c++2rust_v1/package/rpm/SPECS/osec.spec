
Summary: osec
Name: osec
Version: %VERSION
Source: $RPM_SOURCE_DIR/
Release: %RELEASE
Vendor: osec company
License: copyright to osec
Group: Application/system
Requires: net-tools

%description
osec

%prep

%pre
    # 升级时先停止旧服务
    if [ "$1" = "2" ]; then
        # 停止 systemd 服务
        systemctl stop osec 2>/dev/null || true
        systemctl stop osec.service 2>/dev/null || true
        systemctl stop agent_manager 2>/dev/null || true
        systemctl stop agent_manager.service 2>/dev/null || true
        systemctl stop osec_cli 2>/dev/null || true
        systemctl stop MagicArmor_cli 2>/dev/null || true

        # 杀掉所有旧进程
        pkill -9 MagicArmor 2>/dev/null || true
        pkill -9 osecmonitor 2>/dev/null || true
        pkill -9 MagicArmorAgent 2>/dev/null || true
        pkill -9 agent_manager 2>/dev/null || true
        pkill -9 MagicArmor_cli 2>/dev/null || true
        pkill -9 osec_cli 2>/dev/null || true
        pkill -9 osecservicecentos 2>/dev/null || true

        sleep 2
    fi

%clean

%files
%attr(0644,root,root) /opt/osec
%dir /opt/osec/*

%post
    touch /opt/osec/.osec.txt
    chmod 777 /opt/osec/* -R >/dev/null 2>&1 || true
    chmod 644 /opt/osec/*.service -R >/dev/null 2>&1 || true

#    if [ -f /opt/osec/net_info.ini ]; then
#        cp -f /opt/osec/net_info.ini /var/log/net_info.ini
#    fi

    # 读取配置：从当前目录读取 config.ini
    if [ -f ./config.ini ]; then
        ip=$(grep URL ./config.ini | awk -F '=' '{print $2}')
        port=$(grep PORT ./config.ini | awk -F '=' '{print $2}')
        userid=$(grep USER_ID ./config.ini | awk -F '=' '{print $2}')
        
        sed -i "s|^SERVER_IP=.*|SERVER_IP=$ip|" /opt/osec/net_info.ini
        sed -i "s|^SERVER_PORT=.*|SERVER_PORT=$port|" /opt/osec/net_info.ini
        sed -i "s|^USER_ID=.*|USER_ID=$userid|" /opt/osec/net_info.ini
        sed -i "s|^SERVERIPPORT=.*|SERVERIPPORT=$ip:$port|" /opt/osec/net_info.ini
    fi

    # 清理旧的 systemd 服务
    rm -f /usr/lib/systemd/system/osec.service 2>/dev/null || true
    rm -f /lib/systemd/system/osec.service 2>/dev/null || true
    rm -f /etc/systemd/system/osec.service 2>/dev/null || true
    rm -f /usr/lib/systemd/system/agent_manager.service 2>/dev/null || true
    rm -f /lib/systemd/system/agent_manager.service 2>/dev/null || true
    rm -f /etc/systemd/system/agent_manager.service 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true

    # 清理老版本残留
    pkill -9 -f osecmonitor 2>/dev/null || true
    if [ -f /etc/init.d/osecservicecentos ]; then
        chkconfig --del osecservicecentos 2>/dev/null || true
        rm -f /etc/init.d/osecservicecentos
    fi
    rm -f /opt/osec/osecmonitor 2>/dev/null || true
    rm -f /var/run/osec.pid 2>/dev/null || true

    # 优先使用 systemd（如果可用），否则使用 init.d + 监控脚本
    if [ -d /run/systemd/system ]; then
        # 使用 systemd
        cp -f /opt/osec/osec.service /etc/systemd/system/osec.service
        cp -f /opt/osec/agent_manager.service /etc/systemd/system/agent_manager.service
        chmod 644 /etc/systemd/system/osec.service /etc/systemd/system/agent_manager.service
        systemctl daemon-reload
        systemctl enable osec agent_manager
        systemctl start osec agent_manager

        # systemd 环境不需要 monitor 脚本，删除
        rm -f /opt/osec/osec.monitor 2>/dev/null || true
        rm -f /opt/osec/agent_manager.monitor 2>/dev/null || true
        rm -f /opt/osec/osec.init 2>/dev/null || true
        rm -f /opt/osec/agent_manager.init 2>/dev/null || true
    else
        # 使用 init.d，监控脚本放在 /opt/osec 下由 init.d 调用
        cp -f /opt/osec/osec.init /etc/init.d/osec
        cp -f /opt/osec/agent_manager.init /etc/init.d/agent_manager
        chmod +x /etc/init.d/osec /etc/init.d/agent_manager

        # 添加开机启动
        if command -v chkconfig &> /dev/null; then
            chkconfig --add osec
            chkconfig --add agent_manager
            chkconfig osec on
            chkconfig agent_manager on
        elif command -v update-rc.d &> /dev/null; then
            update-rc.d osec defaults
            update-rc.d agent_manager defaults
        fi

        # 启动服务
        service osec start || /etc/init.d/osec start
        service agent_manager start || /etc/init.d/agent_manager start
    fi

%preun
    # 忽略错误，确保升级继续进行
    exit 0

%postun
    # 忽略错误，确保升级继续进行
    exit 0
    
    pkill -10 MagicArmor 2>/dev/null || true
    pkill -9 MagicArmor_0 2>/dev/null || true
    pkill -9 osecmonitor 2>/dev/null || true
    pkill -9 MagicArmorAgent 2>/dev/null || true
    pkill -9 MagicArmor_cli 2>/dev/null || true
    pkill -9 osec_cli 2>/dev/null || true

    sleep 2
    rmmod -f osec_base 2>/dev/null || true

    rm -rf /opt/osec/log 2>/dev/null || true
    rm -rf /opt/osec/osec_log.db 2>/dev/null || true
    rm -f /var/log/myosec.pid 2>/dev/null || true
    rm -f /tmp/.osec_cli.sock 2>/dev/null || true
    rm -f /tmp/.osec_cli.pid 2>/dev/null || true
    rm -rf /opt/osec 2>/dev/null || true

    # 清理 systemd 服务
    rm -f /usr/lib/systemd/system/osec.service 2>/dev/null || true
    rm -f /lib/systemd/system/osec.service 2>/dev/null || true
    rm -f /etc/systemd/system/osec.service 2>/dev/null || true
    rm -f /usr/lib/systemd/system/agent_manager.service 2>/dev/null || true
    rm -f /lib/systemd/system/agent_manager.service 2>/dev/null || true
    rm -f /etc/systemd/system/agent_manager.service 2>/dev/null || true
    rm -f /usr/lib/systemd/system/osec_cli.service 2>/dev/null || true
    rm -f /lib/systemd/system/osec_cli.service 2>/dev/null || true
    rm -f /etc/systemd/system/osec_cli.service 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true

    # 清理 init.d
    rm -f /etc/init.d/osec 2>/dev/null || true
    rm -f /etc/init.d/agent_manager 2>/dev/null || true
    rm -f /etc/init.d/osecservicecentos 2>/dev/null || true

    exit 0
