#!/bin/bash
# ============================================================================
# gRPC 接口测试脚本 — 可手动选择要测试的接口
# 用法:
#   ./test_grpc.sh              # 交互式菜单选择
#   ./test_grpc.sh <编号>        # 直接测试指定接口
#   ./test_grpc.sh all           # 测试全部只读接口
#   ./test_grpc.sh 22             # 设置准入-AUTO
#   ./test_grpc.sh write         # 测试写接口（需离线模式）
#   ./test_grpc.sh stream        # 测试流式接口
# ============================================================================

GRPC_ADDR="${GRPC_ADDR:-127.0.0.1:50051}"
PROTO_DIR="$(dirname "$0")/../crates/grpc_gateway/src/proto"
PROTO_DIR="$(cd "$PROTO_DIR" 2>/dev/null && pwd || echo "$PROTO_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

pass=0
fail=0

# ── helpers ────────────────────────────────────────────────────────────

grpc_call() {
    local desc="$1" proto="$2" svc="$3" method="$4" data="${5:-{\}}" extra_protos="${6:-}"
    local all_protos="common.proto $proto $extra_protos"
    local proto_args=""
    for p in $all_protos; do
        [ -n "$p" ] && proto_args="$proto_args -proto $p"
    done

    echo -ne "${CYAN}[TEST]${NC} $desc ... "
    local output
    if output=$(grpcurl -plaintext -emit-defaults \
        -import-path "$PROTO_DIR" \
        $proto_args \
        -d "$data" \
        -connect-timeout 3 -max-time 10 \
        "$GRPC_ADDR" "$svc/$method" 2>&1); then
        echo -e "${GREEN}PASS${NC}"
        echo "$output" | sed 's/^/  /'
        ((pass++))
        return 0
    else
        echo -e "${RED}FAIL${NC}"
        echo "$output" | sed 's/^/  /'
        ((fail++))
        return 1
    fi
}

grpc_call_raw() {
    # Returns raw output for piping, no PASS/FAIL decoration
    local proto="$1" svc="$2" method="$3" data="${4:-{\}}" extra_protos="${5:-}"
    local all_protos="common.proto $proto $extra_protos"
    local proto_args=""
    for p in $all_protos; do
        [ -n "$p" ] && proto_args="$proto_args -proto $p"
    done
    grpcurl -plaintext -emit-defaults \
        -import-path "$PROTO_DIR" \
        $proto_args \
        -d "$data" \
        -connect-timeout 3 -max-time 10 \
        "$GRPC_ADDR" "$svc/$method" 2>&1
}

grpc_expect_perm_denied() {
    local desc="$1" proto="$2" svc="$3" method="$4" data="$5" extra_protos="${6:-}"
    local all_protos="common.proto $proto $extra_protos"
    local proto_args=""
    for p in $all_protos; do
        [ -n "$p" ] && proto_args="$proto_args -proto $p"
    done

    echo -ne "${CYAN}[TEST]${NC} $desc ... "
    local output
    if output=$(grpcurl -plaintext -emit-defaults \
        -import-path "$PROTO_DIR" \
        $proto_args \
        -d "$data" \
        -connect-timeout 3 -max-time 10 \
        "$GRPC_ADDR" "$svc/$method" 2>&1); then
        echo -e "${YELLOW}UNEXPECTED PASS${NC} (expected PERMISSION_DENIED)"
        ((fail++))
        return 1
    else
        if echo "$output" | grep -q "PermissionDenied\|在线模式下不允许"; then
            echo -e "${GREEN}PASS${NC} (正确拒绝)"
            ((pass++))
            return 0
        else
            echo -e "${RED}FAIL${NC} (错误类型不符)"
            echo "$output" | sed 's/^/  /'
            ((fail++))
            return 1
        fi
    fi
}

stream_test() {
    local desc="$1" proto="$2" svc="$3" method="$4" data="${5:-{\}}" duration="${6:-3}" extra_protos="${7:-}"
    local all_protos="common.proto $proto $extra_protos"
    local proto_args=""
    for p in $all_protos; do
        [ -n "$p" ] && proto_args="$proto_args -proto $p"
    done

    echo -ne "${CYAN}[TEST]${NC} $desc (流, ${duration}s) ... "
    local output exit_code
    output=$(timeout "$duration" grpcurl -plaintext -emit-defaults \
        -import-path "$PROTO_DIR" \
        $proto_args \
        -d "$data" \
        -connect-timeout 3 \
        "$GRPC_ADDR" "$svc/$method" 2>&1) && exit_code=0 || exit_code=$?
    if [ "$exit_code" = "124" ] || [ "$exit_code" = "0" ]; then
        # timeout (124) or clean exit (0) are both OK for streaming
        if [ -n "$output" ]; then
            echo -e "${GREEN}PASS${NC} (收到事件)"
            echo "$output" | sed 's/^/  /'
        else
            echo -e "${GREEN}PASS${NC} (流保持 ${duration}s，无事件 — 正常)"
        fi
        ((pass++))
        return 0
    else
        echo -e "${RED}FAIL${NC} (exit=$exit_code)"
        echo "$output" | sed 's/^/  /'
        ((fail++))
        return 1
    fi
}

print_result() {
    echo ""
    echo -e "=============================================="
    echo -e "  结果: ${GREEN}${pass} 通过${NC} / ${RED}${fail} 失败${NC}"
    echo -e "=============================================="
}

# ── test groups ────────────────────────────────────────────────────────

test_01() { grpc_call "Agent状态(含is_online/protection_days)" \
    agent_status.proto agent_status.AgentStatusService GetAgentStatus; }

test_02() { grpc_call "当前配置" \
    config.proto config.ConfigService GetConfig; }

test_03() { grpc_call "进程策略(白名单)" \
    process_policy.proto process_policy.ProcessPolicyService GetProcessPolicy \
    '{"is_white": 1}'; }

test_03b() { grpc_call "进程策略(黑名单)" \
    process_policy.proto process_policy.ProcessPolicyService GetProcessPolicy \
    '{"is_white": 0}'; }

test_04() { grpc_call "外设策略(白名单)" \
    peripheral_policy.proto peripheral_policy.PeripheralPolicyService GetPeripheralPolicy \
    '{"is_white": 1}'; }

test_04b() { grpc_call "外设策略(黑名单)" \
    peripheral_policy.proto peripheral_policy.PeripheralPolicyService GetPeripheralPolicy \
    '{"is_white": 0}'; }

test_05() { grpc_call "IP阻断策略" \
    ip_policy.proto ip_policy.IpPolicyService GetIpBlockPolicy; }

test_06() { grpc_call "IP黑名单" \
    ip_policy.proto ip_policy.IpPolicyService GetIpBlackPolicy; }

test_07() { grpc_call "外联检测规则" \
    outreach_detect.proto outreach_detect.OutreachDetectService GetOutreachRules; }

test_08() { grpc_call "目录保护策略" \
    dir_policy.proto dir_policy.DirPolicyService GetDirPolicy; }

test_09() { grpc_call "勒索保护策略" \
    extort_policy.proto extort_policy.ExtortPolicyService GetExtortPolicy; }

test_10() { grpc_call "信任目录" \
    trust_dir.proto trust_dir.TrustDirService GetTrustDir; }

test_11() { grpc_call "虚拟端口规则" \
    virtual_port.proto virtual_port.VirtualPortService GetVirtualPort; }

test_12() { grpc_call "备份列表" \
    backup.proto backup.BackupService GetBackupList; }

test_13() { grpc_call "跳变状态" \
    jump.proto jump.JumpService GetJumpStatus; }

test_14() { grpc_call "进程列表(top 10, filter=all)" \
    data_query.proto data_query.DataQueryService GetProcessList \
    '{"limit": 10, "sort_by": "pid", "filter_status": 0}' \
    "peripheral_policy.proto"; }

test_14b() { grpc_call "进程列表(仅白名单)" \
    data_query.proto data_query.DataQueryService GetProcessList \
    '{"limit": 10, "sort_by": "pid", "filter_status": 1}' \
    "peripheral_policy.proto"; }

test_14c() { grpc_call "进程列表(仅黑名单)" \
    data_query.proto data_query.DataQueryService GetProcessList \
    '{"limit": 10, "sort_by": "pid", "filter_status": 2}' \
    "peripheral_policy.proto"; }

test_15() { grpc_call "端口列表" \
    data_query.proto data_query.DataQueryService GetPortList \
    '{}' "peripheral_policy.proto"; }

test_16() { grpc_call "USB设备列表" \
    data_query.proto data_query.DataQueryService GetUsbDeviceList \
    '{}' "peripheral_policy.proto"; }

test_17() { stream_test "策略变更订阅" \
    policy_watch.proto policy_watch.PolicyWatchService SubscribePolicyChanges \
    '{}' 3; }

test_18() { stream_test "告警订阅" \
    alert.proto alert.AlertService SubscribeAlerts \
    '{"type": 0}' 3; }

test_19() { grpc_call "查询准入开关" \
    admission.proto admission.AdmissionService GetAdmissionSwitch \
    '{}' ''; }

# 准入设置: 20=关闭, 21=开启, 22=自动
test_20() { grpc_call "设置准入(关闭/OFF)" \
    admission.proto admission.AdmissionService UpdateAdmissionSwitch \
    '{"mode": 0}' ''; }

test_21() { grpc_call "设置准入(开启/ON)" \
    admission.proto admission.AdmissionService UpdateAdmissionSwitch \
    '{"mode": 1}' ''; }

test_22() { grpc_call "设置准入(自动/AUTO)" \
    admission.proto admission.AdmissionService UpdateAdmissionSwitch \
    '{"mode": 2}' ''; }

# ── write tests (should be denied in online mode) ──────────────────────

test_w1() { grpc_expect_perm_denied "更新配置（在线拒绝）" \
    config.proto config.ConfigService UpdateConfig \
    '{"crontime": 120}'; }

test_w2() { grpc_expect_perm_denied "更新进程策略(在线拒绝)" \
    process_policy.proto process_policy.ProcessPolicyService UpdateProcessPolicy \
    '{"hash_list": ["abc123"], "action": 1}'; }

test_w3() { grpc_expect_perm_denied "更新外设策略(在线拒绝)" \
    peripheral_policy.proto peripheral_policy.PeripheralPolicyService UpdatePeripheralPolicy \
    '{"devices": [], "action": 1}'; }

test_w4() { grpc_expect_perm_denied "更新IP阻断（在线拒绝）" \
    ip_policy.proto ip_policy.IpPolicyService UpdateIpBlockPolicy \
    '{"items": [{"ip": "10.0.0.1", "direction": 1, "duration": 3600, "is_ipv6": false}]}'; }

test_w5() { grpc_expect_perm_denied "下发任务（在线拒绝）" \
    task_local.proto task_local.LocalTaskService SubmitTask \
    '{"task_ids": [6, 19]}'; }

test_w6() { grpc_expect_perm_denied "IP跳变（在线拒绝）" \
    jump.proto jump.JumpService ExecuteIpJump \
    '{"gateway":"192.168.1.1","source_ip":"10.0.0.5","target_ip":"10.0.0.6","mode":1}'; }

test_w7() { grpc_expect_perm_denied "密码跳变（在线拒绝）" \
    jump.proto jump.JumpService ExecutePwJump \
    '{"new_password":"test123"}'; }

test_w8() { grpc_expect_perm_denied "创建备份（在线拒绝）" \
    backup.proto backup.BackupService CreateBackup \
    '{"name":"test_bak"}'; }

test_w9() { grpc_expect_perm_denied "还原备份（在线拒绝）" \
    backup.proto backup.BackupService RestoreBackup \
    '{"backup_id":"abc123"}'; }

test_w10() { grpc_expect_perm_denied "更新信任目录（在线拒绝）" \
    trust_dir.proto trust_dir.TrustDirService UpdateTrustDir \
    '{"dirs": [{"dir":"/opt","type":1,"is_extend":0}]}'; }

test_w11() { grpc_expect_perm_denied "更新虚拟端口（在线拒绝）" \
    virtual_port.proto virtual_port.VirtualPortService UpdateVirtualPort \
    '{"rules": [{"alarm_level":1,"dest_ip":"192.168.1.1","dest_port":"80","dest_port_type":0,"id":1,"protocol":"tcp","source_ip":"10.0.0.1","source_port_start":8080,"source_port_end":8080,"type":"tcp"}]}'; }

test_w12() { grpc_expect_perm_denied "更新目录保护策略（在线拒绝）" \
    dir_policy.proto dir_policy.DirPolicyService UpdateDirPolicy \
    '{"rules": [{"dir":"/opt","pid":0,"typ":1}]}'; }

test_w13() { grpc_expect_perm_denied "更新勒索保护策略（在线拒绝）" \
    extort_policy.proto extort_policy.ExtortPolicyService UpdateExtortPolicy \
    '{"rules": [{"file_type":"doc","typ":1}]}'; }

# ── eBPF 后端检测 ──────────────────────────────────────────────────────

test_ebpf_cap() {
    echo -ne "${CYAN}[CHECK]${NC} eBPF 系统能力检测 ... "
    local ok=true
    local reasons=""

    # 1. 内核版本 >= 5.8
    local kver=$(uname -r | cut -d. -f1,2)
    local kmajor=$(echo "$kver" | cut -d. -f1)
    local kminor=$(echo "$kver" | cut -d. -f2)
    if [ "$kmajor" -lt 5 ] || { [ "$kmajor" -eq 5 ] && [ "$kminor" -lt 8 ]; }; then
        ok=false
        reasons="$reasons\n  内核版本过低: $kver (需要 >= 5.8)"
    fi

    # 2. BTF 支持
    if [ ! -f /sys/kernel/btf/vmlinux ]; then
        ok=false
        reasons="$reasons\n  BTF 不可用: /sys/kernel/btf/vmlinux 不存在"
    fi

    # 3. BPF LSM
    if ! grep -q '\bbpf\b' /sys/kernel/security/lsm 2>/dev/null; then
        ok=false
        reasons="$reasons\n  BPF LSM 未启用: /sys/kernel/security/lsm 不含 bpf"
    fi

    # 4. bpffs
    if ! mount | grep -q 'bpf.*on.*/sys/fs/bpf'; then
        ok=false
        reasons="$reasons\n  bpffs 未挂载到 /sys/fs/bpf"
    fi

    if $ok; then
        echo -e "${GREEN}通过${NC}"
    else
        echo -e "${RED}失败${NC}"
        echo -e "$reasons"
    fi
}

test_23() {
    echo -e "${CYAN}[TEST]${NC} 后端模式查询 (AgentStatus) ... "
    local output
    if output=$(grpcurl -plaintext -emit-defaults \
        -import-path "$PROTO_DIR" \
        -proto common.proto -proto agent_status.proto \
        -d '{}' -connect-timeout 3 -max-time 5 \
        "$GRPC_ADDR" agent_status.AgentStatusService/GetAgentStatus 2>&1); then
        local backend=$(echo "$output" | grep -o '"mod_ver":"[^"]*"' | cut -d'"' -f4)
        if [ -n "$backend" ]; then
            echo -e "  后端版本: ${GREEN}${backend}${NC}"
            if echo "$backend" | grep -q "ebpf"; then
                echo -e "  ${GREEN}当前使用 eBPF 模式${NC}"
            else
                echo -e "  ${YELLOW}当前使用驱动模式${NC}"
            fi
        fi
        ((pass++))
    else
        echo -e "${RED}FAIL${NC}"
        ((fail++))
    fi
}

test_24() { grpc_call "进程策略(只读, eBPF兼容)" \
    process_policy.proto process_policy.ProcessPolicyService GetProcessPolicy '{"is_white": 1}'; }

test_25() { grpc_call "IP阻断策略(只读, eBPF兼容)" \
    ip_policy.proto ip_policy.IpPolicyService GetIpBlockPolicy '{}'; }

test_29() { grpc_call "可执行文件列表" \
    data_query.proto data_query.DataQueryService GetExecutableList \
    '{"filter_status": 0}' "peripheral_policy.proto"; }

test_26() { grpc_call "后端模式查询" \
    backend.proto backend.BackendService GetBackendMode '{}'; }

test_27() { grpc_call "设置后端-ebpf" \
    backend.proto backend.BackendService UpdateBackendMode \
    '{"mode": "ebpf"}'; }

test_28() { grpc_call "设置后端-driver" \
    backend.proto backend.BackendService UpdateBackendMode \
    '{"mode": "driver"}'; }

# ── menu ───────────────────────────────────────────────────────────────

show_menu() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}        gRPC 接口测试脚本                               ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}        目标: ${GRPC_ADDR}                        ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}只读接口（始终可用）${NC}                                  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   1) AgentStatus      9)  ExtortPolicy    17) PolicyWatch(流)${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   2) Config          10)  TrustDir       18) Alert(流)       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   3) ProcessPolicy   11)  VirtualPort    19) 查询准入        ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   4) PeripheralPolicy 12) BackupList     20) 准入-OFF        ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   5) IpBlockPolicy   13)  JumpStatus     21) 准入-ON         ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   6) IpBlackPolicy   14)  ProcessList    22) 准入-AUTO       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   7) OutreachRules   15)  PortList                         ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   8) DirPolicy       16)  UsbDeviceList  29) ExecutableList ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${RED}写接口（仅离线可用，在线应返回 PERMISSION_DENIED）${NC}       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   w1) UpdateConfig   w2) UpdateProcessPolicy              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   w3) UpdatePeripheral w4) UpdateIpBlockPolicy            ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   w5) SubmitTask     w6) ExecuteIpJump                    ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   w7) ExecutePwJump  w8) CreateBackup                     ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   w9) RestoreBackup  w10) UpdateTrustDir                  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   w11) UpdateVirtualPort w12) UpdateDirPolicy                ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   w13) UpdateExtortPolicy                                  ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}all${NC}  测试全部只读接口                                  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${RED}write${NC} 测试全部写接口（验证在线拒绝）                    ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}stream${NC} 测试全部流式接口                                ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}full${NC}  测试全部接口（读写+流）                          ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}listen [秒]${NC} 监听告警流（默认300秒，Ctrl+C停止）    ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}eBPF 专项:${NC}                                          ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   cap) eBPF能力检测    23) 后端状态查询               ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   24) 进程策略(eBPF)  25) IP阻断(eBPF)                ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   26) 查询后端模式    27) 设置ebpf    28) 设置driver   ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  q    退出                                              ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ── main ───────────────────────────────────────────────────────────────

case "${1:-menu}" in
    menu|"")
        # Check connectivity
        if ! grpcurl -plaintext -emit-defaults -import-path "$PROTO_DIR" \
            -proto common.proto -proto agent_status.proto \
            -d '{}' -connect-timeout 2 -max-time 3 \
            "$GRPC_ADDR" agent_status.AgentStatusService/GetAgentStatus >/dev/null 2>&1; then
            echo -e "${RED}错误: 无法连接 gRPC 服务 ($GRPC_ADDR)${NC}"
            echo "请确认 Agent 已启动且 gRPC 端口已监听"
            exit 1
        fi

        show_menu
        while true; do
            echo -ne "${CYAN}选择接口编号 > ${NC}"
            read -r choice
            case "$choice" in
                1)  test_01 ;;
                2)  test_02 ;;
                3)  test_03 ;;
                4)  test_04 ;;
                5)  test_05 ;;
                6)  test_06 ;;
                7)  test_07 ;;
                8)  test_08 ;;
                9)  test_09 ;;
                10) test_10 ;;
                11) test_11 ;;
                12) test_12 ;;
                13) test_13 ;;
                14) test_14 ;;
                15) test_15 ;;
                16) test_16 ;;
                17) test_17 ;;
                18) test_18 ;;
                19) test_19 ;;
                20) test_20 ;;
                21) test_21 ;;
                22) test_22 ;;
                w1) test_w1 ;;
                w2) test_w2 ;;
                w3) test_w3 ;;
                w4) test_w4 ;;
                w5) test_w5 ;;
                w6) test_w6 ;;
                w7) test_w7 ;;
                w8) test_w8 ;;
                w9) test_w9 ;;
                w10) test_w10 ;;
                w11) test_w11 ;; w12) test_w12 ;; w13) test_w13 ;;
                cap) test_ebpf_cap ;;
                23) test_23 ;;
                24) test_24 ;;
                25) test_25 ;;
                26) test_26 ;;
                27) test_27 ;;
                28) test_28 ;;
                29) test_29 ;;
                all)
                    echo -e "\n${GREEN}── 测试全部只读接口 ──${NC}"
                    for i in $(seq 1 28); do test_0$i 2>/dev/null || test_$i 2>/dev/null; done
                    test_29
                    print_result
                    ;;
                write)
                    echo -e "\n${RED}── 测试全部写接口（预期全部 PERMISSION_DENIED）──${NC}"
                    test_w1; test_w2; test_w3; test_w4; test_w5; test_w6; test_w7; test_w8; test_w9; test_w10; test_w11; test_w12; test_w13
                    print_result
                    ;;
                stream)
                    echo -e "\n${YELLOW}── 测试全部流式接口 ──${NC}"
                    test_17; test_18
                    print_result
                    ;;
                listen|listen\ *)
                    local secs=300
                    [[ "$choice" =~ listen[[:space:]]+([0-9]+) ]] && secs="${BASH_REMATCH[1]}"
                    echo -e "\n${YELLOW}── 监听告警流 ${secs}秒 (Ctrl+C 停止) ──${NC}"
                    timeout "$secs" grpcurl -plaintext -emit-defaults \
                        -import-path "$PROTO_DIR" \
                        -proto common.proto -proto alert.proto \
                        -d '{"type": 0}' \
                        "$GRPC_ADDR" alert.AlertService/SubscribeAlerts 2>&1 || true
                    echo -e "${GREEN}监听结束${NC}"
                    ;;
                full)
                    echo -e "\n${GREEN}── 测试全部接口 ──${NC}"
                    for i in $(seq 1 28); do test_0$i 2>/dev/null || test_$i 2>/dev/null; done
                    test_17; test_18
                    test_w1; test_w2; test_w3; test_w4; test_w5; test_w6; test_w7; test_w8; test_w9; test_w10; test_w11; test_w12; test_w13
                    print_result
                    ;;
	                \?|h|help)
	                    echo ""
	                    echo -e "${CYAN}── 只读接口 ──${NC}"
	                    echo "   1) AgentStatus       2) Config"
	                    echo "   3) ProcessPolicy     4) PeripheralPolicy"
	                    echo "   5) IpBlockPolicy     6) IpBlackPolicy"
	                    echo "   7) OutreachRules     8) DirPolicy"
	                    echo "   9) ExtortPolicy     10) TrustDir"
	                    echo "  11) VirtualPort      12) BackupList"
	                    echo "  13) JumpStatus       14) ProcessList"
	                    echo "  15) PortList         16) UsbDeviceList"
	                    echo "  17) PolicyWatch(流)  18) Alert(流)"
	                    echo "  19) 查询准入         20) 准入-OFF"
	                    echo "  21) 准入-ON          22) 准入-AUTO"
	                    echo ""
	                    echo -e "${CYAN}── 写接口（仅离线可用）──${NC}"
	                    echo "  w1) UpdateConfig       w2) UpdateProcessPolicy"
	                    echo "  w3) UpdatePeripheral   w4) UpdateIpBlockPolicy"
	                    echo "  w5) SubmitTask         w6) ExecuteIpJump"
	                    echo "  w7) ExecutePwJump      w8) CreateBackup"
	                    echo "  w9) RestoreBackup    w10) UpdateTrustDir"
	                    echo "  w11) UpdateVirtualPort  w12) UpdateDirPolicy"
	                    echo "  w13) UpdateExtortPolicy"
	                    echo ""
	                    echo -e "${CYAN}── 快捷命令 ──${NC}"
	                    echo "  all    测试全部只读    write   测试全部写"
	                    echo "  stream 测试全部流式    full    测试全部"
	                    echo "  ?|h    显示此帮助     q       退出"
	                    echo ""
	                    ;;
                q|Q|quit|exit) echo "退出"; break ;;
		*) echo -e "${RED}无效选择: $choice${NC} (输入 ? 查看帮助)" ;;
            esac
        done
        ;;

    # Direct invocation mode
    all)
        for i in $(seq 1 22); do test_0$i 2>/dev/null || test_$i 2>/dev/null; done
        print_result
        ;;
    write)
        test_w1; test_w2; test_w3; test_w4; test_w5; test_w6; test_w7; test_w8; test_w9; test_w10; test_w11; test_w12; test_w13
        print_result
        ;;
    stream)
        test_17; test_18
        print_result
        ;;
    listen)
        echo -e "${YELLOW}监听告警流 ${2:-300}秒 (Ctrl+C 停止)${NC}"
        timeout "${2:-300}" grpcurl -plaintext -emit-defaults \
            -import-path "$PROTO_DIR" \
            -proto common.proto -proto alert.proto \
            -d '{"type": 0}' \
            "$GRPC_ADDR" alert.AlertService/SubscribeAlerts 2>&1 || true
        echo -e "${GREEN}监听结束${NC}"
        ;;
    full)
        for i in $(seq 1 22); do test_0$i 2>/dev/null || test_$i 2>/dev/null; done
        test_17; test_18
        test_w1; test_w2; test_w3; test_w4; test_w5; test_w6; test_w7; test_w8; test_w9; test_w10; test_w11; test_w12; test_w13
        print_result
        ;;
    ?|help|-h|--help)
        echo "用法: $0 [选项]"
        echo ""
        echo "  无参数          交互式菜单"
        echo "  ?|help|-h      显示此帮助"
        echo "  all            测试全部只读接口 (1-22)"
        echo "  write          测试全部写接口 (w1-w13, 需离线模式)"
        echo "  stream          测试流式接口 (17-18)"
        echo "  full            测试全部接口（读写+流）"
        echo "  listen [秒]     监听告警流（默认300秒, Ctrl+C停止）"
        echo "  1-22            测试指定编号的接口"
        echo "  w1-w13          测试指定编号的写接口"
        echo "  menu            显示交互式菜单"
        echo ""
        echo "示例:"
        echo "  $0              进入交互式菜单"
        echo "  $0 1            直接测试 AgentStatus"
        echo "  $0 all          测试全部只读接口"
        echo "  $0 write        测试全部写接口"
        echo "  $0 listen 60    监听告警流60秒"
        echo ""
        echo "配置:"
        echo "  GRPC_ADDR        目标地址（默认 127.0.0.1:50051）"
        echo "  PROTO_DIR        proto 文件目录（自动检测）"
        ;;

    *)
        # Treat as a number: run that specific test
        if [[ "$choice" =~ ^w[1-9]$ ]] || [[ "$choice" =~ ^w1[0-3]$ ]]; then
            "test_$choice"
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le 22 ]; then
            "test_$(printf '%02d' "$choice")"
        else
            echo "无效参数: $1"
            echo "用法: $0 [?|help|all|write|stream|full|listen|<1-22>|w1-w13|menu]"
            echo "试试: $0 ?  查看完整帮助"
            exit 1
        fi
        print_result
        ;;
esac
