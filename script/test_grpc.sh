#!/bin/bash
# ============================================================================
# gRPC 接口测试脚本 — 可手动选择要测试的接口
# 用法:
#   ./test_grpc.sh              # 交互式菜单选择
#   ./test_grpc.sh <编号>        # 直接测试指定接口
#   ./test_grpc.sh all           # 测试全部只读接口
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
    if output=$(grpcurl -plaintext \
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
    grpcurl -plaintext \
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
    if output=$(grpcurl -plaintext \
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
    output=$(timeout "$duration" grpcurl -plaintext \
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

test_01() { grpc_call "Agent状态" \
    agent_status.proto agent_status.AgentStatusService GetAgentStatus; }

test_02() { grpc_call "当前配置" \
    config.proto config.ConfigService GetConfig; }

test_03() { grpc_call "进程策略" \
    process_policy.proto process_policy.ProcessPolicyService GetProcessPolicy; }

test_04() { grpc_call "外设策略" \
    peripheral_policy.proto peripheral_policy.PeripheralPolicyService GetPeripheralPolicy; }

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

test_14() { grpc_call "进程列表(top 10)" \
    data_query.proto data_query.DataQueryService GetProcessList \
    '{"limit": 10, "sort_by": "pid"}' \
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

# ── write tests (should be denied in online mode) ──────────────────────

test_w1() { grpc_expect_perm_denied "更新配置（在线拒绝）" \
    config.proto config.ConfigService UpdateConfig \
    '{"crontime": 120}'; }

test_w2() { grpc_expect_perm_denied "更新进程策略（在线拒绝）" \
    process_policy.proto process_policy.ProcessPolicyService UpdateProcessPolicy \
    '{"hash_list": ["abc123"], "is_white": true}'; }

test_w3() { grpc_expect_perm_denied "更新外设策略（在线拒绝）" \
    peripheral_policy.proto peripheral_policy.PeripheralPolicyService UpdatePeripheralPolicy \
    '{"devices": [], "is_white": true}'; }

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
    echo -e "${CYAN}║${NC}   3) ProcessPolicy   11)  VirtualPort                       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   4) PeripheralPolicy 12) BackupList                        ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   5) IpBlockPolicy   13)  JumpStatus                       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   6) IpBlackPolicy   14)  ProcessList                      ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   7) OutreachRules   15)  PortList                         ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   8) DirPolicy       16)  UsbDeviceList                    ${CYAN}║${NC}"
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
    echo -e "${CYAN}║${NC}  q    退出                                              ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ── main ───────────────────────────────────────────────────────────────

case "${1:-menu}" in
    menu|"")
        # Check connectivity
        if ! grpcurl -plaintext -import-path "$PROTO_DIR" \
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
                all)
                    echo -e "\n${GREEN}── 测试全部只读接口 ──${NC}"
                    for i in $(seq 1 16); do test_0$i 2>/dev/null || test_$i 2>/dev/null; done
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
                    timeout "$secs" grpcurl -plaintext \
                        -import-path "$PROTO_DIR" \
                        -proto common.proto -proto alert.proto \
                        -d '{"type": 0}' \
                        "$GRPC_ADDR" alert.AlertService/SubscribeAlerts 2>&1 || true
                    echo -e "${GREEN}监听结束${NC}"
                    ;;
                full)
                    echo -e "\n${GREEN}── 测试全部接口 ──${NC}"
                    for i in $(seq 1 16); do test_0$i 2>/dev/null || test_$i 2>/dev/null; done
                    test_17; test_18
                    test_w1; test_w2; test_w3; test_w4; test_w5; test_w6; test_w7; test_w8; test_w9; test_w10; test_w11; test_w12; test_w13
                    print_result
                    ;;
                q|Q|quit|exit) echo "退出"; break ;;
                *) echo -e "${RED}无效选择: $choice${NC}" ;;
            esac
        done
        ;;

    # Direct invocation mode
    all)
        for i in $(seq 1 16); do test_0$i 2>/dev/null || test_$i 2>/dev/null; done
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
        timeout "${2:-300}" grpcurl -plaintext \
            -import-path "$PROTO_DIR" \
            -proto common.proto -proto alert.proto \
            -d '{"type": 0}' \
            "$GRPC_ADDR" alert.AlertService/SubscribeAlerts 2>&1 || true
        echo -e "${GREEN}监听结束${NC}"
        ;;
    full)
        for i in $(seq 1 16); do test_0$i 2>/dev/null || test_$i 2>/dev/null; done
        test_17; test_18
        test_w1; test_w2; test_w3; test_w4; test_w5; test_w6; test_w7; test_w8; test_w9; test_w10; test_w11; test_w12; test_w13
        print_result
        ;;
    *)
        # Treat as a number: run that specific test
        if [[ "$choice" =~ ^w[1-5]$ ]]; then
            "test_$choice"
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le 18 ]; then
            "test_$(printf '%02d' "$choice")"
        else
            echo "用法: $0 [all|write|stream|full|<1-18>|w1-w5|menu]"
            echo ""
            echo "  无参数    交互式菜单"
            echo "  all      测试全部只读接口 (1-16)"
            echo "  write    测试全部写接口 (w1-w5)"
            echo "  stream   测试流式接口 (17-18)"
            echo "  full     测试全部接口"
            echo "  1-18     测试指定编号的只读接口"
            echo "  w1-w5    测试指定编号的写接口"
            echo "  menu     显示交互式菜单"
            exit 1
        fi
        print_result
        ;;
esac
