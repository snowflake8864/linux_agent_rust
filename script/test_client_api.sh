#!/bin/bash
# ============================================================================
# 客户端接口测试脚本 — 仅覆盖交付给客户端/Windows Agent 开发人员的接口
# Proto: common + agent_status + jump + process_policy + peripheral_policy
#        + protection_mode + alert + backup
#
# 用法:
#   ./test_client_api.sh              # 交互式菜单
#   ./test_client_api.sh all          # 测试全部只读接口
#   ./test_client_api.sh write        # 测试写接口（在线应被拒绝）
#   ./test_client_api.sh full         # 测试全部
#   ./test_client_api.sh listen [秒]  # 监听告警流
# ============================================================================

GRPC_ADDR="${GRPC_ADDR:-127.0.0.1:50051}"
PROTO_DIR="$(dirname "$0")/../crates/grpc_gateway/src/proto"
PROTO_DIR="$(cd "$PROTO_DIR" 2>/dev/null && pwd || echo "$PROTO_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

pass=0
fail=0

# ── helpers ────────────────────────────────────────────────────────────

grpc_call() {
    local desc="$1" proto="$2" svc="$3" method="$4" data="${5:-{\}}"
    echo -ne "${CYAN}[TEST]${NC} $desc ... "
    local output
    if output=$(grpcurl -plaintext -emit-defaults \
        -import-path "$PROTO_DIR" \
        -proto common.proto -proto "$proto" \
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

grpc_expect_perm_denied() {
    local desc="$1" proto="$2" svc="$3" method="$4" data="$5"
    echo -ne "${CYAN}[TEST]${NC} $desc ... "
    local output
    if output=$(grpcurl -plaintext -emit-defaults \
        -import-path "$PROTO_DIR" \
        -proto common.proto -proto "$proto" \
        -d "$data" \
        -connect-timeout 3 -max-time 10 \
        "$GRPC_ADDR" "$svc/$method" 2>&1); then
        echo -e "${YELLOW}UNEXPECTED PASS${NC} (预期 PERMISSION_DENIED)"
        echo "$output" | sed 's/^/  /'
        ((fail++))
        return 1
    else
        if echo "$output" | grep -q "PermissionDenied\|在线模式下不允许"; then
            echo -e "${GREEN}PASS${NC} (正确拒绝: 在线模式)"
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
    local desc="$1" proto="$2" svc="$3" method="$4" data="${5:-{\}}" duration="${6:-3}"
    echo -ne "${CYAN}[TEST]${NC} $desc (流式, ${duration}s) ... "
    local output exit_code
    output=$(timeout "$duration" grpcurl -plaintext -emit-defaults \
        -import-path "$PROTO_DIR" \
        -proto common.proto -proto "$proto" \
        -d "$data" \
        -connect-timeout 3 \
        "$GRPC_ADDR" "$svc/$method" 2>&1) && exit_code=0 || exit_code=$?
    if [ "$exit_code" = "124" ] || [ "$exit_code" = "0" ]; then
        if [ -n "$output" ]; then
            echo -e "${GREEN}PASS${NC} (收到事件)"
            echo "$output" | head -20 | sed 's/^/  /'
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
    echo -e "══════════════════════════════════════════════"
    echo -e "  结果: ${GREEN}${pass} 通过${NC} / ${RED}${fail} 失败${NC}"
    echo -e "══════════════════════════════════════════════"
}

# ── 只读接口 ──────────────────────────────────────────────────────────

test_status() { grpc_call "查询Agent状态(含is_online/protection_days) (GetAgentStatus)" \
    agent_status.proto agent_status.AgentStatusService GetAgentStatus; }

test_jump_status() { grpc_call "查询跳变状态 (GetJumpStatus)" \
    jump.proto jump.JumpService GetJumpStatus; }

test_proc_policy() { grpc_call "查询进程策略 (GetProcessPolicy)" \
    process_policy.proto process_policy.ProcessPolicyService GetProcessPolicy; }

test_peri_policy() { grpc_call "查询外设策略 (GetPeripheralPolicy)" \
    peripheral_policy.proto peripheral_policy.PeripheralPolicyService GetPeripheralPolicy; }

test_backup_list() { grpc_call "查询备份列表 (GetBackupList)" \
    backup.proto backup.BackupService GetBackupList; }

test_proc_defense() { grpc_call "查询进程防护模式 (GetProcessDefenseMode)" \
    protection_mode.proto protection_mode.ProcessDefenseService GetProcessDefenseMode; }

test_peri_defense() { grpc_call "查询外设防护模式 (GetPeripheralDefenseMode)" \
    protection_mode.proto protection_mode.PeripheralDefenseService GetPeripheralDefenseMode; }

# ── 流式接口 ──────────────────────────────────────────────────────────

test_alert_all() { stream_test "订阅全部告警 (type=0)" \
    alert.proto alert.AlertService SubscribeAlerts \
    '{"type": 0}' 3; }

test_alert_process() { stream_test "订阅进程告警 (type=1)" \
    alert.proto alert.AlertService SubscribeAlerts \
    '{"type": 1}' 3; }

test_alert_device() { stream_test "订阅外设告警 (type=3)" \
    alert.proto alert.AlertService SubscribeAlerts \
    '{"type": 3}' 3; }

# ── 写接口（在线模式应返回 PERMISSION_DENIED）──────────────────────────

test_w_ip_jump() { grpc_expect_perm_denied "执行IP跳变 (ExecuteIpJump)" \
    jump.proto jump.JumpService ExecuteIpJump \
    '{"gateway":"192.168.1.1","source_ip":"","target_ip":"192.168.1.100/24","mode":1,"allow_size":24,"aging_time":2,"active_time":0}'; }

test_w_pw_jump() { grpc_expect_perm_denied "执行密码跳变 (ExecutePwJump)" \
    jump.proto jump.JumpService ExecutePwJump \
    '{"new_password":"Test@12345"}'; }

test_w_proc_policy() { grpc_expect_perm_denied "更新进程策略 (UpdateProcessPolicy)" \
    process_policy.proto process_policy.ProcessPolicyService UpdateProcessPolicy \
    '{"hash_list":["d41d8cd98f00b204e9800998ecf8427e"],"is_white":true}'; }

test_w_peri_policy() { grpc_expect_perm_denied "更新外设策略 (UpdatePeripheralPolicy)" \
    peripheral_policy.proto peripheral_policy.PeripheralPolicyService UpdatePeripheralPolicy \
    '{"devices":[{"peripheral_eid":"USB001","peripheral_name":"TestUSB","intro":"","type_":"mass_storage","allow":true}],"is_white":true}'; }

test_w_create_backup() { grpc_expect_perm_denied "创建备份 (CreateBackup)" \
    backup.proto backup.BackupService CreateBackup \
    '{"name":"test_backup_0602"}'; }

test_w_restore_backup() { grpc_expect_perm_denied "还原备份 (RestoreBackup)" \
    backup.proto backup.BackupService RestoreBackup \
    '{"backup_id":"00000000-0000-0000-0000-000000000000"}'; }

test_w_proc_defense() { grpc_expect_perm_denied "设置进程防护模式 (UpdateProcessDefenseMode)" \
    protection_mode.proto protection_mode.ProcessDefenseService UpdateProcessDefenseMode \
    '{"mode":2}'; }

test_w_peri_defense() { grpc_expect_perm_denied "设置外设防护模式 (UpdatePeripheralDefenseMode)" \
    protection_mode.proto protection_mode.PeripheralDefenseService UpdatePeripheralDefenseMode \
    '{"mode":1}'; }

# ── 菜单 ──────────────────────────────────────────────────────────────

show_menu() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  客户端接口测试 (对应 client_grpc_api.txt 文档接口)       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  目标: ${GRPC_ADDR}                                  ${CYAN}║${NC}"
    echo -e "${CYAN}╠═══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}只读接口（始终可用）${NC}                                    ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   1) GetAgentStatus          查询Agent状态/在线离线/已保护天数     ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   2) GetJumpStatus           查询跳变状态               ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   3) GetProcessPolicy        查询进程策略               ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   4) GetPeripheralPolicy     查询外设策略               ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   5) GetBackupList           查询备份列表               ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   6) GetProcessDefenseMode   查询进程防护模式           ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   7) GetPeripheralDefenseMode查询外设防护模式           ${CYAN}║${NC}"
    echo -e "${CYAN}╠═══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}流式接口（始终可用）${NC}                                    ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   8) SubscribeAlerts(全部)   订阅所有类型告警           ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   9) SubscribeAlerts(进程)   仅订阅进程告警             ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  10) SubscribeAlerts(外设)   仅订阅外设告警             ${CYAN}║${NC}"
    echo -e "${CYAN}╠═══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${RED}写接口（仅离线可用，在线应返回 PERMISSION_DENIED）${NC}        ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   w1) ExecuteIpJump          执行IP跳变                 ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   w2) ExecutePwJump          执行密码跳变               ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   w3) UpdateProcessPolicy    更新进程策略               ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   w4) UpdatePeripheralPolicy 更新外设策略               ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   w5) CreateBackup           创建备份                   ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   w6) RestoreBackup          还原备份                   ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   w7) UpdateProcessDefense   设置进程防护模式           ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   w8) UpdatePeripheralDefense设置外设防护模式           ${CYAN}║${NC}"
    echo -e "${CYAN}╠═══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  all    测试全部只读接口                                  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  write  测试全部写接口（验证在线拒绝）                    ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  stream 测试全部流式接口                                  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  full   测试全部接口                                      ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  listen [秒] 持续监听告警流（默认300秒）                  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  q      退出                                              ${CYAN}║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

run_all_read() {
    echo -e "\n${GREEN}── 只读接口 ──${NC}"
    test_status
    test_jump_status
    test_proc_policy
    test_peri_policy
    test_backup_list
    test_proc_defense
    test_peri_defense
}

run_all_stream() {
    echo -e "\n${YELLOW}── 流式接口 ──${NC}"
    test_alert_all
    test_alert_process
    test_alert_device
}

run_all_write() {
    echo -e "\n${RED}── 写接口（预期: 在线返回 PERMISSION_DENIED）──${NC}"
    test_w_ip_jump
    test_w_pw_jump
    test_w_proc_policy
    test_w_peri_policy
    test_w_create_backup
    test_w_restore_backup
    test_w_proc_defense
    test_w_peri_defense
}

# ── main ───────────────────────────────────────────────────────────────

case "${1:-menu}" in
    menu|"")
        # 连通性检查
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
            echo -ne "${CYAN}选择 > ${NC}"
            read -r choice
            case "$choice" in
                1) test_status ;;
                2) test_jump_status ;;
                3) test_proc_policy ;;
                4) test_peri_policy ;;
                5) test_backup_list ;;
                6) test_proc_defense ;;
                7) test_peri_defense ;;
                8) test_alert_all ;;
                9) test_alert_process ;;
                10) test_alert_device ;;
                w1) test_w_ip_jump ;;
                w2) test_w_pw_jump ;;
                w3) test_w_proc_policy ;;
                w4) test_w_peri_policy ;;
                w5) test_w_create_backup ;;
                w6) test_w_restore_backup ;;
                w7) test_w_proc_defense ;;
                w8) test_w_peri_defense ;;
                all) run_all_read; print_result ;;
                write) run_all_write; print_result ;;
                stream) run_all_stream; print_result ;;
                full) run_all_read; run_all_stream; run_all_write; print_result ;;
                listen|listen\ *)
                    secs=300
                    [[ "$choice" =~ listen[[:space:]]+([0-9]+) ]] && secs="${BASH_REMATCH[1]}"
                    echo -e "\n${YELLOW}── 监听告警流 ${secs}秒 (Ctrl+C 停止) ──${NC}"
                    timeout "$secs" grpcurl -plaintext -emit-defaults \
                        -import-path "$PROTO_DIR" \
                        -proto common.proto -proto alert.proto \
                        -d '{"type": 0}' \
                        "$GRPC_ADDR" alert.AlertService/SubscribeAlerts 2>&1 || true
                    echo -e "${GREEN}监听结束${NC}"
                    ;;
                q|Q|quit|exit) echo "退出"; break ;;
                *) echo -e "${RED}无效选择: $choice${NC}" ;;
            esac
        done
        ;;
    all) run_all_read; print_result ;;
    write) run_all_write; print_result ;;
    stream) run_all_stream; print_result ;;
    full) run_all_read; run_all_stream; run_all_write; print_result ;;
    listen) 
        echo -e "${YELLOW}监听告警流 ${2:-300}秒 (Ctrl+C 停止)${NC}"
        timeout "${2:-300}" grpcurl -plaintext -emit-defaults \
            -import-path "$PROTO_DIR" \
            -proto common.proto -proto alert.proto \
            -d '{"type": 0}' \
            "$GRPC_ADDR" alert.AlertService/SubscribeAlerts 2>&1 || true
        echo -e "${GREEN}监听结束${NC}"
        ;;
    *)
        echo "用法: $0 [all|write|stream|full|listen [秒]|menu]"
        echo ""
        echo "  无参数   交互式菜单"
        echo "  all     测试全部只读接口 (1-5)"
        echo "  write   测试写接口 (w1-w6, 验证在线拒绝)"
        echo "  stream  测试流式接口 (6-8)"
        echo "  full    全部接口"
        echo "  listen  持续监听告警流"
        exit 1
        ;;
esac
