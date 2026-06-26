#!/bin/bash
# ============================================================================
# gRPC 接口测试脚本 — 可手动选择要测试的接口
# 用法:
#   ./test_grpc.sh              # 交互式菜单选择
#   ./test_grpc.sh <编号>        # 直接测试指定接口 (1-28, s1)
#   ./test_grpc.sh all           # 测试全部只读接口 (1-28)
#   ./test_grpc.sh write         # 测试写接口（需离线模式）
#   ./test_grpc.sh stream        # 测试流式接口 (17, 18, s1)
#   ./test_grpc.sh full          # 测试全部接口（读写+流）
#   ./test_grpc.sh listen [秒]   # 监听告警流
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
    local desc="$1" proto="$2" svc="$3" method="$4" data="${5:-{\}}" extra_protos="${6:-}" max_time="${7:-10}"
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
        -connect-timeout 3 -max-time "$max_time" \
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

# ── 只读接口测试 (1-28) ─────────────────────────────────────────────────

test_01() { grpc_call "Agent状态(含is_online/protection_days)" \
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

test_13() { grpc_call "跳变状态(读内存缓存,不请求服务器)" \
    jump.proto jump.JumpService GetJumpStatus; }

test_14() { grpc_call "进程列表(top 10, 按PID排序)" \
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

test_18() { stream_test "告警订阅(全部类型)" \
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

test_23() { grpc_call "可执行文件列表(含策略状态,MD5去重)" \
    data_query.proto data_query.DataQueryService GetExecutableList \
    '{}' "peripheral_policy.proto" 60; }

test_24() { grpc_call "漏洞扫描上报(测试数据)" \
    vuln_scan.proto vuln_scan.VulnScanService PutVulnScan \
    '{"start_at":"2026-06-02 09:00:00","end_at":"2026-06-02 09:01:00","vuln_total":1,"vuln_list":[{"title":"CVE-TEST","severity":"LOW","file_path":"/usr/bin/test"}]}'; }

# 历史告警日志查询(分页)：客户端初始化时调用一次补读历史，随后用 SubscribeAlerts 接收新告警
test_25() { grpc_call "历史告警日志(全部/分页)" \
    alert.proto alert.AlertService GetAlertLogs \
    '{"handle_status": -1, "page": 1, "page_size": 20}'; }

test_26() { grpc_call "历史告警日志(未处理)" \
    alert.proto alert.AlertService GetAlertLogs \
    '{"handle_status": 0, "page": 1, "page_size": 20}'; }

# 告警处置：标记为已处理(handle_status=1)
test_27() { grpc_call "告警处置(标记已处理)" \
    alert.proto alert.AlertService HandleAlert \
    '{"id": 1, "handle_status": 1, "handle_user": "admin"}'; }

# 告警处置：标记为已忽略(handle_status=2)
test_28() { grpc_call "告警处置(标记已忽略)" \
    alert.proto alert.AlertService HandleAlert \
    '{"id": 1, "handle_status": 2, "handle_user": "admin"}'; }

# ── 流式接口测试 ────────────────────────────────────────────────────────

# 病毒扫描双向流 — 发 StartScanRequest 并等待响应，测连通性
test_s1() {
    local desc="病毒扫描-启动测连通性(VirusScan/StreamControl)"
    echo -ne "${CYAN}[TEST]${NC} $desc ... "
    local output exit_code
    output=$(echo '{"start_scan":{"target":"/tmp","include_script":false,"full_disk":false}}' | \
        timeout 6 grpcurl -plaintext -emit-defaults \
        -import-path "$PROTO_DIR" \
        -proto common.proto -proto virus_scan.proto \
        -d @ \
        -connect-timeout 3 \
        "$GRPC_ADDR" virus_scan.VirusScanService/StreamControl 2>&1) && exit_code=0 || exit_code=$?
    if [ "$exit_code" = "124" ] || [ "$exit_code" = "0" ]; then
        echo -e "${GREEN}PASS${NC}"
        echo "$output" | sed 's/^/  /'
        ((pass++))
    else
        echo -e "${RED}FAIL${NC} (exit=$exit_code)"
        echo "$output" | sed 's/^/  /'
        ((fail++))
    fi
}

# ── 写接口测试（在线应全部返回 PERMISSION_DENIED）─────────────────────

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

test_w6() { grpc_expect_perm_denied "IP跳变（在线拒绝;成功后自动刷新jump.db）" \
    jump.proto jump.JumpService ExecuteIpJump \
    '{"gateway":"192.168.1.1","source_ip":"10.0.0.5","target_ip":"10.0.0.6","mode":1}'; }

test_w7() { grpc_expect_perm_denied "密码跳变（在线拒绝;成功后自动刷新jump.db）" \
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

test_w14() { grpc_expect_perm_denied "进程防护模式（在线拒绝）" \
    protection_mode.proto protection_mode.ProcessDefenseService UpdateProcessDefenseMode \
    '{"mode": 2}'; }

test_w15() { grpc_expect_perm_denied "外设防护模式（在线拒绝）" \
    protection_mode.proto protection_mode.PeripheralDefenseService UpdatePeripheralDefenseMode \
    '{"mode": 2}'; }

test_w16() { grpc_expect_perm_denied "删除备份（在线拒绝）" \
    backup.proto backup.BackupService DeleteBackup \
    '{"backup_id":"test_bak"}'; }

# ── 菜单 ───────────────────────────────────────────────────────────────

show_menu() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}        gRPC 接口测试脚本                               ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}        目标: ${GRPC_ADDR}                        ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}只读接口（始终可用）${NC}                                  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   1) AgentStatus      9)  ExtortPolicy    17) PolicyWatch(流)${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   2) Config          10)  TrustDir        18) Alert(流)       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   3) ProcessPolicy   11)  VirtualPort     19) 查询准入        ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   4) PeripheralPolicy 12) BackupList      20) 准入-OFF        ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   5) IpBlockPolicy   13)  JumpStatus      21) 准入-ON         ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   6) IpBlackPolicy   14)  ProcessList     22) 准入-AUTO       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   7) OutreachRules   15)  PortList        23) ExecutableList  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   8) DirPolicy       16)  UsbDeviceList   24) VulnScan上报    ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  25) 历史告警(全部)  26) 历史告警(未处理)                  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  27) 告警处置(已处理) 28) 告警处置(已忽略)                  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  s1) VirusScan流(StreamControl)                              ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${RED}写接口（仅离线可用，在线应返回 PERMISSION_DENIED）${NC}       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   w1) UpdateConfig      w2) UpdateProcessPolicy             ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   w3) UpdatePeripheral  w4) UpdateIpBlockPolicy             ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   w5) SubmitTask        w6) ExecuteIpJump                   ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   w7) ExecutePwJump     w8) CreateBackup                    ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   w9) RestoreBackup    w10) UpdateTrustDir                  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  w11) UpdateVirtualPort w12) UpdateDirPolicy                ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  w13) UpdateExtortPolicy w14) ProcessDefenseMode            ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  w15) PeripheralDefenseMode  w16) DeleteBackup                ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}all${NC}    测试全部只读接口 (1-28)                          ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${RED}write${NC}  测试全部写接口（验证在线拒绝）                    ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}stream${NC} 测试全部流式接口 (17, 18, s1)                   ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}full${NC}   测试全部接口（读写+流）                          ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}listen [秒]${NC} 监听告警流（默认300秒，Ctrl+C停止）         ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  q    退出                                              ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
}

run_all_readonly() {
    for i in $(seq -w 1 28); do
        fn="test_$(printf '%02d' $((10#$i)))"
        type "$fn" &>/dev/null && "$fn"
    done
}

run_all_write() {
    test_w1; test_w2; test_w3; test_w4; test_w5; test_w6; test_w7; test_w8
    test_w9; test_w10; test_w11; test_w12; test_w13; test_w14; test_w15; test_w16
}

run_all_stream() {
    test_17; test_18; test_s1
}

# ── main ───────────────────────────────────────────────────────────────

case "${1:-menu}" in
    menu|"")
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
                1)  test_01 ;; 2)  test_02 ;; 3)  test_03 ;; 4)  test_04 ;;
                5)  test_05 ;; 6)  test_06 ;; 7)  test_07 ;; 8)  test_08 ;;
                9)  test_09 ;; 10) test_10 ;; 11) test_11 ;; 12) test_12 ;;
                13) test_13 ;; 14) test_14 ;; 15) test_15 ;; 16) test_16 ;;
                17) test_17 ;; 18) test_18 ;; 19) test_19 ;; 20) test_20 ;;
                21) test_21 ;; 22) test_22 ;; 23) test_23 ;; 24) test_24 ;;
                25) test_25 ;; 26) test_26 ;;
                27) test_27 ;; 28) test_28 ;;
                s1) test_s1 ;;
                w1)  test_w1  ;; w2)  test_w2  ;; w3)  test_w3  ;; w4)  test_w4  ;;
                w5)  test_w5  ;; w6)  test_w6  ;; w7)  test_w7  ;; w8)  test_w8  ;;
                w9)  test_w9  ;; w10) test_w10 ;; w11) test_w11 ;; w12) test_w12 ;;
                w13) test_w13 ;; w14) test_w14 ;; w15) test_w15 ;; w16) test_w16 ;;
                all)
                    echo -e "\n${GREEN}── 测试全部只读接口 (1-28) ──${NC}"
                    run_all_readonly
                    print_result
                    ;;
                write)
                    echo -e "\n${RED}── 测试全部写接口（预期全部 PERMISSION_DENIED）──${NC}"
                    run_all_write
                    print_result
                    ;;
                stream)
                    echo -e "\n${YELLOW}── 测试全部流式接口 ──${NC}"
                    run_all_stream
                    print_result
                    ;;
                full)
                    echo -e "\n${GREEN}── 测试全部接口 ──${NC}"
                    run_all_readonly
                    run_all_stream
                    run_all_write
                    print_result
                    ;;
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
                \?|h|help)
                    echo ""
                    echo -e "${CYAN}── 只读接口 ──${NC}"
                    echo "   1) AgentStatus        2) Config"
                    echo "   3) ProcessPolicy      4) PeripheralPolicy"
                    echo "   5) IpBlockPolicy      6) IpBlackPolicy"
                    echo "   7) OutreachRules      8) DirPolicy"
                    echo "   9) ExtortPolicy      10) TrustDir"
                    echo "  11) VirtualPort        12) BackupList"
                    echo "  13) JumpStatus         14) ProcessList"
                    echo "  15) PortList           16) UsbDeviceList"
                    echo "  17) PolicyWatch(流)    18) Alert(流)"
                    echo "  19) 查询准入           20) 准入-OFF"
                    echo "  21) 准入-ON            22) 准入-AUTO"
                    echo "  23) ExecutableList     24) VulnScan上报"
                    echo "  25) 历史告警(全部)   26) 历史告警(未处理)"
                    echo "  27) 告警处置(已处理)  28) 告警处置(已忽略)"
                    echo "  s1) VirusScan流"
                    echo ""
                    echo -e "${CYAN}── 写接口（仅离线可用）──${NC}"
                    echo "   w1) UpdateConfig        w2) UpdateProcessPolicy"
                    echo "   w3) UpdatePeripheral    w4) UpdateIpBlockPolicy"
                    echo "   w5) SubmitTask          w6) ExecuteIpJump"
                    echo "   w7) ExecutePwJump       w8) CreateBackup"
                    echo "   w9) RestoreBackup      w10) UpdateTrustDir"
                    echo "  w11) UpdateVirtualPort  w12) UpdateDirPolicy"
                    echo "  w13) UpdateExtortPolicy w14) ProcessDefenseMode"
                    echo "  w15) PeripheralDefenseMode  w16) DeleteBackup"
                    echo ""
                    echo -e "${CYAN}── 快捷命令 ──${NC}"
                    echo "  all    测试全部只读 (1-28)"
                    echo "  write  测试全部写 (w1-w16)"
                    echo "  stream 测试全部流式 (17, 18, s1)"
                    echo "  full   测试全部"
                    echo "  listen [秒]  监听告警流"
                    echo "  ?|h    显示此帮助     q  退出"
                    echo ""
                    ;;
                q|Q|quit|exit) echo "退出"; break ;;
                *) echo -e "${RED}无效选择: $choice${NC} (输入 ? 查看帮助)" ;;
            esac
        done
        ;;

    # 直接调用模式
    all)
        run_all_readonly
        print_result
        ;;
    write)
        run_all_write
        print_result
        ;;
    stream)
        run_all_stream
        print_result
        ;;
    full)
        run_all_readonly
        run_all_stream
        run_all_write
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
    ?|help|-h|--help)
        echo "用法: $0 [选项]"
        echo ""
        echo "  无参数           交互式菜单"
        echo "  ?|help|-h       显示此帮助"
        echo "  all             测试全部只读接口 (1-28)"
        echo "  write           测试全部写接口 (w1-w16, 需离线模式)"
        echo "  stream          测试流式接口 (17, 18, s1)"
        echo "  full            测试全部接口（读写+流）"
        echo "  listen [秒]     监听告警流（默认300秒, Ctrl+C停止）"
        echo "  1-28            测试指定编号的只读接口"
        echo "  s1              测试病毒扫描双向流"
        echo "  w1-w16          测试指定编号的写接口"
        echo "  menu            显示交互式菜单"
        echo ""
        echo "示例:"
        echo "  $0              进入交互式菜单"
        echo "  $0 1            直接测试 AgentStatus"
        echo "  $0 23           直接测试 GetExecutableList"
        echo "  $0 s1           直接测试 VirusScan 双向流"
        echo "  $0 all          测试全部只读接口"
        echo "  $0 write        测试全部写接口"
        echo "  $0 listen 60    监听告警流60秒"
        echo ""
        echo "环境变量:"
        echo "  GRPC_ADDR       目标地址（默认 127.0.0.1:50051）"
        echo "  PROTO_DIR       proto 文件目录（自动检测）"
        ;;

    s1) test_s1; print_result ;;

    *)
        arg="$1"
        if [[ "$arg" =~ ^w[1-9]$|^w1[0-6]$ ]]; then
            "test_$arg"
        elif [[ "$arg" =~ ^[0-9]+$ ]] && [ "$arg" -ge 1 ] && [ "$arg" -le 28 ]; then
            "test_$(printf '%02d' "$arg")"
        else
            echo "无效参数: $1"
            echo "用法: $0 [?|help|all|write|stream|full|listen|<1-28>|s1|w1-w16|menu]"
            echo "试试: $0 ?  查看完整帮助"
            exit 1
        fi
        print_result
        ;;
esac
