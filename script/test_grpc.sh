#!/bin/bash
# ============================================================================
# gRPC 接口测试脚本
# 用法:
#   ./test_grpc.sh                  # 交互式菜单
#   ./test_grpc.sh <编号>            # 直接测试
#   ./test_grpc.sh all               # 全部只读
#   ./test_grpc.sh write             # 全部写（验证在线拒绝，w0除外）
#   ./test_grpc.sh stream            # 全部流式
#   ./test_grpc.sh full              # 全部（读写+流）
#   ./test_grpc.sh listen [秒]       # 监听告警流
#   ./test_grpc.sh w0 <json>         # UpdateConfig 直接下发
#   ./test_grpc.sh w2 <json>         # UpdateProcessPolicy 直接下发
# ============================================================================

GRPC_ADDR="${GRPC_ADDR:-127.0.0.1:50051}"
PROTO_DIR="$(dirname "$0")/../crates/grpc_gateway/src/proto"
PROTO_DIR="$(cd "$PROTO_DIR" 2>/dev/null && pwd || echo "$PROTO_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

pass=0
fail=0

# ── helpers ────────────────────────────────────────────────────────────

grpc_call() {
    local desc="$1" proto="$2" svc="$3" method="$4" data="${5:-{\}}" extra_protos="${6:-}"
    local proto_args=""
    for p in common.proto $proto $extra_protos; do
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
    local proto="$1" svc="$2" method="$3" data="${4:-{\}}" extra_protos="${5:-}"
    local proto_args=""
    for p in common.proto $proto $extra_protos; do
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
    local desc="$1" proto="$2" svc="$3" method="$4" data="${5:-{\}}" extra_protos="${6:-}"
    local proto_args=""
    for p in common.proto $proto $extra_protos; do
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
        echo -e "${YELLOW}UNEXPECTED PASS${NC} (预期 PERMISSION_DENIED)"
        echo "$output" | sed 's/^/  /'
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
    local proto_args=""
    for p in common.proto $proto $extra_protos; do
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
            echo -e "${GREEN}PASS${NC} (流保持 ${duration}s，无事件)"
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

# ── result ──────────────────────────────────────────────────────────────

print_result() {
    echo ""
    echo -e "=============================================="
    local total=$((pass + fail))
    echo -e "  结果: ${GREEN}${pass} 通过${NC} / ${RED}${fail} 失败${NC} / ${total} 总计"
    echo -e "=============================================="
    pass=0; fail=0
}

# ── test functions ──────────────────────────────────────────────────────

# ─ 只读接口（始终可用）
test_01() { grpc_call "AgentStatus(运行状态/版本/在线)" \
    agent_status.proto agent_status.AgentStatusService GetAgentStatus; }

test_02() { grpc_call "Config(当前配置)" \
    config.proto config.ConfigService GetConfig; }

test_03() { grpc_call "ProcessPolicy(进程白名单)" \
    process_policy.proto process_policy.ProcessPolicyService GetProcessPolicy \
    '{"is_white": 1}'; }

test_03b(){ grpc_call "ProcessPolicy(进程黑名单)" \
    process_policy.proto process_policy.ProcessPolicyService GetProcessPolicy \
    '{"is_white": 0}'; }

test_04() { grpc_call "PeripheralPolicy(外设白名单)" \
    peripheral_policy.proto peripheral_policy.PeripheralPolicyService GetPeripheralPolicy \
    '{"is_white": 1}'; }

test_04b(){ grpc_call "PeripheralPolicy(外设黑名单)" \
    peripheral_policy.proto peripheral_policy.PeripheralPolicyService GetPeripheralPolicy \
    '{"is_white": 0}'; }

test_05() { grpc_call "IpBlockPolicy(IP阻断策略)" \
    ip_policy.proto ip_policy.IpPolicyService GetIpBlockPolicy; }

test_06() { grpc_call "IpBlackPolicy(IP黑名单)" \
    ip_policy.proto ip_policy.IpPolicyService GetIpBlackPolicy; }

test_07() { grpc_call "OutreachRules(外联检测规则)" \
    outreach_detect.proto outreach_detect.OutreachDetectService GetOutreachRules; }

test_08() { grpc_call "DirPolicy(目录保护策略)" \
    dir_policy.proto dir_policy.DirPolicyService GetDirPolicy; }

test_09() { grpc_call "ExtortPolicy(勒索保护策略)" \
    extort_policy.proto extort_policy.ExtortPolicyService GetExtortPolicy; }

test_10() { grpc_call "TrustDir(信任目录)" \
    trust_dir.proto trust_dir.TrustDirService GetTrustDir; }

test_11() { grpc_call "VirtualPort(虚拟端口规则)" \
    virtual_port.proto virtual_port.VirtualPortService GetVirtualPort; }

test_12() { grpc_call "BackupList(备份列表)" \
    backup.proto backup.BackupService GetBackupList; }

test_13() { grpc_call "JumpStatus(跳变状态)" \
    jump.proto jump.JumpService GetJumpStatus; }

test_14() { grpc_call "ProcessList(进程列表 全部 top20)" \
    data_query.proto data_query.DataQueryService GetProcessList \
    '{"limit": 20, "sort_by": "pid", "filter_status": 0}' \
    "peripheral_policy.proto"; }

test_14b(){ grpc_call "ProcessList(进程列表 仅白名单)" \
    data_query.proto data_query.DataQueryService GetProcessList \
    '{"limit": 20, "sort_by": "pid", "filter_status": 1}' \
    "peripheral_policy.proto"; }

test_14c(){ grpc_call "ProcessList(进程列表 仅黑名单)" \
    data_query.proto data_query.DataQueryService GetProcessList \
    '{"limit": 20, "sort_by": "pid", "filter_status": 2}' \
    "peripheral_policy.proto"; }

test_15() { grpc_call "PortList(端口列表)" \
    data_query.proto data_query.DataQueryService GetPortList \
    '{}' "peripheral_policy.proto"; }

test_16() { grpc_call "UsbDeviceList(USB设备列表)" \
    data_query.proto data_query.DataQueryService GetUsbDeviceList \
    '{}' "peripheral_policy.proto"; }

test_29() { grpc_call "ExecutableList(可执行文件列表)" \
    data_query.proto data_query.DataQueryService GetExecutableList \
    '{"filter_status": 0}' "peripheral_policy.proto"; }

# ─ 流式接口
test_17() { stream_test "PolicyWatch(策略变更流)" \
    policy_watch.proto policy_watch.PolicyWatchService SubscribePolicyChanges \
    '{}' 3; }

test_18() { stream_test "Alert(告警流)" \
    alert.proto alert.AlertService SubscribeAlerts \
    '{"type": 0}' 3; }

# ─ 准入控制
test_19() { grpc_call "准入-查询" \
    admission.proto admission.AdmissionService GetAdmissionSwitch '{}' ''; }

test_20() { grpc_call "准入-关闭(OFF)" \
    admission.proto admission.AdmissionService UpdateAdmissionSwitch \
    '{"mode": 0}' ''; }

test_21() { grpc_call "准入-开启(ON)" \
    admission.proto admission.AdmissionService UpdateAdmissionSwitch \
    '{"mode": 1}' ''; }

test_22() { grpc_call "准入-自动(AUTO)" \
    admission.proto admission.AdmissionService UpdateAdmissionSwitch \
    '{"mode": 2}' ''; }

# ─ 防护模式查询
test_30() { grpc_call "进程防护模式(查询)" \
    protection_mode.proto protection_mode.ProcessDefenseService GetProcessDefenseMode; }

test_31() { grpc_call "外设防护模式(查询)" \
    protection_mode.proto protection_mode.PeripheralDefenseService GetPeripheralDefenseMode; }

# ─ 后端模式
test_23() { grpc_call "后端模式(查询)" \
    backend.proto backend.BackendService GetBackendMode '{}'; }

test_24() { grpc_call "进程策略(eBPF查询白名单)" \
    process_policy.proto process_policy.ProcessPolicyService GetProcessPolicy '{"is_white": 1}'; }

test_25() { grpc_call "IP阻断(eBPF查询)" \
    ip_policy.proto ip_policy.IpPolicyService GetIpBlockPolicy '{}'; }

test_26() { grpc_call "后端模式(查询)" \
    backend.proto backend.BackendService GetBackendMode '{}'; }

test_27() { grpc_call "后端模式-设ebpf" \
    backend.proto backend.BackendService UpdateBackendMode '{"mode": "ebpf"}'; }

test_28() { grpc_call "后端模式-设driver" \
    backend.proto backend.BackendService UpdateBackendMode '{"mode": "driver"}'; }

# ─ eBPF 系统能力检测
test_cap() {
    echo -ne "${CYAN}[CHECK]${NC} eBPF 系统能力检测 ... "
    local ok=true reasons=""

    local kver=$(uname -r | cut -d. -f1,2)
    local kmajor=$(echo "$kver" | cut -d. -f1)
    local kminor=$(echo "$kver" | cut -d. -f2)
    if [ "$kmajor" -lt 5 ] || { [ "$kmajor" -eq 5 ] && [ "$kminor" -lt 8 ]; }; then
        ok=false
        reasons="$reasons\n  内核版本过低: $kver (需要 >= 5.8)"
    fi
    if [ ! -f /sys/kernel/btf/vmlinux ]; then
        ok=false
        reasons="$reasons\n  BTF 不可用: /sys/kernel/btf/vmlinux 不存在"
    fi
    if ! grep -q '\bbpf\b' /sys/kernel/security/lsm 2>/dev/null; then
        ok=false
        reasons="$reasons\n  BPF LSM 未启用: /sys/kernel/security/lsm 不含 bpf"
    fi
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

# ── write tests ─────────────────────────────────────────────────────────
# w0: UpdateConfig (受 ALLOW_CONFIG_WRITE_ONLINE 控制，非简单拒绝)
# 其他 w1-w13: 在线模式应拒绝

test_w0_deny() {
    grpc_expect_perm_denied "UpdateConfig(在线拒绝，ALLOW=0)" \
        config.proto config.ConfigService UpdateConfig \
        '{"crontime": 120}'; }

test_w0() {
    grpc_call "UpdateConfig(配置下发)" \
        config.proto config.ConfigService UpdateConfig \
        "$1"; }

test_w1() { grpc_expect_perm_denied "UpdateProcessPolicy(在线拒绝)" \
    process_policy.proto process_policy.ProcessPolicyService UpdateProcessPolicy \
    '{"hash_list": ["abc123"], "action": 1}'; }

test_w2() { grpc_expect_perm_denied "UpdatePeripheralPolicy(在线拒绝)" \
    peripheral_policy.proto peripheral_policy.PeripheralPolicyService UpdatePeripheralPolicy \
    '{"devices": [], "action": 1}'; }

test_w3() { grpc_expect_perm_denied "UpdateIpBlockPolicy(在线拒绝)" \
    ip_policy.proto ip_policy.IpPolicyService UpdateIpBlockPolicy \
    '{"items": [{"ip": "10.0.0.1", "direction": 1, "duration": 3600, "is_ipv6": false}]}'; }

test_w4() { grpc_expect_perm_denied "SubmitTask(在线拒绝)" \
    task_local.proto task_local.LocalTaskService SubmitTask \
    '{"task_ids": [6, 19]}'; }

test_w5() { grpc_expect_perm_denied "ExecuteIpJump(在线拒绝)" \
    jump.proto jump.JumpService ExecuteIpJump \
    '{"gateway":"192.168.1.1","source_ip":"10.0.0.5","target_ip":"10.0.0.6","mode":1}'; }

test_w6() { grpc_expect_perm_denied "ExecutePwJump(在线拒绝)" \
    jump.proto jump.JumpService ExecutePwJump \
    '{"new_password":"test123"}'; }

test_w7() { grpc_expect_perm_denied "CreateBackup(在线拒绝)" \
    backup.proto backup.BackupService CreateBackup \
    '{"name":"test_bak"}'; }

test_w8() { grpc_expect_perm_denied "RestoreBackup(在线拒绝)" \
    backup.proto backup.BackupService RestoreBackup \
    '{"backup_id":"abc123"}'; }

test_w9() { grpc_expect_perm_denied "UpdateTrustDir(在线拒绝)" \
    trust_dir.proto trust_dir.TrustDirService UpdateTrustDir \
    '{"dirs": [{"dir":"/opt","type":1,"is_extend":0}]}'; }

test_w10(){ grpc_expect_perm_denied "UpdateVirtualPort(在线拒绝)" \
    virtual_port.proto virtual_port.VirtualPortService UpdateVirtualPort \
    '{"rules": [{"alarm_level":1,"dest_ip":"192.168.1.1","dest_port":"80","dest_port_type":0,"id":1,"protocol":"tcp","source_ip":"10.0.0.1","source_port_start":8080,"source_port_end":8080,"type":"tcp"}]}'; }

test_w11(){ grpc_expect_perm_denied "UpdateDirPolicy(在线拒绝)" \
    dir_policy.proto dir_policy.DirPolicyService UpdateDirPolicy \
    '{"rules": [{"dir":"/opt","pid":0,"typ":1}]}'; }

test_w12(){ grpc_expect_perm_denied "UpdateExtortPolicy(在线拒绝)" \
    extort_policy.proto extort_policy.ExtortPolicyService UpdateExtortPolicy \
    '{"rules": [{"file_type":"doc","typ":1}]}'; }

test_w13(){ grpc_expect_perm_denied "SetProcessDefense(在线拒绝)" \
    protection_mode.proto protection_mode.ProcessDefenseService UpdateProcessDefenseMode \
    '{"mode": 1}'; }

test_w14(){ grpc_expect_perm_denied "SetPeripheralDefense(在线拒绝)" \
    protection_mode.proto protection_mode.PeripheralDefenseService UpdatePeripheralDefenseMode \
    '{"mode": 1}'; }

test_w15(){ grpc_expect_perm_denied "UpdateBackendMode(在线拒绝)" \
    backend.proto backend.BackendService/SetBackendMode \
    '{"mode":1}'; }

test_w16(){ grpc_expect_perm_denied "TriggerLocalUpdate(在线拒绝)" \
    task_local.proto task_local.LocalTaskService/TriggerLocalUpdate \
    '{"zipPath":""}'; }

# 实际本地升级测试（需离线模式）
test_local_upgrade() {
    grpc_call "触发本地升级(扫描 /opt/osec/upgrade/)" \
        task_local.proto task_local.LocalTaskService TriggerLocalUpdate \
        '{"zipPath":""}'
}

test_local_upgrade_file() {
    local fp="${1:-/opt/osec/upgrade/update.zip}"
    grpc_call "触发本地升级(指定文件: $fp)" \
        task_local.proto task_local.LocalTaskService TriggerLocalUpdate \
        "{\"zipPath\":\"$fp\"}"
}
    backend.proto backend.BackendService UpdateBackendMode \
    '{"mode": "ebpf"}'; }

# ── 病毒扫描/隔离测试（VirusScanService bidi 流） ──
# 用法: test_vs_move <file_path> [scan_id]
test_vs_move() {
    local fp="${1:-/tmp/test_virus_sample}"
    local sid="${2:-test-restore-001}"
    echo -ne "${CYAN}[TEST]${NC} 病毒隔离(MOVE) $fp ... "
    local output
    output=$(grpcurl -plaintext -emit-defaults \
        -import-path "$PROTO_DIR" \
        -proto common.proto -proto virus_scan.proto \
        -d "{\"dispose_file\":{\"scan_id\":\"$sid\",\"file_path\":\"$fp\",\"action\":1}}" \
        -connect-timeout 3 -max-time 10 \
        "$GRPC_ADDR" virus_scan.VirusScanService/StreamControl 2>&1) && rc=0 || rc=1
    if [ $rc -eq 0 ] && echo "$output" | grep -q "隔离成功"; then
        echo -e "${GREEN}PASS${NC} (已隔离 → /opt/vigilixav/quarantine/$(basename "$fp").quar)"
        echo "$output" | sed 's/^/  /'
        ((pass++))
    elif [ $rc -eq 0 ]; then
        echo -e "${YELLOW}OK${NC}"
        echo "$output" | sed 's/^/  /'
        ((pass++))
    else
        echo -e "${RED}FAIL${NC}"
        echo "$output" | sed 's/^/  /'
        ((fail++))
    fi
}

# 用法: test_vs_restore <隔离区文件路径|原始路径>
test_vs_restore() {
    local fp="${1:-/tmp/test_virus_sample}"
    local sid="${2:-test-restore-001}"
    echo -ne "${CYAN}[TEST]${NC} 病毒还原(RESTORE) $fp ... "
    local output
    output=$(grpcurl -plaintext -emit-defaults \
        -import-path "$PROTO_DIR" \
        -proto common.proto -proto virus_scan.proto \
        -d "{\"dispose_file\":{\"scan_id\":\"$sid\",\"file_path\":\"$fp\",\"action\":3}}" \
        -connect-timeout 3 -max-time 10 \
        "$GRPC_ADDR" virus_scan.VirusScanService/StreamControl 2>&1) && rc=0 || rc=1
    if [ $rc -eq 0 ] && echo "$output" | grep -q "还原成功"; then
        echo -e "${GREEN}PASS${NC} (已还原)"
        echo "$output" | sed 's/^/  /'
        ((pass++))
    elif [ $rc -eq 0 ]; then
        echo -e "${YELLOW}OK${NC}"
        echo "$output" | sed 's/^/  /'
        ((pass++))
    else
        echo -e "${RED}FAIL${NC}"
        echo "$output" | sed 's/^/  /'
        ((fail++))
    fi
}

# 用法: test_vs_remove <file_path>
test_vs_remove() {
    local fp="${1:-/tmp/test_virus_sample}"
    local sid="${2:-test-restore-001}"
    echo -ne "${CYAN}[TEST]${NC} 病毒删除(REMOVE) $fp ... "
    local output
    output=$(grpcurl -plaintext -emit-defaults \
        -import-path "$PROTO_DIR" \
        -proto common.proto -proto virus_scan.proto \
        -d "{\"dispose_file\":{\"scan_id\":\"$sid\",\"file_path\":\"$fp\",\"action\":2}}" \
        -connect-timeout 3 -max-time 10 \
        "$GRPC_ADDR" virus_scan.VirusScanService/StreamControl 2>&1) && rc=0 || rc=1
    if [ $rc -eq 0 ]; then
        echo -e "${GREEN}PASS${NC}"
        echo "$output" | sed 's/^/  /'
        ((pass++))
    else
        echo -e "${RED}FAIL${NC}"
        echo "$output" | sed 's/^/  /'
        ((fail++))
    fi
}

# 病毒扫描端到端: 创建测试文件 → 隔离 → 还原 → 清理
# 用法: test_vs_e2e [test_dir]
test_vs_e2e() {
    local test_dir="${1:-/tmp}"
    local test_file="$test_dir/vs_restore_test_$$.txt"
    local test_content="virus-test-$(date +%s)"
    local sid="e2e-$$"

    echo -e "\n${YELLOW}═══ 病毒处置端到端测试 ═══${NC}"
    echo "测试文件: $test_file"
    echo ""

    # Step 1: create test file
    echo -ne "${CYAN}[E2E:1]${NC} 创建测试文件 ... "
    if echo "$test_content" > "$test_file" && chmod 755 "$test_file"; then
        echo -e "${GREEN}OK${NC} ($(stat -c '%a' "$test_file"))"
    else
        echo -e "${RED}FAIL${NC}"
        return 1
    fi

    # Step 2: quarantine (MOVE)
    echo -ne "${CYAN}[E2E:2]${NC} 隔离文件 ... "
    local output
    output=$(grpcurl -plaintext -emit-defaults \
        -import-path "$PROTO_DIR" \
        -proto common.proto -proto virus_scan.proto \
        -d "{\"dispose_file\":{\"scan_id\":\"$sid\",\"file_path\":\"$test_file\",\"action\":1}}" \
        -connect-timeout 3 -max-time 10 \
        "$GRPC_ADDR" virus_scan.VirusScanService/StreamControl 2>&1) && rc=0 || rc=1
    if [ $rc -eq 0 ] && echo "$output" | grep -q "隔离成功"; then
        echo -e "${GREEN}OK${NC}"
        echo "$output" | sed 's/^/    /'
    else
        echo -e "${RED}FAIL${NC}"
        echo "$output" | sed 's/^/    /'
        rm -f "$test_file"
        return 1
    fi

    # verify quarantined
    local quar_path="/opt/vigilixav/quarantine/$(basename "$test_file").quar"
    echo -ne "${CYAN}[E2E:3]${NC} 验证隔离 ... "
    if [ -f "$quar_path" ]; then
        local qperm=$(stat -c '%a' "$quar_path" 2>/dev/null || echo "???")
        echo -e "${GREEN}OK${NC} (存在: $quar_path, 权限: $qperm)"
        if [ "$qperm" != "000" ]; then
            echo -e "    ${YELLOW}⚠ 权限应为 000 但实际: $qperm${NC}"
        else
            echo -e "    ${GREEN}✓ 权限 chmod 000 已生效${NC}"
        fi
    else
        echo -e "${YELLOW}WARN${NC} (隔离文件不存在？可能跨设备 copy+delete)"
        # try find meta
        local meta_path="/opt/vigilixav/quarantine/$(basename "$test_file").quar.meta"
        if [ -f "$meta_path" ]; then
            echo "    meta 文件存在: $meta_path"
        fi
    fi

    # Step 4: restore (RESTORE)
    echo -ne "${CYAN}[E2E:4]${NC} 还原文件 ... "
    local r_output
    r_output=$(grpcurl -plaintext -emit-defaults \
        -import-path "$PROTO_DIR" \
        -proto common.proto -proto virus_scan.proto \
        -d "{\"dispose_file\":{\"scan_id\":\"$sid\",\"file_path\":\"$test_file\",\"action\":3}}" \
        -connect-timeout 3 -max-time 10 \
        "$GRPC_ADDR" virus_scan.VirusScanService/StreamControl 2>&1) && rc=0 || rc=1
    if [ $rc -eq 0 ] && echo "$r_output" | grep -q "还原成功"; then
        echo -e "${GREEN}OK${NC}"
        echo "$r_output" | sed 's/^/    /'
    else
        echo -e "${RED}FAIL${NC}"
        echo "$r_output" | sed 's/^/    /'
    fi

    # Step 5: verify restored
    echo -ne "${CYAN}[E2E:5]${NC} 验证还原 ... "
    if [ -f "$test_file" ]; then
        local rperm=$(stat -c '%a' "$test_file" 2>/dev/null)
        echo -e "${GREEN}OK${NC} (权限: $rperm)"
        if [ "$rperm" = "755" ]; then
            echo -e "    ${GREEN}✓ 权限已恢复${NC}"
        fi
        rm -f "$test_file"
    else
        echo -e "${YELLOW}WARN${NC} (文件仍未还原到原位)"
    fi

    # cleanup .meta
    local meta_f="/opt/vigilixav/quarantine/$(basename "$test_file").quar.meta"
    rm -f "$meta_f" "$quar_path"

    echo -e "${GREEN}═══ 端到端测试完成 ═══${NC}"
    echo ""
}

# ── help ────────────────────────────────────────────────────────────────

show_help_detail() {
    echo ""
    case "$1" in
        1)  echo -e "${CYAN}[1] AgentStatus${NC} — Agent运行状态"
            echo "    返回: mod_ver, agent_mode(online/offline), protection_days, hostname, dev_uid 等" ;;
        2)  echo -e "${CYAN}[2] Config${NC} — 当前Agent配置（net_info.ini 中的策略字段）"
            echo "    返回: crontime, file_switch, proc_switch, extortion_protect 等 29 个字段" ;;
        3)  echo -e "${CYAN}[3] ProcessPolicy(白)${NC} — 进程白名单 hash 列表"
            echo "    gRPC: GetProcessPolicy {\"is_white\": 1}" ;;
        3b) echo -e "${CYAN}[3b] ProcessPolicy(黑)${NC} — 进程黑名单 hash 列表"
            echo "    gRPC: GetProcessPolicy {\"is_white\": 0}" ;;
        4)  echo -e "${CYAN}[4] PeripheralPolicy(白)${NC} — 外设白名单"
            echo "    gRPC: GetPeripheralPolicy {\"is_white\": 1}" ;;
        4b) echo -e "${CYAN}[4b] PeripheralPolicy(黑)${NC} — 外设黑名单"
            echo "    gRPC: GetPeripheralPolicy {\"is_white\": 0}" ;;
        14) echo -e "${CYAN}[14] ProcessList${NC} — 进程列表"
            echo "    filter_status: 0=全部 1=白名单 2=黑名单 3=未知" ;;
        14b)echo -e "${CYAN}[14b] ProcessList(白)${NC} — 进程列表(仅白名单)" ;;
        14c)echo -e "${CYAN}[14c] ProcessList(黑)${NC} — 进程列表(仅黑名单)" ;;
        w0) echo -e "${CYAN}[w0] UpdateConfig${NC} — ★ 配置下发（ini + 内核）"
            echo ""
            echo -e "  行为: 受 ${YELLOW}[GRPC] ALLOW_CONFIG_WRITE_ONLINE${NC} 控制"
            echo "    ALLOW=0(default): 在线拒绝 (PERMISSION_DENIED)"
            echo "    ALLOW=1         : 在线允许，完整下发到内核/BPF"
            echo ""
            echo "  测试在线拒绝:  输入 w0"
            echo "  直接下发:      输入 w0 {\"crontime\":60,\"file_switch\":true}"
            echo "  示例:"
            echo "    w0 {\"crontime\": 60}"
            echo "    w0 {\"crontime\":60,\"proc_switch\":false,\"file_switch\":true}" ;;
        w2) echo -e "${CYAN}[w2] UpdateProcessPolicy${NC} — 进程黑白名单(eBPF在线下发)"
            echo ""
            echo "  直接下发:  w2 {\"hash_list\":[\"<MD5>\"],\"action\":2}"
            echo "  action: 0=白名单(放行) 1=黑名单(监控) 2=黑名单(保护)"
            echo ""
            echo "  示例:"
            echo "    1. md5sum /usr/bin/ls"
            echo "    2. w2 {\"hash_list\":[\"abc123\"],\"action\":2}"
            echo "    3. ./test_grpc.sh 3b  (查看是否生效)" ;;
        cap) echo -e "${CYAN}[cap] eBPF系统能力检测${NC}"
            echo "  检查: 内核>=5.8, BTF, BPF LSM, bpffs" ;;
        vs-move) echo -e "${CYAN}[vs-move]${NC} 病毒隔离 — 文件→隔离区(chmod 000 + .quar)"
            echo "  用法: vs-move /path/to/virus [scan_id]" ;;
        vs-restore) echo -e "${CYAN}[vs-restore]${NC} 病毒还原 — 隔离区→原位(读.meta恢复权限)"
            echo "  用法: vs-restore /path/to/original"
            echo "  用法: vs-restore /opt/vigilixav/quarantine/file.quar" ;;
        vs-remove) echo -e "${CYAN}[vs-remove]${NC} 病毒删除 — 直接删除文件"
            echo "  用法: vs-remove /path/to/virus [scan_id]" ;;
        vs-e2e) echo -e "${CYAN}[vs-e2e]${NC} 病毒处置端到端测试"
            echo "  创建测试文件 → 隔离(chmod 000) → 还原(权限恢复) → 清理"
            echo "  用法: vs-e2e [test_dir]" ;;
        30) echo -e "${CYAN}[30] ProcessDefenseMode${NC} — 进程防护模式(查询)"
            echo "  0=关闭 1=监控 2=保护" ;;
        31) echo -e "${CYAN}[31] PeripheralDefenseMode${NC} — 外设防护模式(查询)"
            echo "  0=关闭 1=监控 2=保护" ;;
        *)  echo -e "${RED}帮助: $1 — 暂无详情${NC}"
            echo "  有效: 1-16, 3b, 4b, 14b, 14c, 17-22, 23-31, cap, w0-w15, vs-move, vs-restore, vs-remove, vs-e2e" ;;
    esac
    echo ""
}

# ── menu ────────────────────────────────────────────────────────────────

show_menu() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}     ${YELLOW}gRPC 接口测试  —  ${GRPC_ADDR}${NC}                       ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}── 只读接口（始终可用）${NC}                                    ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   1)AgentStatus   2)Config        3)ProcPolicy(白) 3b)黑名单${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   4)Periph(白)    4b)Periph(黑)    5)IpBlock       6)IpBlack ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   7)Outreach      8)DirPolicy      9)Extort       10)TrustDir ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  11)VirtualPort  12)BackupList    13)JumpStatus               ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  14)ProcessList 14b)白名单 14c)黑名单 15)PortList 16)UsbDev  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  17)PolicyWatch(流) 18)Alert(流)   19)准入查询   29)ExeList  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  20)准入-OFF    21)准入-ON        22)准入-AUTO               ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  30)进程防护查询 31)外设防护查询                              ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${RED}── 写接口（仅离线可用，在线应返回 PERMISSION_DENIED）${NC}        ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  w0)UpdateConfig ★(ALLOW_CONFIG_WRITE_ONLINE控制)${NC}           ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  w1)UpdateProcPolicy  w2)UpdatePeriph    w3)UpdateIpBlock   ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  w4)SubmitTask       w5)ExecuteIpJump   w6)ExecutePwJump    ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  w7)CreateBackup     w8)RestoreBackup   w9)UpdateTrustDir   ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  w10)UpdateVirtPort  w11)UpdateDirPol   w12)UpdateExtortPol  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  w13)SetProcDefense  w14)SetPeriphDef   w15)SetBackendMode   ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  w16)LocalUpgrade    ${BLUE}upgrade${NC}=触发本地升级(离线)             ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${BLUE}── 病毒处置（VirusScanService 流式接口）${NC}                      ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  vs-move <文件>           = 隔离病毒文件(MOVE)             ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  vs-restore <文件>        = 还原隔离文件(RESTORE)          ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  vs-remove <文件>         = 删除病毒文件(REMOVE)           ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  vs-e2e                   = 端到端测试(隔离→还原)          ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${BLUE}── 快捷命令${NC}                                                ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  all=只读 | write=写 | stream=流 | full=全部 | listen [秒] ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  cap=eBPF检测 | 23=后端状态 | 26=查询后端 27=ebpf 28=drv  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ?=帮助 | <id> ?=详情 | w0 <json>=直接下发 | q=退出       ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ── main ────────────────────────────────────────────────────────────────

case "${1:-menu}" in
    menu|"")
        # Connectivity check
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

            # "? " or "<id> ?" → help
            if [[ "$choice" =~ \?$ ]]; then
                tid="${choice%%\?*}"
                tid="${tid%% }"
                [ -z "$tid" ] && show_menu || show_help_detail "$tid"
                continue
            fi

            # "w0 <json>" direct UpdateConfig
            if [[ "$choice" =~ ^w0[[:space:]]+\{ ]]; then
                json_data="${choice#w0 }"
                echo -ne "${CYAN}[直接下发]${NC} UpdateConfig ... "
                output=$(grpcurl -plaintext -emit-defaults \
                    -import-path "$PROTO_DIR" \
                    -proto common.proto -proto config.proto \
                    -d "$json_data" \
                    -connect-timeout 3 -max-time 10 \
                    "$GRPC_ADDR" config.ConfigService/UpdateConfig 2>&1) && rc=0 || rc=1
                if [ $rc -eq 0 ]; then
                    echo -e "${GREEN}成功${NC}"
                    echo "$output" | sed 's/^/  /'
                    echo -ne "${CYAN}[查询]${NC} 当前配置: "
                    grpcurl -plaintext -emit-defaults \
                        -import-path "$PROTO_DIR" \
                        -proto common.proto -proto config.proto \
                        -d '{}' -connect-timeout 3 -max-time 5 \
                        "$GRPC_ADDR" config.ConfigService/GetConfig 2>&1 | sed 's/^/  /'
                else
                    echo -e "${RED}失败${NC}"
                    echo "$output" | sed 's/^/  /'
                fi
                continue
            fi

            # "w2 <json>" direct UpdateProcessPolicy
            if [[ "$choice" =~ ^w2[[:space:]]+\{ ]]; then
                json_data="${choice#w2 }"
                echo -ne "${CYAN}[直接下发]${NC} UpdateProcessPolicy ... "
                output=$(grpcurl -plaintext -emit-defaults \
                    -import-path "$PROTO_DIR" \
                    -proto common.proto -proto process_policy.proto \
                    -d "$json_data" \
                    -connect-timeout 3 -max-time 10 \
                    "$GRPC_ADDR" process_policy.ProcessPolicyService/UpdateProcessPolicy 2>&1) && rc=0 || rc=1
                if [ $rc -eq 0 ]; then
                    echo -e "${GREEN}成功${NC}"
                    echo "$output" | sed 's/^/  /'
                    echo -ne "${CYAN}[查询]${NC} 黑名单: "
                    grpcurl -plaintext -emit-defaults \
                        -import-path "$PROTO_DIR" \
                        -proto common.proto -proto process_policy.proto \
                        -d '{"is_white": 0}' \
                        -connect-timeout 3 -max-time 5 \
                        "$GRPC_ADDR" process_policy.ProcessPolicyService/GetProcessPolicy 2>&1 | sed 's/^/  /'
                else
                    echo -e "${RED}失败${NC}"
                    echo "$output" | sed 's/^/  /'
                fi
                continue
            fi

            case "$choice" in
                1)  test_01 ;;             2)  test_02 ;;
                3)  test_03 ;;             3b|3B) test_03b ;;
                4)  test_04 ;;             4b|4B) test_04b ;;
                5)  test_05 ;;             6)  test_06 ;;
                7)  test_07 ;;             8)  test_08 ;;
                9)  test_09 ;;             10) test_10 ;;
                11) test_11 ;;             12) test_12 ;;      13) test_13 ;;
                14) test_14 ;;             14b|14B) test_14b ;; 14c|14C) test_14c ;;
                15) test_15 ;;             16) test_16 ;;
                17) test_17 ;;             18) test_18 ;;
                19) test_19 ;;             20) test_20 ;;
                21) test_21 ;;             22) test_22 ;;
                23) test_23 ;;             24) test_24 ;;      25) test_25 ;;
                26) test_26 ;;             27) test_27 ;;      28) test_28 ;;
                29) test_29 ;;
                30) test_30 ;;             31) test_31 ;;
                cap) test_cap ;;
                w0) test_w0_deny ;;
                w1) test_w1 ;;   w2) test_w2 ;;   w3) test_w3 ;;
                w4) test_w4 ;;   w5) test_w5 ;;   w6) test_w6 ;;
                w7) test_w7 ;;   w8) test_w8 ;;   w9) test_w9 ;;
                w10) test_w10 ;; w11) test_w11 ;; w12) test_w12 ;;
                w13) test_w13 ;; w14) test_w14 ;; w15) test_w15 ;;
                w16) test_w16 ;;
                upgrade) test_local_upgrade ;;
                vs-move|vs-move\ *)
                    fp=""; sid="vs-$$"
                    if [[ "$choice" =~ ^vs-move[[:space:]]+(.+)$ ]]; then
                        fp="${BASH_REMATCH[1]}"
                        if [[ "$fp" =~ [[:space:]]+(.+)$ ]]; then
                            sid="${BASH_REMATCH[1]}"
                            fp="${fp%% *}"
                        fi
                    else
                        read -rp "文件路径: " fp
                    fi
                    test_vs_move "$fp" "$sid"
                    ;;
                vs-restore|vs-restore\ *)
                    fp=""; sid="vs-$$"
                    if [[ "$choice" =~ ^vs-restore[[:space:]]+(.+)$ ]]; then
                        fp="${BASH_REMATCH[1]}"
                        if [[ "$fp" =~ [[:space:]]+(.+)$ ]]; then
                            sid="${BASH_REMATCH[1]}"
                            fp="${fp%% *}"
                        fi
                    else
                        read -rp "文件路径(隔离区或原始): " fp
                    fi
                    test_vs_restore "$fp" "$sid"
                    ;;
                vs-remove|vs-remove\ *)
                    fp=""; sid="vs-$$"
                    if [[ "$choice" =~ ^vs-remove[[:space:]]+(.+)$ ]]; then
                        fp="${BASH_REMATCH[1]}"
                        if [[ "$fp" =~ [[:space:]]+(.+)$ ]]; then
                            sid="${BASH_REMATCH[1]}"
                            fp="${fp%% *}"
                        fi
                    else
                        read -rp "文件路径: " fp
                    fi
                    test_vs_remove "$fp" "$sid"
                    ;;
                vs-e2e)
                    td="/tmp"
                    read -rp "测试目录 [/tmp]: " td
                    td="${td:-/tmp}"
                    test_vs_e2e "$td"
                    ;;
                all)
                    echo -e "\n${GREEN}── 测试全部只读接口 ──${NC}"
                    for tid in 1 2 3 3b 4 4b 5 6 7 8 9 10 11 12 13 14 14b 14c 15 16 19 30 31; do
                        "test_${tid}" 2>/dev/null || true
                    done
                    print_result
                    ;;
                write)
                    echo -e "\n${RED}── 测试全部写接口（预期全部 PERMISSION_DENIED）──${NC}"
                    for i in $(seq 0 16); do
                        "test_w${i}" 2>/dev/null || true
                    done
                    print_result
                    ;;
                stream)
                    echo -e "\n${YELLOW}── 测试全部流式接口 ──${NC}"
                    test_17; test_18
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
                full)
                    echo -e "\n${GREEN}── 测试全部接口 ──${NC}"
                    for tid in 1 2 3 3b 4 4b 5 6 7 8 9 10 11 12 13 14 14b 14c 15 16 19 30 31; do
                        "test_${tid}" 2>/dev/null || true
                    done
                    test_17; test_18
                    for i in $(seq 0 16); do
                        "test_w${i}" 2>/dev/null || true
                    done
                    print_result
                    ;;
                '?'|h|help)
                    show_menu ;;
                q|Q|quit|exit)
                    echo "退出"; break ;;
                *)
                    echo -e "${RED}无效选择: $choice${NC} (输入 ? 查看完整菜单, <id> ? 查看详情)" ;;
            esac
        done
        ;;

    # ── Direct invocation ──
    all)
        for tid in 1 2 3 3b 4 4b 5 6 7 8 9 10 11 12 13 14 14b 14c 15 16 19 30 31; do
            "test_${tid}" 2>/dev/null || true
        done
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
    write)
        for i in $(seq 0 16); do
            "test_w${i}" 2>/dev/null || true
        done
        print_result
        ;;
    full)
        for tid in 1 2 3 3b 4 4b 5 6 7 8 9 10 11 12 13 14 14b 14c 15 16 19 30 31; do
            "test_${tid}" 2>/dev/null || true
        done
        test_17; test_18
        for i in $(seq 0 16); do
            "test_w${i}" 2>/dev/null || true
        done
        print_result
        ;;
    '?'|help|-h|--help)
        echo "用法: $0 [编号|命令]"
        echo ""
        echo -e "${GREEN}═══ 只读接口（始终可用）═══${NC}"
        echo "   1)AgentStatus   2)Config           3)ProcPolicy(白)  3b)黑名单"
        echo "   4)Periph(白)    4b)Periph(黑)       5)IpBlock         6)IpBlack"
        echo "   7)Outreach      8)DirPolicy         9)Extort         10)TrustDir"
        echo "  11)VirtualPort  12)BackupList       13)JumpStatus"
        echo "  14)ProcessList  14b)ProcList(白)    14c)ProcList(黑)   15)PortList"
        echo "  16)UsbDevList   17)PolicyWatch(流)  18)Alert(流)      19)准入查询"
        echo "  20)准入-OFF     21)准入-ON          22)准入-AUTO      23)后端模式"
        echo "  26)查询后端     27)设ebpf           28)设driver       29)ExeList"
        echo "  30)进程防护查询 31)外设防护查询"
        echo ""
        echo -e "${RED}═══ 写接口 ═══${NC}"
        echo "  w0)UpdateConfig ★(受 ALLOW_CONFIG_WRITE_ONLINE 控制)"
        echo "  w1)UpdateProcPol  w2)UpdatePeriph     w3)UpdateIpBlock"
        echo "  w4)SubmitTask     w5)IpJump           w6)PwJump"
        echo "  w7)CreateBackup   w8)RestoreBackup    w9)UpdateTrustDir"
        echo "  w10)UpdateVirtPort w11)UpdateDirPol   w12)UpdateExtortPol"
        echo "  w13)SetProcDefense w14)SetPeriphDef   w15)SetBackendMode"
        echo "  w16)LocalUpgrade   upgrade=触发本地升级(离线)"
        echo ""
        echo -e "${BLUE}═══ 病毒处置 ═══${NC}"
        echo "  vs-move <文件> [scan_id]         # 隔离(MOVE, chmod 000 + .quar)"
        echo "  vs-restore <文件> [scan_id]      # 还原(RESTORE, 恢复权限)"
        echo "  vs-remove <文件> [scan_id]       # 删除(REMOVE)"
        echo "  vs-e2e [test_dir]                # 端到端(创建→隔离→还原→清理)"
        echo ""
        echo -e "${BLUE}═══ 快捷命令 ═══${NC}"
        echo "  all=只读 | write=写 | stream=流 | full=全部 | listen [秒]"
        echo "  cap=eBPF系统检测"
        echo ""
        echo -e "${BLUE}═══ 直接下发 ═══${NC}"
        echo "  w0 {\"crontime\":60,\"file_switch\":true}     # UpdateConfig"
        echo "  w2 {\"hash_list\":[\"<MD5>\"],\"action\":2}  # UpdateProcessPolicy"
        echo ""
        echo "配置: GRPC_ADDR=$GRPC_ADDR  PROTO_DIR=$PROTO_DIR"
        ;;

    *)
        # Direct: number, wN, or vs-* commands
        if [[ "$1" =~ ^w[0-9]$ ]] || [[ "$1" =~ ^w1[0-5]$ ]]; then
            "test_$1"
        elif [[ "$1" =~ ^3[bB]$ ]]; then
            test_03b
        elif [[ "$1" =~ ^4[bB]$ ]]; then
            test_04b
        elif [[ "$1" =~ ^14[bB]$ ]]; then
            test_14b
        elif [[ "$1" =~ ^14[cC]$ ]]; then
            test_14c
        elif [ "$1" = "cap" ]; then
            test_cap
        elif [ "$1" = "vs-e2e" ]; then
            test_vs_e2e "${2:-/tmp}"
        elif [ "$1" = "vs-move" ]; then
            test_vs_move "${2:-/tmp/test_sample}" "${3:-vs-$$}"
        elif [ "$1" = "vs-restore" ]; then
            test_vs_restore "${2:-/tmp/test_sample}" "${3:-vs-$$}"
        elif [ "$1" = "vs-remove" ]; then
            test_vs_remove "${2:-/tmp/test_sample}" "${3:-vs-$$}"
        elif [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 31 ]; then
            "test_$(printf '%02d' "$1")"
        else
            echo "无效参数: $1"
            echo "用法: $0 [?|help|all|write|stream|full|listen|<1-31>|w0-w15|vs-*|3b|4b|14b|14c|cap]"
            echo "试试: $0 ?  查看完整帮助"
            exit 1
        fi
        print_result
        ;;
esac
