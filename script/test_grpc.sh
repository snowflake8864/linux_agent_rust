#!/bin/bash
# ============================================================================
# gRPC 接口测试脚本 — 可手动选择要测试的接口
# 用法:
#   ./test_grpc.sh              # 交互式菜单选择
#   ./test_grpc.sh <编号>        # 直接测试指定接口 (1-30, s1)
#   ./test_grpc.sh all           # 测试全部只读接口 (1-30)
#   ./test_grpc.sh write         # 测试写接口（需离线模式）
#   ./test_grpc.sh stream        # 测试流式接口 (17, 18, s1)
#   ./test_grpc.sh full          # 测试全部接口（读写+流）
#   ./test_grpc.sh listen [秒]   # 监听告警流
# ============================================================================

GRPC_ADDR="${GRPC_ADDR:-192.168.3.4:50051}"
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

check_online_status() {
    # 快速检查 agent 在线状态，返回 0=在线, 1=离线, 2=无法判断
    local output
    if output=$(grpcurl -plaintext -emit-defaults \
        -import-path "$PROTO_DIR" \
        -proto common.proto -proto agent_status.proto \
        -d '{}' -connect-timeout 2 -max-time 3 \
        "$GRPC_ADDR" agent_status.AgentStatusService/GetAgentStatus 2>&1); then
        if echo "$output" | grep -qi '"isOnline"[[:space:]]*:[[:space:]]*true'; then
            return 0  # 在线
        else
            return 1  # 离线
        fi
    fi
    return 2  # 无法判断
}

show_test_help() {
    local tid="$1"
    echo ""
    case "$tid" in
        # ── 只读接口 ──
        1|01)  echo -e "${CYAN}[1] AgentStatus${NC} — 获取 Agent 运行状态"
               echo "    包含: 在线状态、版本号、OS信息、防护天数、CPU/内存/磁盘、模块状态、deviceUid、hostName"
               echo "    用法: $0 1" ;;
        2|02)  echo -e "${CYAN}[2] Config${NC} — 获取 Agent 配置信息"
               echo "    返回当前心跳间隔(crontime)、设备标识等配置"
               echo "    用法: $0 2" ;;
        3|03)  echo -e "${CYAN}[3] ProcessPolicy${NC} — 获取进程黑白名单策略"
               echo "    参数: {\"isWhite\": 1} 白名单 / 0 黑名单"
               echo "    返回 hash_list 和 action 标志"
               echo "    用法: $0 3  (白名单)  | 手动: test_03b (黑名单)" ;;
        4|04)  echo -e "${CYAN}[4] PeripheralPolicy${NC} — 获取外设管控策略"
               echo "    参数: {\"isWhite\": 1} 白名单 / 0 黑名单"
               echo "    返回设备列表和 action 标志"
               echo "    用法: $0 4  (白名单)  | 手动: test_04b (黑名单)" ;;
        5|05)  echo -e "${CYAN}[5] IpBlockPolicy${NC} — 获取 IP 阻断策略"
               echo "    用法: $0 5" ;;
        6|06)  echo -e "${CYAN}[6] IpBlackPolicy${NC} — 获取 IP 黑名单策略"
               echo "    用法: $0 6" ;;
        7|07)  echo -e "${CYAN}[7] OutreachRules${NC} — 获取外联探测规则"
               echo "    用法: $0 7" ;;
        8|08)  echo -e "${CYAN}[8] DirPolicy${NC} — 获取目录防护策略"
               echo "    用法: $0 8" ;;
        9|09)  echo -e "${CYAN}[9] ExtortPolicy${NC} — 获取勒索软件防护策略"
               echo "    用法: $0 9" ;;
        10)    echo -e "${CYAN}[10] TrustDir${NC} — 获取信任目录列表"
               echo "    用法: $0 10" ;;
        11)    echo -e "${CYAN}[11] VirtualPort${NC} — 获取虚拟端口配置"
               echo "    用法: $0 11" ;;
        12)    echo -e "${CYAN}[12] BackupList${NC} — 获取 LVM 快照/备份列表"
               echo "    返回: backup_id, name, created_at, size_bytes"
               echo "    用法: $0 12" ;;
        13)    echo -e "${CYAN}[13] JumpStatus${NC} — 获取跳变机状态"
               echo "    用法: $0 13" ;;
        14)    echo -e "${CYAN}[14] ProcessList${NC} — 获取进程列表（支持按策略状态过滤）"
               echo "    参数: {\"limit\": N, \"sort_by\": \"pid\", \"filter_status\": 0-3}"
               echo "    filter_status: 0=全部(默认), 1=白名单, 2=黑名单, 3=未知"
               echo "    用法: $0 14 | 14b(白名单) | 14c(黑名单)" ;;
        15)    echo -e "${CYAN}[15] PortList${NC} — 获取端口列表"
               echo "    用法: $0 15" ;;
        16)    echo -e "${CYAN}[16] UsbDeviceList${NC} — 获取 USB 设备列表（支持 filter_status）"
               echo "    参数: {\"filter_status\": 0-3}, 0=全部, 1=白名单, 2=黑名单, 3=未知"
               echo "    用法: $0 16 | 16b(黑) | 16c(白) | 16d(未知)" ;;
        17)    echo -e "${CYAN}[17] PolicyWatch(流)${NC} — 订阅策略变更推送（流式）"
               echo "    服务端持续推送策略变更事件，需流式接收"
               echo "    用法: $0 17" ;;
        18)    echo -e "${CYAN}[18] Alert(流)${NC} — 订阅实时告警推送（流式）"
               echo "    服务端持续推送告警事件，type=0 订阅全部"
               echo "    用法: $0 18" ;;
        19)    echo -e "${CYAN}[19] 查询准入${NC} — 查询当前准入控制模式"
               echo "    返回: mode (0=OFF, 1=ON, 2=AUTO) 及生效状态"
               echo "    用法: $0 19" ;;
        20)    echo -e "${CYAN}[20] 准入-OFF${NC} — 关闭准入控制"
               echo "    用法: $0 20" ;;
        21)    echo -e "${CYAN}[21] 准入-ON${NC} — 开启准入控制"
               echo "    用法: $0 21" ;;
        22)    echo -e "${CYAN}[22] 准入-AUTO${NC} — 切换准入控制为自动模式"
               echo "    用法: $0 22" ;;
        23)    echo -e "${CYAN}[23] ExecutableList${NC} — 获取可执行文件列表（支持按策略状态过滤）"
               echo "    参数: {\"filter_status\": 0-3}, 0=全部, 1=白名单, 2=黑名单, 3=未知"
               echo "    用法: $0 23 | 23b(黑) | 23c(白) | 23d(未知)" ;;
        24)    echo -e "${CYAN}[24] VulnScan上报${NC} — 上报漏洞扫描结果"
               echo "    用法: $0 24" ;;
        25)    echo -e "${CYAN}[25] 历史告警(全部)${NC} — 查询所有历史告警"
               echo "    用法: $0 25  |  25b(仅外设)  | 25c(仅进程)  | 25d(按identifier)"
               echo "          25e(按handle_status_label)  | 25f(按时间范围)"
               echo "          25g(组合: 时间+类型+处置状态)" ;;
        26)    echo -e "${CYAN}[26] 历史告警(未处理)${NC} — 查询未处理的历史告警"
               echo "    用法: $0 26  |  26b(按identifier+未处理)" ;;
        27)    echo -e "${CYAN}[27] 告警处置(已处理)${NC} — 将告警标记为已处理"
               echo "    用法: $0 27" ;;
        28)    echo -e "${CYAN}[28] 告警处置(已忽略)${NC} — 将告警标记为已忽略"
               echo "    用法: $0 28  |  28b(批量已处理)";;
        29)    echo -e "${CYAN}[29] ProcessDefenseMode${NC} — 获取进程防护模式（读）"
               echo "    返回: mode (0=OFF, 1=MONITOR, 2=PROTECT)"
               echo "    用法: $0 29" ;;
        30)    echo -e "${CYAN}[30] PeripheralDefenseMode${NC} — 获取外设防护模式（读）"
               echo "    返回: mode (0=OFF, 1=MONITOR, 2=PROTECT)"
               echo "    用法: $0 30" ;;
        s1)    echo -e "${CYAN}[s1] VirusScan流${NC} — 病毒扫描双向流 (StreamControl)"
               echo "    双向流式接口，客户端发送扫描指令，服务端返回扫描结果"
               echo "    用法: $0 s1" ;;

        # ── 写接口 ──
        w1)    echo -e "${CYAN}[w1] UpdateConfig${NC} — 更新 Agent 配置（写）"
               echo "    参数: {\"crontime\": 120}"
               echo "    ⚠️  仅离线可用，在线返回 PERMISSION_DENIED"
               echo "    测试: 发送更新请求，验证在线/离线状态下的正确拒绝/允许" ;;
        w2)    echo -e "${CYAN}[w2] UpdateProcessPolicy${NC} — 更新进程黑白名单策略（写）"
               echo "    参数: {\"hash_list\": [\"abc123\"], \"action\": 1}  (0=移除,1=白,2=黑)"
               echo "    ⚠️  仅离线可用，在线返回 PERMISSION_DENIED" ;;
        w3)    echo -e "${CYAN}[w3] UpdatePeripheral${NC} — 更新外设策略（写）"
               echo "    参数: {\"devices\": [], \"action\": 1}  (0=移除,1=白,2=黑)"
               echo "    ⚠️  仅离线可用，在线返回 PERMISSION_DENIED" ;;
        w4)    echo -e "${CYAN}[w4] UpdateIpBlockPolicy${NC} — 更新 IP 阻断策略（写）"
               echo "    参数: {\"ip_list\": [\"10.0.0.1\"], \"is_white\": true}"
               echo "    ⚠️  仅离线可用，在线返回 PERMISSION_DENIED" ;;
        w5)    echo -e "${CYAN}[w5] SubmitTask${NC} — 下发任务（写）"
               echo "    参数: 任务类型、目标等"
               echo "    ⚠️  仅离线可用，在线返回 PERMISSION_DENIED" ;;
        w6)    echo -e "${CYAN}[w6] ExecuteIpJump${NC} — 执行 IP 跳变（写）"
               echo "    成功后自动刷新 jump.db"
               echo "    ⚠️  仅离线可用，在线返回 PERMISSION_DENIED" ;;
        w7)    echo -e "${CYAN}[w7] ExecutePwJump${NC} — 执行密码跳变（写）"
               echo "    成功后自动刷新 jump.db"
               echo "    ⚠️  仅离线可用，在线返回 PERMISSION_DENIED" ;;
        w8)    echo -e "${CYAN}[w8] CreateBackup${NC} — 创建 LVM 快照备份（写）"
               echo "    参数: {\"name\": \"backup_name\"}"
               echo "    实际调用 lvcreate 创建 LVM 快照"
               echo "    ⚠️  仅离线可用，在线返回 PERMISSION_DENIED" ;;
        w9)    echo -e "${CYAN}[w9] RestoreBackup${NC} — 还原 LVM 快照（写）"
               echo "    参数: {\"backup_id\": \"snap_suffix\"}"
               echo "    实际调用 lvconvert --merge 合并快照"
               echo "    ⚠️  仅离线可用，在线返回 PERMISSION_DENIED"
               echo "    注意: 如快照不存在则返回 NOT_FOUND" ;;
        w10)   echo -e "${CYAN}[w10] UpdateTrustDir${NC} — 更新信任目录（写）"
               echo "    ⚠️  仅离线可用，在线返回 PERMISSION_DENIED" ;;
        w11)   echo -e "${CYAN}[w11] UpdateVirtualPort${NC} — 更新虚拟端口（写）"
               echo "    ⚠️  仅离线可用，在线返回 PERMISSION_DENIED" ;;
        w12)   echo -e "${CYAN}[w12] UpdateDirPolicy${NC} — 更新目录防护策略（写）"
               echo "    ⚠️  仅离线可用，在线返回 PERMISSION_DENIED" ;;
        w13)   echo -e "${CYAN}[w13] UpdateExtortPolicy${NC} — 更新勒索防护策略（写）"
               echo "    ⚠️  仅离线可用，在线返回 PERMISSION_DENIED" ;;
        w14)   echo -e "${CYAN}[w14] UpdateProcessDefenseMode${NC} — 进程防护模式切换（写）"
               echo "    mode: 0=OFF(关闭)  1=MONITOR(只告警不阻止)  2=PROTECT(告警+阻止)"
               echo "    用法: $0 w14 {\"mode\": 0}  # 关闭"
               echo "          $0 w14 {\"mode\": 1}  # 监控"
               echo "          $0 w14 {\"mode\": 2}  # 保护"
               echo "    ⚠️  仅离线可用，在线返回 PERMISSION_DENIED" ;;
        w15)   echo -e "${CYAN}[w15] UpdatePeripheralDefenseMode${NC} — 外设防护模式切换（写）"
               echo "    mode: 0=OFF(关闭)  1=MONITOR(只告警不阻止)  2=PROTECT(告警+阻止)"
               echo "    用法: $0 w15 {\"mode\": 0}  # 关闭"
               echo "          $0 w15 {\"mode\": 1}  # 监控"
               echo "          $0 w15 {\"mode\": 2}  # 保护"
               echo "    ⚠️  仅离线可用，在线返回 PERMISSION_DENIED" ;;
          w16)   echo -e "${CYAN}[w16] TriggerLocalUpdate${NC} — 触发本地升级（自动扫描/指定包）"
              echo "    行为: 自动扫描 /opt/osec/upgrade/ 目录并触发升级，或指定 zipPath" 
              echo "    用法: $0 w16                # 自动扫描并触发本地升级"
              echo "          $0 w16 {\"zipPath\":\"/opt/osec/upgrade/update.zip\"}  # 指定升级包"
              echo "" ;;

          w17)   echo -e "${CYAN}[w17] DeleteBackup${NC} — 删除 LVM 快照（写）"
              echo "    参数: {\"backup_id\": \"snap_name_or_suffix\"}"
              echo "    实际调用 lvremove 删除 LVM 快照"
              echo "    ⚠️  仅离线可用，在线返回 PERMISSION_DENIED"
              echo "    注意: 如快照不存在则返回 NOT_FOUND"
              echo ""
              echo -e "    ${YELLOW}测试模式:${NC} w17        → 验证在线拒绝（固定 test_bak）"
              echo -e "    ${GREEN}执行模式:${NC} w17 {\"backup_id\":\"root_snap_6_20260626_155713\"} → 实际删除指定快照" ;;

        *)     echo -e "${RED}未知测试编号: $tid${NC}"
                echo "有效范围: 1-30, s1, w1-w17"
               echo "输入 ? 查看完整菜单，输入 <编号> ? 查看单项说明" ;;
    esac
    echo ""
}

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

# ── 只读接口测试 (1-30) ─────────────────────────────────────────────────

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

test_13() { grpc_call "跳变状态(读内存缓存,不请求服务器)" \
    jump.proto jump.JumpService GetJumpStatus; }

test_14() { grpc_call "进程列表(全部, 按PID排序)" \
    data_query.proto data_query.DataQueryService GetProcessList \
    '{"sort_by": "pid"}' \
    "peripheral_policy.proto"; }

test_14b() { grpc_call "进程列表(仅白名单)" \
    data_query.proto data_query.DataQueryService GetProcessList \
    '{"filter_status": 1}' \
    "peripheral_policy.proto"; }

test_14c() { grpc_call "进程列表(仅黑名单)" \
    data_query.proto data_query.DataQueryService GetProcessList \
    '{"filter_status": 2}' \
    "peripheral_policy.proto"; }

test_14d() { grpc_call "进程列表(仅未知)" \
    data_query.proto data_query.DataQueryService GetProcessList \
    '{"filter_status": 3}' \
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

test_23() { grpc_call "可执行文件列表(全部, MD5去重)" \
    data_query.proto data_query.DataQueryService GetExecutableList \
    '{}' "peripheral_policy.proto" 60; }

test_23b() { grpc_call "可执行文件列表(仅黑名单)" \
    data_query.proto data_query.DataQueryService GetExecutableList \
    '{"filter_status": 2}' "peripheral_policy.proto" 60; }

test_23c() { grpc_call "可执行文件列表(仅白名单)" \
    data_query.proto data_query.DataQueryService GetExecutableList \
    '{"filter_status": 1}' "peripheral_policy.proto" 60; }

test_23d() { grpc_call "可执行文件列表(仅未知)" \
    data_query.proto data_query.DataQueryService GetExecutableList \
    '{"filter_status": 3}' "peripheral_policy.proto" 60; }

test_24() { grpc_call "漏洞扫描上报(测试数据)" \
    vuln_scan.proto vuln_scan.VulnScanService PutVulnScan \
    '{"start_at":"2026-06-02 09:00:00","end_at":"2026-06-02 09:01:00","vuln_total":1,"vuln_list":[{"title":"CVE-TEST","severity":"LOW","file_path":"/usr/bin/test"}]}'; }

# 历史告警日志查询(分页)：客户端初始化时调用一次补读历史，随后用 SubscribeAlerts 接收新告警
test_25() { grpc_call "历史告警日志(全部/分页)" \
    alert.proto alert.AlertService GetAlertLogs \
    '{"handle_status": -1, "page": 1, "page_size": 20}'; }

test_25b() { grpc_call "历史告警日志(仅外设)" \
    alert.proto alert.AlertService GetAlertLogs \
    '{"handle_status": -1, "alert_type": 3, "page": 1, "page_size": 20}'; }

test_25c() { grpc_call "历史告警日志(仅进程)" \
    alert.proto alert.AlertService GetAlertLogs \
    '{"handle_status": -1, "alert_type": 1, "page": 1, "page_size": 20}'; }

test_26() { grpc_call "历史告警日志(未处理)" \
    alert.proto alert.AlertService GetAlertLogs \
    '{"handle_status": 0, "page": 1, "page_size": 20}'; }

# 新增: 按 identifier 过滤 (进程md5/外设eid)
test_25d() { grpc_call "历史告警日志(按identifier)" \
    alert.proto alert.AlertService GetAlertLogs \
    '{"page": 1, "page_size": 20, "identifier": "d41d8cd98f00b204e9800998ecf8427e"}'; }

# 新增: 按 handle_status_label 过滤 ("未处理"/"已处理"/"已忽略")
test_25e() { grpc_call "历史告警日志(按handle_status_label)" \
    alert.proto alert.AlertService GetAlertLogs \
    '{"page": 1, "page_size": 20, "handle_status_label": "未处理"}'; }

# 新增: 按时间范围过滤 (Unix时间戳秒)
test_25f() { grpc_call "历史告警日志(按时间范围)" \
    alert.proto alert.AlertService GetAlertLogs \
    '{"page": 1, "page_size": 20, "start_time": 1751234567, "end_time": 1751834567}'; }

# 新增: 组合过滤 (时间 + 告警类型 + 处置状态)
test_25g() { grpc_call "历史告警日志(组合:时间+类型+状态)" \
    alert.proto alert.AlertService GetAlertLogs \
    '{"page": 1, "page_size": 20, "handle_status": 0, "alert_type": 3, "start_time": 1751234567}'; }

# 新增: 按identifier + 未处理状态组合
test_26b() { grpc_call "历史告警日志(identifier+未处理)" \
    alert.proto alert.AlertService GetAlertLogs \
    '{"page": 1, "page_size": 20, "handle_status": 0, "identifier": "d41d8cd98f00b204e9800998ecf8427e"}'; }

# 告警处置：标记为已处理(handle_status=1)
test_27() { grpc_call "告警处置(标记已处理)" \
    alert.proto alert.AlertService HandleAlert \
    '{"id": 1, "handle_status": 1, "handle_user": "admin"}'; }

# 告警处置：标记为已忽略(handle_status=2)
test_28() { grpc_call "告警处置(标记已忽略)" \
    alert.proto alert.AlertService HandleAlert \
    '{"id": 1, "handle_status": 2, "handle_user": "admin"}'; }

# 批量处置：标记为已处理
test_28b() { grpc_call "告警处置(批量已处理)" \
    alert.proto alert.AlertService BatchHandleAlerts \
    '{"ids": [1, 2, 3], "handle_status": 1, "handle_user": "admin"}'; }

# 防护模式读取：29=进程防护模式, 30=外设防护模式
test_29() { grpc_call "进程防护模式(读)" \
    protection_mode.proto protection_mode.ProcessDefenseService GetProcessDefenseMode \
    '{}'; }

test_30() { grpc_call "外设防护模式(读)" \
    protection_mode.proto protection_mode.PeripheralDefenseService GetPeripheralDefenseMode \
    '{}'; }

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

test_w16() { grpc_call "TriggerLocalUpdate(自动扫描 /opt/osec/upgrade/)" \
    task_local.proto task_local.LocalTaskService TriggerLocalUpdate \
    '{"zipPath":""}'; }

test_w17() { grpc_expect_perm_denied "删除备份（在线拒绝）" \
    backup.proto backup.BackupService DeleteBackup \
    '{"backup_id":"test_bak"}'; }

# ── 写接口实际执行（离线模式下手动操作）───────────────────────────────
# 用法: exec_w17 '{"backup_id":"root_snap_6_20260626_155713"}'
# 菜单用法: w17 {"backup_id":"root_snap_6_20260626_155713"}
#
# 注意: 因为 bash ${1:-default} 中 default 含 {} 会导致解析错误，
# 所以改用变量 + set-default 模式。

_DEF_W1='{"crontime": 120}'
_DEF_W2='{"hash_list": ["abc123"], "action": 1}'
_DEF_W3='{"devices": [], "action": 1}'
_DEF_W4='{"items": [{"ip": "10.0.0.1", "direction": 1, "duration": 3600, "is_ipv6": false}]}'
_DEF_W5='{"task_ids": [6, 19]}'
_DEF_W6='{"gateway":"192.168.1.1","source_ip":"10.0.0.5","target_ip":"10.0.0.6","mode":1}'
_DEF_W7='{"new_password":"test123"}'
_DEF_W8='{"name":"test_bak"}'
_DEF_W9='{"backup_id":"abc123"}'
_DEF_W10='{"dirs": [{"dir":"/opt","type":1,"is_extend":0}]}'
_DEF_W11='{"rules": [{"alarm_level":1,"dest_ip":"192.168.1.1","dest_port":"80","dest_port_type":0,"id":1,"protocol":"tcp","source_ip":"10.0.0.1","source_port_start":8080,"source_port_end":8080,"type":"tcp"}]}'
_DEF_W12='{"rules": [{"dir":"/opt","pid":0,"typ":1}]}'
_DEF_W13='{"rules": [{"file_type":"doc","typ":1}]}'
_DEF_W14='{"mode": 2}'
_DEF_W15='{"mode": 2}'
_DEF_W17='{"backup_id":"test_bak"}'

exec_w1()  { grpc_call "更新配置"       config.proto         config.ConfigService                UpdateConfig               "${1:-$_DEF_W1}"; }
exec_w2()  { grpc_call "更新进程策略"    process_policy.proto process_policy.ProcessPolicyService  UpdateProcessPolicy         "${1:-$_DEF_W2}"; }
exec_w3()  { grpc_call "更新外设策略"    peripheral_policy.proto peripheral_policy.PeripheralPolicyService UpdatePeripheralPolicy "${1:-$_DEF_W3}"; }
exec_w4()  { grpc_call "更新IP阻断"     ip_policy.proto       ip_policy.IpPolicyService            UpdateIpBlockPolicy         "${1:-$_DEF_W4}"; }
exec_w5()  { grpc_call "下发任务"       task_local.proto      task_local.LocalTaskService          SubmitTask                  "${1:-$_DEF_W5}"; }
exec_w6()  { grpc_call "IP跳变"        jump.proto            jump.JumpService                     ExecuteIpJump               "${1:-$_DEF_W6}"; }
exec_w7()  { grpc_call "密码跳变"       jump.proto            jump.JumpService                     ExecutePwJump               "${1:-$_DEF_W7}"; }
exec_w8()  { grpc_call "创建备份"       backup.proto          backup.BackupService                 CreateBackup                "${1:-$_DEF_W8}"; }
exec_w9()  { grpc_call "还原备份"       backup.proto          backup.BackupService                 RestoreBackup               "${1:-$_DEF_W9}"; }
exec_w10() { grpc_call "更新信任目录"    trust_dir.proto       trust_dir.TrustDirService             UpdateTrustDir              "${1:-$_DEF_W10}"; }
exec_w11() { grpc_call "更新虚拟端口"    virtual_port.proto    virtual_port.VirtualPortService       UpdateVirtualPort           "${1:-$_DEF_W11}"; }
exec_w12() { grpc_call "更新目录保护策略" dir_policy.proto      dir_policy.DirPolicyService           UpdateDirPolicy             "${1:-$_DEF_W12}"; }
exec_w13() { grpc_call "更新勒索保护策略" extort_policy.proto   extort_policy.ExtortPolicyService     UpdateExtortPolicy          "${1:-$_DEF_W13}"; }
exec_w14() { grpc_call "进程防护模式"    protection_mode.proto protection_mode.ProcessDefenseService  UpdateProcessDefenseMode    "${1:-$_DEF_W14}"; }
exec_w15() { grpc_call "外设防护模式"    protection_mode.proto protection_mode.PeripheralDefenseService UpdatePeripheralDefenseMode "${1:-$_DEF_W15}"; }
exec_w17() { grpc_call "删除备份"       backup.proto          backup.BackupService                 DeleteBackup                "${1:-$_DEF_W17}"; }

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
    echo -e "${CYAN}║${NC}  25b)仅外设 25c)仅进程 25d)identifier 25e)label          ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  25f)时间范围 25g)组合 26b)identifier+未处理             ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  27) 告警处置(已处理) 28) 告警处置(已忽略)                  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  29) ProcessDefenseMode(读)  30) PeripheralDefenseMode(读)${CYAN}║${NC}"
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
        echo -e "${CYAN}║${NC}  w15) PeripheralDefenseMode  w16) TriggerLocalUpdate  w17) DeleteBackup                ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}                                                               ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}wN {json} 离线时实际执行写操作${NC}                                ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  例: w17 {\"backup_id\":\"snap_name\"}  → 实际删除快照           ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}all${NC}    测试全部只读接口 (1-30)                          ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${RED}write${NC}  测试全部写接口（验证在线拒绝）                    ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}stream${NC} 测试全部流式接口 (17, 18, s1)                   ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}full${NC}   测试全部接口（读写+流）                          ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}listen [秒]${NC} 监听告警流（默认300秒，Ctrl+C停止）         ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  q    退出                                              ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
}

run_all_readonly() {
    for i in $(seq -w 1 30); do
        fn="test_$(printf '%02d' $((10#$i)))"
        type "$fn" &>/dev/null && "$fn"
    done
    test_03b   # 黑名单
    test_04b   # 外设-黑名单
    test_14b   # 进程列表-仅白名单
    test_14c   # 进程列表-仅黑名单
    test_14d   # 进程列表-仅未知
    test_23b   # 可执行文件列表-仅黑名单
    test_23c   # 可执行文件列表-仅白名单
    test_23d   # 可执行文件列表-仅未知
    test_25d   # 历史告警-按identifier
    test_25e   # 历史告警-按handle_status_label
    test_25f   # 历史告警-按时间范围
    test_25g   # 历史告警-组合过滤
    test_26b   # 历史告警-identifier+未处理
}

run_all_write() {
    test_w1; test_w2; test_w3; test_w4; test_w5; test_w6; test_w7; test_w8
    test_w9; test_w10; test_w11; test_w12; test_w13; test_w14; test_w15; test_w17
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
        last_choice=""
        while true; do
            echo -ne "${CYAN}选择接口编号 > ${NC}"
            read -r choice

            # ── !! 重复上一条 / !N 历史命令 ──
            if [[ "$choice" == "!!" ]]; then
                if [ -z "$last_choice" ]; then
                    echo -e "${YELLOW}暂无上一条命令${NC}"
                    continue
                fi
                choice="$last_choice"
                echo -e "${CYAN}[!!]${NC} $choice"
            else
                last_choice="$choice"
            fi

            # ── 预检查: wN {...} 格式 → 实际执行写操作（非 PERMISSION_DENIED 测试）──
            if [[ "$choice" =~ ^(w[0-9]+)[[:space:]]+(\{.*\})$ ]]; then
                tid="${BASH_REMATCH[1]}"
                json="${BASH_REMATCH[2]}"
                if declare -f "exec_$tid" &>/dev/null; then
                    "exec_$tid" "$json"
                else
                    echo -e "${RED}未知执行命令: $tid${NC}"
                fi
                continue
            fi

            # ── 预检查: 14/23/json {...} → 自定义 filter_status ──
            if [[ "$choice" =~ ^(14|23|03|3|14b|14c|14d|23b|23c|23d|03b|04b)[[:space:]]+(\{.*\})$ ]]; then
                tid="${BASH_REMATCH[1]}"
                json="${BASH_REMATCH[2]}"
                case "$tid" in
                    14|14b|14c|14d)
                        grpc_call "进程列表(自定义)" data_query.proto data_query.DataQueryService GetProcessList "$json" "peripheral_policy.proto" ;;
                    23|23b|23c|23d)
                        grpc_call "可执行文件列表(自定义)" data_query.proto data_query.DataQueryService GetExecutableList "$json" "peripheral_policy.proto" 60 ;;
                    3|03|03b)
                        grpc_call "进程策略(自定义)" process_policy.proto process_policy.ProcessPolicyService GetProcessPolicy "$json" ;;
                    04b)
                        grpc_call "外设策略(自定义)" peripheral_policy.proto peripheral_policy.PeripheralPolicyService GetPeripheralPolicy "$json" ;;
                esac
                continue
            fi

            # ── 预检查: <编号> ? 格式 → 查看详细说明 ──
            if [[ "$choice" =~ ^(.+)\ ([\?]|help|h)$ ]]; then
                tid="${BASH_REMATCH[1]}"
                show_test_help "$tid"
                continue
            fi

            # "w16 <json>" direct TriggerLocalUpdate
            if [[ "$choice" =~ ^w16[[:space:]]+\{ ]]; then
                json_data="${choice#w16 }"
                echo -ne "${CYAN}[直接下发]${NC} TriggerLocalUpdate ... "
                output=$(grpcurl -plaintext -emit-defaults \
                    -import-path "$PROTO_DIR" \
                    -proto common.proto -proto task_local.proto \
                    -d "$json_data" \
                    -connect-timeout 3 -max-time 10 \
                    "$GRPC_ADDR" task_local.LocalTaskService/TriggerLocalUpdate 2>&1) && rc=0 || rc=1
                if [ $rc -eq 0 ]; then
                    echo -e "${GREEN}成功${NC}"
                    echo "$output" | sed 's/^/  /'
                else
                    echo -e "${RED}失败${NC}"
                    echo "$output" | sed 's/^/  /'
                fi
                continue
            fi

            case "$choice" in
                1)  test_01 ;; 2)  test_02 ;; 3)  test_03 ;; 4)  test_04 ;;
                5)  test_05 ;; 6)  test_06 ;; 7)  test_07 ;; 8)  test_08 ;;
                9)  test_09 ;; 10) test_10 ;; 11) test_11 ;; 12) test_12 ;;
                13) test_13 ;; 14) test_14 ;; 15) test_15 ;; 16) test_16 ;;
                17) test_17 ;; 18) test_18 ;; 19) test_19 ;; 20) test_20 ;;
                21) test_21 ;; 22) test_22 ;; 23) test_23 ;; 24) test_24 ;;
                25) test_25 ;; 26) test_26 ;;
                27) test_27 ;; 28) test_28 ;; 28b) test_28b ;;
                29) test_29 ;; 30) test_30 ;;
                s1) test_s1 ;;
                03b) test_03b ;; 14b) test_14b ;; 14c) test_14c ;; 14d) test_14d ;;
                04b) test_04b ;;
                25b) test_25b ;; 25c) test_25c ;; 25d) test_25d ;; 25e) test_25e ;;
                25f) test_25f ;; 25g) test_25g ;; 26b) test_26b ;;
                23b) test_23b ;; 23c) test_23c ;; 23d) test_23d ;;
                w1)  test_w1  ;; w2)  test_w2  ;; w3)  test_w3  ;; w4)  test_w4  ;;
                w5)  test_w5  ;; w6)  test_w6  ;; w7)  test_w7  ;; w8)  test_w8  ;;
                w9)  test_w9  ;; w10) test_w10 ;; w11) test_w11 ;; w12) test_w12 ;;
                w13) test_w13 ;; w14) test_w14 ;; w15) test_w15 ;; w16) test_w16 ;; w17) test_w17 ;;
                all)
                    echo -e "\n${GREEN}── 测试全部只读接口 (1-30) ──${NC}"
                    run_all_readonly
                    print_result
                    ;;
                write)
                    check_online_status
                    if [ $? -eq 0 ]; then
                        echo -e "\n${RED}── 测试全部写接口（在线模式，预期全部 PERMISSION_DENIED）──${NC}"
                    else
                        echo -e "\n${RED}── 测试全部写接口 ──${NC}"
                        echo -e "${YELLOW}⚠ 当前离线，写操作将通过 require_offline 检查，可能因其他原因失败${NC}"
                    fi
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
                    timeout --foreground "$secs" grpcurl -plaintext -emit-defaults \
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
                    echo "  25) 历史告警(全部)   25b) 仅外设  25c) 仅进程"
                    echo "  25d) 按identifier 25e) 按label 25f) 时间范围 25g) 组合"
                    echo "  26) 历史告警(未处理)  26b) identifier+未处理"
                    echo "  27) 告警处置(已处理)  28) 告警处置(已忽略)"
                    echo "  29) ProcessDefenseMode(读)  30) PeripheralDefenseMode(读)"
                    echo "  s1) VirusScan流"
                    echo ""
                    echo -e "${CYAN}── 扩展测试（filter_status / is_white 过滤）──${NC}"
                    echo "  03b) ProcessPolicy-黑名单    04b) PeripheralPolicy-黑名单"
                    echo "  14b) ProcessList-仅白名单    "
                    echo "  14c) ProcessList-仅黑名单     14d) ProcessList-仅未知"
                    echo "  23b) ExecutableList-黑名单    23c) ExecutableList-白名单"
                    echo "  23d) ExecutableList-未知"
                    echo ""
                    echo -e "${CYAN}── 写接口（仅离线可用，在线返回 PERMISSION_DENIED）──${NC}"
                    echo "   w1) UpdateConfig        w2) UpdateProcessPolicy"
                    echo "   w3) UpdatePeripheral    w4) UpdateIpBlockPolicy"
                    echo "   w5) SubmitTask          w6) ExecuteIpJump"
                    echo "   w7) ExecutePwJump       w8) CreateBackup"
                    echo "   w9) RestoreBackup      w10) UpdateTrustDir"
                    echo "  w11) UpdateVirtualPort  w12) UpdateDirPolicy"
                    echo "  w13) UpdateExtortPolicy w14) ProcessDefenseMode"
                    echo "  w15) PeripheralDefenseMode  w16) TriggerLocalUpdate  w17) DeleteBackup"
                    echo ""
                    echo -e "${CYAN}── 快捷命令 ──${NC}"
                    echo "  all    测试全部只读 (1-30)"
                    echo "  write  测试全部写 (w1-w17, 需离线模式)"
                    echo "  stream 测试全部流式 (17, 18, s1)"
                    echo "  full   测试全部 (读写+流)"
                    echo "  listen [秒]  监听告警流"
                    echo "  ?|h    显示此帮助    q    退出"
                    echo "  stat   快速查看在线状态"
                    echo ""
                    echo -e "${CYAN}── 查看详细说明 ──${NC}"
                    echo "  输入 \"<编号> ?\" 查看单个接口的详细说明"
                    echo "  例如: w17 ?   → 查看 DeleteBackup 的参数、行为、注意事项"
                    echo "        1 ?     → 查看 AgentStatus 返回内容说明"
                    echo "        w8 ?    → 查看 CreateBackup 详细说明"
                    echo ""
                    echo -e "${CYAN}── 实际执行写操作（离线模式）──${NC}"
                    echo "  输入 \"w<N> {json}\" 离线时实际执行写操作"
                    echo "  例如: w17 {\"backup_id\":\"root_snap_6_20260626_155713\"}"
                    echo "        w8  {\"name\":\"my_backup\"}"
                    echo ""
                    ;;
                q|Q|quit|exit) echo "退出"; break ;;
                stat)
                    check_online_status
                    case $? in
                        0) echo -e "当前状态: ${GREEN}在线${NC} (写操作应被拒绝)" ;;
                        1) echo -e "当前状态: ${RED}离线${NC} (写操作允许通过, w1-w17 测试将失败)" ;;
                        2) echo -e "当前状态: ${YELLOW}无法判断${NC} (连接失败或状态未知)" ;;
                    esac
                    ;;
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
        check_online_status
        if [ $? -eq 0 ]; then
            echo -e "\n${RED}── 测试写接口（在线模式，预期全部 PERMISSION_DENIED）──${NC}"
        else
            echo -e "\n${RED}── 测试写接口 ──${NC}"
            echo -e "${YELLOW}⚠ 当前离线，写操作将通过 require_offline 检查，可能因其他原因失败${NC}"
        fi
        run_all_write
        print_result
        ;;
    stream)
        run_all_stream
        print_result
        ;;
    full)
        check_online_status
        if [ $? -ne 0 ]; then
            echo -e "${YELLOW}⚠ 当前离线模式，w1-w17 写接口测试可能失败（非 PERMISSION_DENIED 错误）${NC}"
        fi
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
        echo "── 交互模式 ──"
        echo "  无参数           进入交互式菜单（推荐）"
        echo "  menu            同无参数"
        echo ""
        echo "  交互菜单内可用命令:"
        echo "    1-30, s1       测试指定只读/流式接口"
        echo "    03b,14b/14c/14d,23b  filter_status 过滤测试"
        echo "    w1-w17          测试指定写接口"
        echo "    all/write/stream/full  批量测试"
        echo "    stat            快速查看 Agent 在线状态"
        echo "    listen [秒]     监听告警流"
        echo "    <编号> ?        查看单个接口的详细说明"
        echo "    ?|h             显示菜单"
        echo "    q               退出"
        echo ""
        echo "── 命令行直接调用 ──"
        echo "  $0 1             直接测试 AgentStatus"
        echo "  $0 14c           直接测试 ProcessList(仅黑名单)"
        echo "  $0 23b           直接测试 ExecutableList(仅黑名单)"
        echo "  $0 s1            直接测试 VirusScan 双向流"
        echo "  $0 w8            直接测试 CreateBackup"
        echo "  $0 all           测试全部只读接口 (1-30)"
        echo "  $0 write         测试全部写接口 (w1-w17)"
        echo "  $0 stream        测试流式接口 (17, 18, s1)"
        echo "  $0 full          测试全部接口（读写+流）"
        echo "  $0 listen [秒]   监听告警流（默认300秒）"
        echo ""
        echo "── 写接口说明 ──"
        echo "  w1-w17 测试仅在 Agent ${RED}在线${NC}时验证 PERMISSION_DENIED 拒绝。"
        echo "  若 Agent 当前离线，写操作会通过 require_offline 检查，实际执行时"
        echo "  可能因参数无效/资源不存在等原因返回其他错误（非 PERMISSION_DENIED）。"
        echo "  使用 'stat' 命令或测试编号 1 查看当前在线状态。"
        echo ""
        echo "── 详细说明 ──"
        echo "  交互菜单中输入 '<编号> ?' 查看单个接口的参数、行为和注意事项。"
        echo "  例如: w16 ?  → DeleteBackup 详细说明"
        echo "        1 ?    → AgentStatus 返回内容说明"
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
            echo "用法: $0 [?|help|all|write|stream|full|listen|<1-30>|s1|w1-w17|menu]"
            echo "试试: $0 ?  查看完整帮助"
            exit 1
        fi
        print_result
        ;;
esac
