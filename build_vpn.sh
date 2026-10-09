#!/bin/bash
# 一次编出 MagicArmor_0（主程序）+ vpn-helper（VPN 拨号子进程）。
# 用法：./build_vpn.sh [target]   例：./build_vpn.sh aarch64-unknown-linux-musl
# 拨号子进程的厂商 SDK 目录按架构自动选择，也可用 FMVPN_SDK_DIR 覆盖；
# 找不到对应 SDK 时只编主程序并告警（VPN 为可选功能，不阻断主流程）。
set -e
cd "$(dirname "$0")"

TARGET="${1:-x86_64-unknown-linux-musl}"

case "$TARGET" in
    # x86_64 构建机即运行机，直接用 /opt/osec/vpn/lib
    x86_64-*)   DEFAULT_SDK="/opt/osec/vpn/lib" ;;
    aarch64-*)  DEFAULT_SDK="sdk/vpn-aarch64" ;;
    mips64el-*) DEFAULT_SDK="sdk/vpn-mips64el" ;;
    loongarch64-*) DEFAULT_SDK="sdk/vpn-loongarch64" ;;
    *)          DEFAULT_SDK="sdk/vpn-unknown" ;;
esac
SDK_DIR="${FMVPN_SDK_DIR:-$DEFAULT_SDK}"

echo "===== [1/2] 编译主程序 MagicArmor_0 ($TARGET) ====="
cargo zigbuild --target "$TARGET" --release

if [ -f "$SDK_DIR/libVpn.so" ]; then
    echo "===== [2/2] 编译拨号子进程 vpn-helper (SDK: $SDK_DIR) ====="
    FMVPN_SDK_DIR="$SDK_DIR" cargo zigbuild -p vpn-helper --target "$TARGET" --release
    echo "产物：target/$TARGET/release/{MagicArmor_0,vpn-helper}"
else
    echo "===== [2/2] 跳过 vpn-helper：$SDK_DIR/libVpn.so 不存在 ====="
    echo "如需 VPN 功能，请把该架构的 5 个 .so 放入 $SDK_DIR 后重跑，或 FMVPN_SDK_DIR=... ./build_vpn.sh $TARGET"
fi
