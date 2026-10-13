use std::env;
use std::path::PathBuf;

fn main() {
    // SDK .so 目录优先级：
    //   1. FMVPN_SDK_DIR —— 显式覆盖（交叉编译时指定）
    //   2. 仓库内 vpn/lib_<arch> —— 按目标架构自动选择（arch 来自 CARGO_CFG_TARGET_ARCH）
    //   3. /opt/osec/vpn/lib —— 本机运行目录（仅当目标 == 宿主 x86_64 时才安全）
    //   4. cpesdk 源码目录 —— 兜底
    // 关键：交叉编译（如 aarch64）绝不能落到 /opt/osec/vpn/lib 的 x86_64 库，
    // 否则 lld 报 "is incompatible with aarch64linux"。
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let repo_root = PathBuf::from(&manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    // 目标架构 → vpn/lib_<tag> 目录名
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let arch_lib = match arch.as_str() {
        "x86_64" => Some("vpn/lib_x86_64"),
        "aarch64" => Some("vpn/lib_aarch64"),
        "loongarch64" => Some("vpn/lib_loongarch64"),
        _ => None,
    };

    let sdk_dir = env::var("FMVPN_SDK_DIR")
        .ok()
        .filter(|d| !d.is_empty() && PathBuf::from(format!("{}/libVpn.so", d)).exists())
        .or_else(|| {
            arch_lib
                .map(|rel| repo_root.join(rel))
                .filter(|d| d.join("libVpn.so").exists())
                .map(|d| d.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| {
            if arch == "x86_64" && PathBuf::from("/opt/osec/vpn/lib/libVpn.so").exists() {
                "/opt/osec/vpn/lib".to_string()
            } else {
                "/home/zebra/workspace/rustprj/cpesdk".to_string()
            }
        });

    println!("cargo:warning=vpn-helper SDK 目录: {}", sdk_dir);
    println!("cargo:rustc-link-search=native={}", sdk_dir);
    println!("cargo:rustc-link-lib=dylib=Vpn");
    println!("cargo:rustc-link-lib=dylib=cosignsdk");
    println!("cargo:rustc-link-lib=dylib=fmssl");
    println!("cargo:rustc-link-lib=dylib=fmcrypto");
    println!("cargo:rustc-link-lib=dylib=ecc");
    // 运行机目录 rpath，方便直接运行（/opt/osec/vpn/lib 是安装后的运行时目录）
    println!("cargo:rustc-link-arg=-Wl,-rpath,/opt/osec/vpn/lib");
    println!("cargo:rerun-if-env-changed=FMVPN_SDK_DIR");
}