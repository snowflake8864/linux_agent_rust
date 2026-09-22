use std::env;
use std::path::PathBuf;

fn main() {
    // SDK .so 目录优先级：FMVPN_SDK_DIR（交叉编译指定架构 SDK）>
    // /opt/osec/vpn/lib（本机运行目录）> cpesdk 源码目录。
    // 注意不能反过来：本机 /opt/osec/vpn/lib 是 x86_64 库，交叉编 aarch64 时
    // 若优先用它，lld 会报 "is incompatible with aarch64linux"。
    let sdk_dir = env::var("FMVPN_SDK_DIR")
        .ok()
        .filter(|d| !d.is_empty() && PathBuf::from(format!("{}/libVpn.so", d)).exists())
        .unwrap_or_else(|| {
            if PathBuf::from("/opt/osec/vpn/lib/libVpn.so").exists() {
                "/opt/osec/vpn/lib".to_string()
            } else {
                "/home/zebra/workspace/rustprj/cpesdk".to_string()
            }
        });

    println!("cargo:rustc-link-search=native={}", sdk_dir);
    println!("cargo:rustc-link-lib=dylib=Vpn");
    println!("cargo:rustc-link-lib=dylib=cosignsdk");
    println!("cargo:rustc-link-lib=dylib=fmssl");
    println!("cargo:rustc-link-lib=dylib=fmcrypto");
    println!("cargo:rustc-link-lib=dylib=ecc");
    // 运行机目录 rpath，方便直接运行
    println!("cargo:rustc-link-arg=-Wl,-rpath,/opt/osec/vpn/lib");
    println!("cargo:rerun-if-env-changed=FMVPN_SDK_DIR");
}
