sudo update-alternatives --config ctags
ctags -R --languages=Rust .
find . -name "*.rs" | xargs ctags -R --languages=Rust
find . -name "*.rs" >cscope.files
cscope -qbR

unset OPENSSL_DIR
export OPENSSL_DIR=/home/zebra/workspace/rustprj/aarch64/openssl
cargo zigbuild --release  --target aarch64-unknown-linux-gnu


# 设置环境变量
unset RUSTFLAGS
export LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:/usr/lib/gcc/x86_64-linux-gnu/12:$LD_LIBRARY_PATH
export RUSTFLAGS="-L /usr/lib/x86_64-linux-gnu -L /usr/lib/gcc/x86_64-linux-gnu/12"
export CC=/usr/bin/gcc-12
export CXX=/usr/bin/g++-12

export PATH=$PATH:/home/zebra/mips-linux-musl-cross/bin
export PATH=$PATH:/home/zebra/mipsel-linux-muslsf-cross/bin

cargo zigbuild --target x86_64-unknown-linux-musl --release

cargo +nightly build --release -Z build-std --target mips-unknown-linux-musl
cargo +nightly build --release -Z build-std --target mipsel-unknown-linux-musl


https://blog.habets.se/2024/04/Cross-compiling-Rust-fixed.html
https://harrychen.xyz/2023/09/03/cross-compile-rust-to-mipsel



================
rustup toolchain install nightly
rustup default nightly  # 临时切换工具链:ml-citation{ref="7" data="citationList"}

rustup target add mips64el-unknown-linux-gnuabi64  :ml-citation{ref="7" data="citationList"}

rustup target list | grep mips64el


rust-toolchain.toml
[toolchain]
channel = "nightly"
targets = ["mips64el-unknown-linux-gnuabi64"]  :ml-citation{ref="7" data="citationList"}



cargo build -Z build-std --target mips64el-unknown-linux-gnuabi64  :ml-citation{ref="7" data="citationList"}
================


这个错误表明在交叉编译Rust项目到MIPS64架构时，链接器遇到了ELF格式的重定位问题。以下是解决方案：

🔧 ‌核心解决方法‌

检查工具链一致性‌
确保使用的Rust目标平台(mips64el-unknown-linux-gnuabi64)与C交叉编译器(mips64el-linux-gnuabi64-gcc)完全匹配：

bash
Copy Code
which mips64el-linux-gnuabi64-gcc  # 确认路径
rustup show                         # 确认Rust目标平台


显式指定ABI模式‌
在编译命令中添加-C target-feature=+mabi64参数强制使用64位ABI：

bash
Copy Code
RUSTFLAGS="-C target-feature=+mabi64" cargo build --target=mips64el-unknown-linux-gnuabi64 :ml-citation{ref="1,9" data="citationList"}


清理并重建项目‌
删除可能冲突的中间文件：

bash
Copy Code
cargo clean
rm -rf target

⚠️ ‌常见问题排查‌
工具链版本冲突‌：检查C编译器与Rust目标平台的ABI兼容性（如mabi=64参数是否一致）
依赖库格式错误‌：若项目依赖C库，需用相同工具链重新编译依赖项
链接器路径错误‌：在.cargo/config.toml中显式指定链接器路径：
toml
Copy Code
[target.mips64el-unknown-linux-gnuabi64]
linker = "/usr/bin/mips64el-linux-gnuabi64-gcc" :ml-citation{ref="4,9" data="citationList"}

📌 ‌替代方案‌

若问题持续，可尝试通过cross工具链容器化编译：

bash
Copy Code
cargo install cross
cross build --target mips64el-unknown-linux-gnuabi64 :ml-citation{ref="4" data="citationList"}


此方法可隔离主机环境差异，自动处理工具链依赖。


sudo apt update
sudo apt install gcc-mipsel-linux-gnu g++-mipsel-linux-gnu
