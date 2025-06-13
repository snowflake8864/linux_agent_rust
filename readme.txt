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
