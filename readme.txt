sudo update-alternatives --config ctags
ctags -R --languages=Rust .
find . -name "*.rs" | xargs ctags -R --languages=Rust
find . -name "*.rs" >cscope.files
cscope -qbR

unset OPENSSL_DIR
export OPENSSL_DIR=/home/zebra/workspace/rustprj/aarch64/openssl
cargo zigbuild --release  --target aarch64-unknown-linux-gnu

