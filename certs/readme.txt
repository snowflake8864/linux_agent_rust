第一步：生成根证书（CA）
# 1. 生成 CA 私钥
openssl genrsa -out root-ca.key.pem 4096

# 2. 生成自签 CA 证书（有效期 10 年）
openssl req -x509 -new -nodes -key root-ca.key.pem -sha256 -days 3650 -out root-ca.pem \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=MyOrg/OU=Security/CN=MyRootCA"

第二步：生成服务器私钥与 CSR
# 1. 生成服务器私钥
openssl genrsa -out cert.key.pem 2048

# 2. 生成 CSR（证书签名请求）
openssl req -new -key cert.key.pem -out cert.csr.pem \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=MyOrg/OU=IT/CN=myserver.local"
第三步:创建扩展文件
cat > cert.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = myserver.local
IP.1 = 10.0.0.1
IP.2 = 10.0.0.2
IP.3 = 192.168.3.4
EOF


使用 CA 签发服务器证书
openssl x509 -req \
    -in cert.csr.pem \
    -CA root-ca.pem -CAkey root-ca.key.pem -CAcreateserial \
    -out cert.pem -days 3650 -sha256 -extfile cert.ext

