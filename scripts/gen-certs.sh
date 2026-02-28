#!/bin/bash

# 生成自签名证书脚本
# 适用于测试环境，生产环境建议使用 Let's Encrypt 或商业证书

set -e

CERT_DIR="$(dirname "$0")/../certs"
mkdir -p "$CERT_DIR"

echo "Generating self-signed certificates..."

# 生成私钥
openssl genrsa -out "$CERT_DIR/key.pem" 2048

# 生成证书签名请求
openssl req -new -key "$CERT_DIR/key.pem" \
    -out "/tmp/cert.csr" \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# 生成自签名证书
openssl x509 -req -days 365 \
    -in "/tmp/cert.csr" \
    -signkey "$CERT_DIR/key.pem" \
    -out "$CERT_DIR/cert.pem"

# 清理
rm "/tmp/cert.csr"

echo "Certificates generated successfully!"
echo "Location: $CERT_DIR"
echo "  - cert.pem"
echo "  - key.pem"
