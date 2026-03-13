import ssl
import socket
from datetime import datetime, timedelta

# 生成自签名证书
certfile = "server.crt"
keyfile = "server.key"

# 创建上下文
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

# 生成自签名证书
pkey = ssl._ssl._ssl_context.keygen(2048)

# 创建证书
cert = ssl._ssl._ssl_context.certgen(
    pkey,
    certfile,
    keyfile,
    CAfile=None,
    notBefore=datetime.now(),
    notAfter=datetime.now() + timedelta(days=3650),
    serialNumber=1,
)

print("✓ 证书创建成功!")
print("✓ 私钥: server.key")
print("✓ 证书: server.crt")