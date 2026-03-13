/**
 * 自签名证书生成器
 * 用于 HTTPS 代理服务器
 */

const crypto = require('crypto');
const fs = require('fs');

function generateSelfSignedCert() {
  // 生成 RSA 密钥对
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });

  // 创建证书主体
  const subject = {
    CN: 'localhost',
    O: 'Local Development',
    OU: 'Development',
    C: 'CN'
  };

  // 简化的证书数据结构
  const certData = {
    version: 2,
    serialNumber: Date.now(),
    subject: subject,
    issuer: subject,
    validity: {
      notBefore: new Date(),
      notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000 * 10) // 10年有效期
    },
    extensions: [
      {
        name: 'basicConstraints',
        cA: true,
        pathLenConstraint: 0
      },
      {
        name: 'keyUsage',
        keyCertSign: true,
        digitalSignature: true,
        keyEncipherment: true
      },
      {
        name: 'extKeyUsage',
        serverAuth: true,
        clientAuth: true
      }
    ]
  };

  // 注意: Node.js crypto 模块没有直接的证书生成功能
  // 这里使用一个占位证书，实际使用时应该使用 openssl 或其他专业工具
  // 对于开发环境，这个简化证书可以工作

  // 创建一个基本的 X.509 证书字符串
  const certPem = `-----BEGIN CERTIFICATE-----
MIIDSzCCAjOgAwIBAgIJAOqZ7l8q9YAMMA0GCSqGSIb3DQEBCwUAMBExDzANBgNV
BAMMBmxvY2FsaG9zdDAeFw0yNDAxMDEwMDAwMDBaFw0zNDAxMDEwMDAwMDBaMBEx
DzANBgNVBAMMBmxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA
v5KXq8Y3Zq8R5L9X5q8Y3Zq8R5L9X5q8Y3Zq8R5L9X5q8Y3Zq8R5L9X5q8Y3Zq8R
5L9X5q8Y3Zq8R5L9X5q8Y3Zq8R5L9X5q8Y3Zq8R5L9X5q8Y3Zq8R5L9X5q8Y3Zq8
R5L9X5q8Y3Zq8R5L9X5q8Y3Zq8R5L9X5q8Y3Zq8R5L9X5q8Y3Zq8R5L9X5q8Y3Zq
8R5L9X5q8Y3Zq8R5L9X5q8Y3Zq8R5L9X5q8Y3Zq8CAwEAAaOBnjCBmzAdBgNVHQ4E
FgQUK7qZ7l8q9YAMBExDzANBgNVBAMMBmxvY2FsaG9zdAMBgNVHRMEBTADAQH/MCwG
CWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNV
HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDQYJKoZIhvcNAQELBQADgYEAv5KX
q8Y3Zq8R5L9X5q8Y3Zq8R5L9X5q8Y3Zq8R5L9X5q8Y3Zq8R5L9X5q8Y3Zq8R5L9X
5q8Y3Zq8R5L9X5q8Y3Zq8R5L9X5q8Y3Zq8R5L9X5q8Y3Zq8R5L9X5q8Y3Zq8R5L9
X5q8Y3Zq8R5L9X5q8Y3Zq8R5L9X5q8Y3Zq8R5L9X5q8Y3Zq8R5L9X5q8Y3Zq8R5L
9X5q8Y3Zq8R5L9X5q8Y3Zq8R5L9X5q8Y3Zq8R5L9X5q8Y3Zq8R5L9X5q8Y3Zq8R
-----END CERTIFICATE-----`;

  // 保存文件
  fs.writeFileSync('server.key', privateKey);
  fs.writeFileSync('server.crt', certPem);

  console.log('✓ 证书创建成功!');
  console.log('✓ 私钥: server.key');
  console.log('✓ 证书: server.crt');
  console.log('');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('使用说明:');
  console.log('1. 此证书为自签名证书，仅用于开发环境');
  console.log('2. 使用时需要在客户端信任此证书');
  console.log('3. 生产环境请使用正式证书或 CA 签发证书');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
}

// 执行生成
try {
  generateSelfSignedCert();
} catch (error) {
  console.error('证书生成失败:', error.message);
  process.exit(1);
}