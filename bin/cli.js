#!/usr/bin/env node

/**
 * api-clawer — 网易云音乐客户端抓包工具
 *
 * 用法:
 *   npx api-clawer                    # 启动 (默认端口 3000 + 9000:9001)
 *   npx api-clawer --help             # 查看帮助
 *   npx api-clawer --version          # 查看版本
 *   npx api-clawer -p 8080            # 指定 HTTP 代理端口
 *   npx api-clawer -p 8080:8443       # 指定 HTTP + HTTPS 代理端口
 *   npx api-clawer -a 127.0.0.1       # 绑定地址
 */

const path = require('path');

// 确保 dotenv 加载项目根目录的 .env
process.env.DOTENV_CONFIG_PATH = path.resolve(__dirname, '..', '.env');
require('dotenv').config({ path: process.env.DOTENV_CONFIG_PATH });

const packageJson = require('../package.json');

// 简易参数解析
const args = process.argv.slice(2);
const flags = {
  help: args.includes('--help') || args.includes('-h'),
  version: args.includes('--version') || args.includes('-v'),
  port: null,
  address: null,
};

// 解析 -p/--port
const portIdx = args.findIndex(a => a === '-p' || a === '--port');
if (portIdx !== -1 && args[portIdx + 1] && !args[portIdx + 1].startsWith('-')) {
  flags.port = args[portIdx + 1];
}

// 解析 -a/--address
const addrIdx = args.findIndex(a => a === '-a' || a === '--address');
if (addrIdx !== -1 && args[addrIdx + 1] && !args[addrIdx + 1].startsWith('-')) {
  flags.address = args[addrIdx + 1];
}

if (flags.help) {
  console.log(`
  api-clawer v${packageJson.version} — 网易云音乐客户端抓包工具

  用法:
    npx api-clawer [选项]

  选项:
    -p, --port <http[:https]>  指定代理端口 (默认: 9000:9001)
    -a, --address <address>    绑定监听地址 (默认: 0.0.0.0)
    -v, --version              输出版本号
    -h, --help                 输出帮助信息

  环境变量:
    PORT=3000                  前端界面端口
    HOOK_PORT=9000:9001        代理服务器端口
    LOG_LEVEL=info             日志级别 (debug/info/warn/error)

  示例:
    npx api-clawer
    npx api-clawer -p 8080
    npx api-clawer -p 8080:8443 -a 127.0.0.1
`);
  process.exit(0);
}

if (flags.version) {
  console.log(packageJson.version);
  process.exit(0);
}

// 将 CLI 参数写入环境变量，供 server/app.js 读取
if (flags.port) process.env.HOOK_PORT = flags.port;
if (flags.address) process.env.ADDRESS = flags.address;
if (!process.env.PORT) process.env.PORT = '3000';

const { startServer } = require('../src/server/app');
const { startClient } = require('../src/client/app');

/** @type {import('http').Server[]} */
const servers = [];

const gracefulShutdown = async (signal) => {
  console.log(`\n收到 ${signal} 信号，正在关闭服务器...`);
  const closePromises = servers.map(s => new Promise(resolve => {
    s.close(() => resolve());
    setTimeout(() => resolve(), 5000);
  }));
  await Promise.all(closePromises);
  console.log('所有服务已关闭');
  process.exit(0);
};

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

(async () => {
  try {
    const [proxyResult, clientServer] = await Promise.all([
      startServer(),
      startClient()
    ]);
    if (proxyResult) {
      if (proxyResult.httpServer) servers.push(proxyResult.httpServer);
      if (proxyResult.httpsServer) servers.push(proxyResult.httpsServer);
    }
    servers.push(clientServer);
    console.log('所有服务启动完成！');
    console.log(`   前端界面: http://localhost:${process.env.PORT || 3000}`);
    console.log(`   HTTP 代理: http://localhost:${(flags.port || process.env.HOOK_PORT || '9000').split(':')[0]}`);
    console.log('   按 Ctrl+C 停止服务');
  } catch (error) {
    console.error('启动服务失败:', error);
    process.exit(1);
  }
})();
