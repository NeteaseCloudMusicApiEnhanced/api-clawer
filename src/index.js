// 主入口文件，同时启动 proxy server 和 frontend client
// 确保 Ctrl+C 时能够优雅地关闭所有服务

require('dotenv').config();

/** @type {import('http').Server[]} */
let servers = [];

/**
 * 优雅关闭所有服务器
 */
const gracefulShutdown = async (signal) => {
  console.log(`\n收到 ${signal} 信号，正在关闭服务器...`);

  const closePromises = servers.map(server => {
    return new Promise((resolve) => {
      server.close(() => {
        console.log('服务器已关闭');
        resolve();
      });
      // 设置超时，强制关闭
      setTimeout(() => resolve(), 5000);
    });
  });

  await Promise.all(closePromises);
  console.log('所有服务已关闭');
  process.exit(0);
};

// 监听退出信号
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

// 启动所有服务
const startAll = async () => {
  try {
    const { startServer } = require('./server/app');
    const { startClient } = require('./client/app');

    // 确保环境变量
    if (!process.env.PORT) process.env.PORT = '3000';

    const [proxyResult, clientServer] = await Promise.all([
      startServer(),
      startClient()
    ]);

    // 收集服务器实例以便优雅关闭
    if (proxyResult) {
      if (proxyResult.httpServer) servers.push(proxyResult.httpServer);
      if (proxyResult.httpsServer) servers.push(proxyResult.httpsServer);
    }
    servers.push(clientServer);

    console.log('所有服务启动完成！');
  } catch (error) {
    console.error('启动服务失败:', error);
    process.exit(1);
  }
};

startAll();
