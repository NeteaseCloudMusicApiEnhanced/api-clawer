// 主入口文件，同时启动 server 和 client
// 确保 Ctrl+C 时能够优雅地关闭所有服务

require('dotenv').config();

const http = require('http');
const https = require('https');

// 保存服务器引用以便关闭
let servers = [];

// 代理 server.app.js
const startServer = () => {
  return new Promise((resolve, reject) => {
    const packageJson = require('../package.json');
    const config = require('./server/cli.js')
      .program({
        name: packageJson.name.replace(/@.+\//, ''),
        version: packageJson.version,
      })
      .option(['-v', '--version'], { action: 'version' })
      .option(['-p', '--port'], {
        metavar: 'http[:https]',
        help: 'specify server port',
      })
      .option(['-a', '--address'], {
        metavar: 'address',
        help: 'specify server host',
      })
      .option(['-h', '--help'], { action: 'help' })
      .parse(process.argv);

    global.address = config.address;
    config.port = (config.port || process.env.HOOK_PORT || '9000')
      .split(':')
      .map((string) => parseInt(string));
    const invalid = (value) => isNaN(value) || value < 1 || value > 65535;
    if (config.port.some(invalid)) {
      console.log('Port must be a number higher than 0 and lower than 65535.');
      process.exit(1);
    }

    if (!process.env.PORT) {
      process.env.PORT = process.env.PORT || '3000';
    }

    const { logScope } = require('./server/logger');
    const escape = require('querystring').escape;
    const hook = require('./server/hook');
    const server = require('./server/server');
    const logger = logScope('app');
    const target = Array.from(hook.target.host);

    global.port = config.port;
    global.proxy = null;
    global.hosts = {};
    global.endpoint = 'https://music.163.com';

    server.whitelist = [
      '://[\w.]*music\\.126\\.net',
      '://[\w.]*vod\\.126\\.net',
      '://acstatic-dun.126.net',
      '://[\w.]*\\.netease\\.com',
      '://[\w.]*\\.163yun\\.com',
    ];

    if (config.endpoint) server.whitelist.push(escape(config.endpoint));

    const dns = (host) =>
      new Promise((resolve, reject) =>
        require('dns').lookup(host, { all: true }, (error, records) =>
          error
            ? reject(error)
            : resolve(records.map((record) => record.address))
        )
      );

    Promise.all(target.map(dns))
      .then((result) => {
        const { host } = hook.target;
        result.forEach((array) => array.forEach(host.add, host));
        server.whitelist = server.whitelist.concat(
          Array.from(host).map(escape)
        );
        const log = (type) =>
          logger.info(
            `${['HTTP', 'HTTPS'][type]} Server running @ http://${
              address || '0.0.0.0'
            }:${port[type]}`
          );
        if (port[0]) {
          const httpServer = server.http
            .listen(port[0], address)
            .once('listening', () => {
              log(0);
              servers.push(httpServer);
            });
        }
        if (port[1]) {
          const httpsServer = server.https
            .listen(port[1], address)
            .once('listening', () => {
              log(1);
              servers.push(httpsServer);
            });
        }
        resolve();
      })
      .catch((error) => {
        console.log(error);
        reject(error);
      });
  });
};

// 启动 client
const startClient = () => {
  return new Promise((resolve, reject) => {
    const express = require('express');
    const path = require('path');

    const app = express();
    const PORT = process.env.PORT || 3000;

    let capturedData = [];
    let clients = [];

    app.use(express.json({ limit: '10mb' }));
    app.use(express.urlencoded({ limit: '10mb', extended: true }));
    app.use(express.static(path.join(__dirname, 'client/public')));

    app.post('/api/capture', (req, res) => {
      const data = req.body;
      capturedData.push(data);
      console.log('Captured data:', data.path);
      
      broadcastData();
      
      res.status(200).send('OK');
    });

    app.get('/api/data', (req, res) => {
      res.json(capturedData);
    });

    app.get('/api/events', (req, res) => {
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');

      res.write(`data: ${JSON.stringify(capturedData)}\n\n`);

      clients.push(res);

      req.on('close', () => {
        clients = clients.filter(client => client !== res);
      });
    });

    function broadcastData() {
      clients.forEach(client => {
        try {
          client.write(`data: ${JSON.stringify(capturedData)}\n\n`);
        } catch (e) {
          clients = clients.filter(c => c !== client);
        }
      });
    }

    const clientServer = app.listen(PORT, () => {
      console.log(`Frontend server running at http://localhost:${PORT}`);
      servers.push(clientServer);
      resolve();
    });

    clientServer.on('error', reject);
  });
};

// 优雅关闭所有服务器
const gracefulShutdown = async (signal) => {
  console.log(`\n收到 ${signal} 信号，正在关闭服务器...`);

  // 关闭所有服务器
  const closePromises = servers.map(server => {
    return new Promise((resolve) => {
      server.close(() => {
        console.log('服务器已关闭');
        resolve();
      });
      // 设置超时，强制关闭
      setTimeout(() => {
        resolve();
      }, 5000);
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
    await Promise.all([
      startServer(),
      startClient()
    ]);
    console.log('所有服务启动完成！');
  } catch (error) {
    console.error('启动服务失败:', error);
    process.exit(1);
  }
};

startAll();