const express = require('express');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
require('dotenv').config();

const CAPTURE_FILE = path.join(__dirname, '..', '..', 'captures.jsonl');

let capturedData = [];
let clients = [];

// ======================== 数据持久化 ========================

/**
 * 从文件加载历史数据
 */
function loadFromFile() {
  try {
    if (fs.existsSync(CAPTURE_FILE)) {
      const content = fs.readFileSync(CAPTURE_FILE, 'utf-8').trim();
      if (content) {
        capturedData = content.split('\n')
          .filter(line => line.trim())
          .map(line => {
            try { return JSON.parse(line); }
            catch { return null; }
          })
          .filter(Boolean);
        console.log(`Loaded ${capturedData.length} historical records from ${CAPTURE_FILE}`);
      }
    }
  } catch (e) {
    console.error('Failed to load capture file:', e.message);
  }
}

/**
 * 追加一条数据到文件
 */
function appendToFile(data) {
  try {
    fs.appendFileSync(CAPTURE_FILE, JSON.stringify(data) + '\n', 'utf-8');
  } catch (e) {
    console.error('Failed to append capture to file:', e.message);
  }
}

/**
 * 清空文件
 */
function clearFile() {
  try {
    fs.writeFileSync(CAPTURE_FILE, '', 'utf-8');
  } catch (e) {
    console.error('Failed to clear capture file:', e.message);
  }
}

// ======================== 请求重放 ========================

/**
 * 重放一个被抓包的请求
 * @param {object} param0 { path, method, params, crypto, rawPath, requestHeaders }
 * @returns {Promise<object>} 重放结果
 */
async function replayRequest({ path: apiPath, method, params, crypto, rawPath, requestHeaders }) {
  const cryptoModule = require('../server/crypto');
  const url = require('url');
  
  const baseUrl = 'https://music.163.com';
  const origPath = rawPath || apiPath;
  
  // 根据加密类型构造请求
  let requestUrl, requestBody, requestHeadersObj = {};
  
  switch (crypto) {
    case 'eapi': {
      const eapiPath = '/eapi' + apiPath.replace(/^\/api/, '');
      const encrypted = cryptoModule.eapi.encryptRequest(baseUrl + eapiPath, params);
      requestUrl = baseUrl + eapiPath;
      requestBody = encrypted.body;
      break;
    }
    case 'linuxapi': {
      const encrypted = cryptoModule.linuxapi.encryptRequest(apiPath, params);
      requestUrl = baseUrl + '/api/linux/forward';
      requestBody = encrypted.body;
      break;
    }
    case 'api': {
      requestUrl = baseUrl + apiPath;
      requestBody = new url.URLSearchParams(params).toString();
      requestHeadersObj['Content-Type'] = 'application/x-www-form-urlencoded';
      break;
    }
    default: {
      // weapi / 未知 -> 直接 POST JSON
      requestUrl = baseUrl + apiPath;
      requestBody = params;
      requestHeadersObj['Content-Type'] = 'application/json';
      break;
    }
  }

  // 合并原始请求头
  if (requestHeaders) {
    ['cookie', 'user-agent', 'referer', 'origin', 'x-real-ip'].forEach(key => {
      if (requestHeaders[key]) requestHeadersObj[key] = requestHeaders[key];
    });
  }
  if (!requestHeadersObj['User-Agent'] && !requestHeadersObj['user-agent']) {
    requestHeadersObj['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
  }
  requestHeadersObj['X-Real-IP'] = '118.88.88.88';

  const startTime = Date.now();
  const response = await axios.post(requestUrl, requestBody, {
    headers: requestHeadersObj,
    responseType: 'arraybuffer',
    timeout: 15000,
    httpsAgent: new (require('https').Agent)({ rejectUnauthorized: false }),
  });
  const duration = Date.now() - startTime;
  
  // 尝试解密响应
  let responseData = null;
  const resBuffer = Buffer.from(response.data);
  const contentType = response.headers['content-type'] || '';
  
  if (contentType.includes('json') || contentType.includes('text')) {
    try {
      responseData = JSON.parse(resBuffer.toString());
    } catch {
      // 非 JSON
    }
  }
  
  // 尝试 eapi 解密
  if (!responseData && resBuffer.length > 0) {
    try {
      const decrypted = cryptoModule.eapi.decrypt(resBuffer).toString();
      responseData = JSON.parse(decrypted);
    } catch {
      // 无法解密
    }
  }

  return {
    timestamp: new Date().toISOString(),
    path: apiPath,
    rawPath: origPath,
    crypto: crypto || 'replay',
    param: params,
    response: responseData,
    statusCode: response.status,
    method: method || 'POST',
    duration,
    requestHeaders: requestHeadersObj,
    responseHeaders: { ...response.headers },
    replay: true,
  };
}

// ======================== Express App ========================

/**
 * 创建前端 Express app (共享 capturedData 和 clients)
 */
function createApp() {
  const app = express();
  
  // 启动时加载历史数据
  loadFromFile();
  
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ limit: '10mb', extended: true }));
  app.use(express.static(path.join(__dirname, 'public')));

  app.post('/api/capture', (req, res) => {
    const data = req.body;
    capturedData.push(data);
    console.log('Captured data:', data.path);
    // 持久化
    appendToFile(data);
    broadcastData();
    res.status(200).send('OK');
  });

  app.get('/api/data', (req, res) => {
    res.json(capturedData);
  });

  app.get('/api/version', (req, res) => {
    try {
      const packageJson = require('../../package.json');
      res.json({ version: packageJson.version });
    } catch (error) {
      console.error('Failed to read package.json:', error);
      res.json({ version: '0.1.0' });
    }
  });

  app.post('/api/clear', (req, res) => {
    capturedData = [];
    clearFile();
    broadcastData();
    res.json({ success: true });
  });

  // 请求重放端点
  app.post('/api/replay', async (req, res) => {
    const { path: apiPath, method, params, crypto, rawPath, requestHeaders } = req.body;
    
    if (!apiPath) {
      return res.status(400).json({ error: 'Missing path' });
    }

    try {
      const result = await replayRequest({ path: apiPath, method, params, crypto, rawPath, requestHeaders });
      // 将重放结果也加入抓包列表
      capturedData.push(result);
      appendToFile(result);
      broadcastData();
      res.json(result);
    } catch (e) {
      console.error('Replay failed:', e.message);
      res.status(500).json({ error: e.message });
    }
  });

  // 获取/设置完整抓包模式
  app.get('/api/settings', (req, res) => {
    res.json({
      fullCapture: global.fullCapture === true,
    });
  });

  app.post('/api/settings', (req, res) => {
    const { fullCapture } = req.body;
    if (typeof fullCapture === 'boolean') {
      global.fullCapture = fullCapture;
      console.log(`Full capture mode: ${fullCapture ? 'ON' : 'OFF'}`);
      res.json({ success: true, fullCapture });
    } else {
      res.status(400).json({ error: 'fullCapture must be boolean' });
    }
  });

  // 获取数据统计信息
  app.get('/api/stats', (req, res) => {
    const total = capturedData.length;
    const methods = {};
    const cryptos = {};
    const statusGroups = {};
    capturedData.forEach(item => {
      const m = (item.method || 'UNKNOWN').toUpperCase();
      methods[m] = (methods[m] || 0) + 1;
      const c = item.crypto || 'unknown';
      cryptos[c] = (cryptos[c] || 0) + 1;
      const sg = String(item.statusCode || '?')[0] + 'xx';
      statusGroups[sg] = (statusGroups[sg] || 0) + 1;
    });
    res.json({ total, methods, cryptos, statusGroups });
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

  return app;
}

function broadcastData() {
  clients.forEach(client => {
    try {
      client.write(`data: ${JSON.stringify(capturedData)}\n\n`);
    } catch (e) {
      clients = clients.filter(c => c !== client);
    }
  });
}

/**
 * 启动前端服务器
 * @returns {Promise<import('http').Server>}
 */
function startClient(port) {
  return new Promise((resolve, reject) => {
    const PORT = port || process.env.PORT || 3000;
    const app = createApp();
    const server = app.listen(PORT, () => {
      console.log(`Frontend server running at http://localhost:${PORT}`);
      resolve(server);
    });
    server.on('error', reject);
  });
}

// 直接运行时启动
if (require.main === module) {
  startClient();
}

module.exports = { startClient, createApp };