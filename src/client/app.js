const express = require('express');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

let capturedData = [];
let clients = [];

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/capture', (req, res) => {
  const data = req.body;
  capturedData.push(data);
  console.log('Captured data:', data.path);
  
  // 通知所有 SSE 客户端有新数据
  broadcastData();
  
  res.status(200).send('OK');
});

app.get('/api/data', (req, res) => {
  res.json(capturedData);
});

// SSE 端点
app.get('/api/events', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  // 立即发送当前数据
  res.write(`data: ${JSON.stringify(capturedData)}\n\n`);

  // 添加到客户端列表
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
      // 连接已断开，移除客户端
      clients = clients.filter(c => c !== client);
    }
  });
}

app.listen(PORT, () => {
  console.log(`Frontend server running at http://localhost:${PORT}`);
});