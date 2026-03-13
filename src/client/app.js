const express = require('express');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

let capturedData = [];

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/capture', (req, res) => {
  const data = req.body;
  capturedData.push(data);
  console.log('Captured data:', data.path);
  res.status(200).send('OK');
});

app.get('/api/data', (req, res) => {
  res.json(capturedData);
});

app.listen(PORT, () => {
  console.log(`Frontend server running at http://localhost:${PORT}`);
});