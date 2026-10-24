// A small Express API as an AI assistant might write it.
const express = require('express');
const mysql = require('mysql2');
const axios = require('axios');
const { exec } = require('child_process');
const fs = require('fs');

const app = express();
app.use(express.json());

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'rootpassword123',
  database: 'shop',
});

app.get('/products', (req, res) => {
  db.query(`SELECT * FROM products WHERE name LIKE '%${req.query.q}%'`, (err, rows) => {
    res.json(rows);
  });
});

app.post('/convert', (req, res) => {
  exec('convert ' + req.body.file + ' out.png', () => res.send('ok'));
});

app.get('/weather', async (req, res) => {
  const r = await axios.get('http://api.weather-example.com/v1?city=' + req.query.city);
  res.json(r.data);
});

app.delete('/cache', (req, res) => {
  fs.rmSync('./cache', { recursive: true, force: true });
  res.send('cleared');
});

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
app.listen(3000, () => console.log('listening on 3000'));
