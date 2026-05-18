const { Client } = require('ssh2');
require('dotenv').config();

const conn = new Client();
conn.on('ready', () => {
  console.log('Client :: ready');
  conn.exec('uptime', (err, stream) => {
    if (err) throw err;
    stream.on('data', (data) => {
      console.log('STDOUT: ' + data);
    }).on('close', (code, signal) => {
      console.log('Stream :: close :: code: ' + code + ', signal: ' + signal);
      conn.end();
    });
  });
}).on('error', (err) => {
  console.error('SSH Error: ' + err.message);
}).connect({
  host: '192.168.90.111',
  port: 22612,
  username: 'maintenance',
  password: process.env.SSH_PASSWORD,
  readyTimeout: 10000
});
