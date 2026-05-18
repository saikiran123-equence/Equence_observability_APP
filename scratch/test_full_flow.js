const jwt = require('jsonwebtoken');
const WebSocket = require('ws');

const secret = '424cd825c0f01f956a34f0618e8ea2c8298d006f98f6ef872bccb025568474ccba3f2a8da5722a7095e4fdae694c6c5618264ccdd4493373c46214932f0763f2';
const token = jwt.sign({ username: 'ITinfra', group: 'infra' }, secret, { expiresIn: '1h' });

const ws = new WebSocket('ws://localhost:3000', {
  headers: {
    cookie: `token=${token}`
  }
});

ws.on('open', () => {
  console.log('Connected to WS');
  ws.send(JSON.stringify({ action: 'connect', serverId: 'METIS-111' }));
});

ws.on('message', (data) => {
  console.log('MSG:', data.toString());
  if (data.toString().includes('Connected via SSH')) {
    console.log('SUCCESS');
    process.exit(0);
  }
  if (data.toString().includes('Error')) {
    console.error('FAILED');
    process.exit(1);
  }
});

ws.on('error', (err) => {
  console.error('WS ERR:', err);
  process.exit(1);
});

setTimeout(() => {
  console.log('TIMEOUT');
  process.exit(1);
}, 10000);
