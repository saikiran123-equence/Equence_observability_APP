const WebSocket = require('ws');
const ws = new WebSocket('ws://localhost:3000');

ws.on('open', () => {
  console.log('Connected to WS');
  // Login first? Wait, WebSocket in server.js uses cookies for auth.
  // We need to login via HTTP first.
});
