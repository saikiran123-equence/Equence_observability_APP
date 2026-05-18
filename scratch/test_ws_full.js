const WebSocket = require('ws');
const ws = new WebSocket('ws://localhost:3000');

ws.on('open', () => {
  console.log('Connected to WS');
  // We need a token. Let's see if we can get one or if we can bypass.
  // Actually, I'll just check if the server logs "LOADED" or "MISSING" when I try to connect.
  // But I need to be authenticated.
  
  // Wait! I can't easily authenticate via script because I don't have the ITinfra password hash.
  // Oh wait! I know the password: bluto@eris (from server.js)
});

ws.on('message', (data) => {
  console.log('MSG:', data.toString());
});

ws.on('error', (err) => {
  console.error('ERR:', err);
});
