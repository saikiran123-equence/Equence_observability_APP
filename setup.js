const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

const envPath = path.join(__dirname, '.env');

async function ask(rl, question) {
  return new Promise(resolve => rl.question(question, resolve));
}

async function main() {
  console.log('\n========================================');
  console.log('   Equence Infra Monitor — Setup');
  console.log('========================================\n');

  if (fs.existsSync(envPath)) {
    console.log('.env already exists. Delete it and re-run to reconfigure.\n');
    return;
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  const port        = await ask(rl, 'Port to run on [5000]: ') || '5000';
  const sshPassword = await ask(rl, 'SSH password for your servers: ');

  rl.close();

  const secret = crypto.randomBytes(64).toString('hex');

  const envContent =
    `PORT=${port}\n` +
    `JWT_SECRET=${secret}\n` +
    `SSH_PASSWORD=${sshPassword}\n`;

  fs.writeFileSync(envPath, envContent);

  console.log('\n.env created successfully!');
  console.log(`\nNow run:  node backend/src/server.js`);
  console.log(`Then open: http://localhost:${port}\n`);
  console.log('Default login: username = ITinfra  (set your password on first login)\n');
}

main().catch(console.error);
