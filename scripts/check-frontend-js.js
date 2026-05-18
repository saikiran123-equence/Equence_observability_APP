const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const htmlPath = path.resolve(__dirname, '../frontend/public/index.html');
const html = fs.readFileSync(htmlPath, 'utf8');
const inlineScripts = [];
const scriptPattern = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
let match;

while ((match = scriptPattern.exec(html)) !== null) {
  const attributes = match[1] || '';
  if (/\bsrc\s*=/.test(attributes)) continue;
  inlineScripts.push(match[2]);
}

if (inlineScripts.length === 0) {
  console.log('No inline frontend scripts found to check.');
  process.exit(0);
}

const tempFile = path.join(os.tmpdir(), `frontend-inline-${process.pid}.js`);
fs.writeFileSync(tempFile, inlineScripts.join('\n'), 'utf8');
const result = spawnSync(process.execPath, ['--check', tempFile], { stdio: 'inherit' });
fs.rmSync(tempFile, { force: true });

if (result.error) {
  console.error(result.error.message);
  process.exit(1);
}

process.exit(result.status ?? 1);
