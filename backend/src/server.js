require('dotenv').config({ path: require('path').resolve(__dirname, '../../.env') });
const express = require('express');
const { WebSocketServer } = require('ws');
const { Client } = require('ssh2');
const http = require('http');
const fs = require('fs');
const path = require('path');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const archiver = require('archiver');

// -- ALERTING & NOTIFICATIONS --
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.office365.com',
  port: process.env.SMTP_PORT || 587,
  secure: false, // true for 465, false for other ports
  auth: {
    user: process.env.SMTP_USER || 'm.saikiran@equence.com',
    pass: process.env.SMTP_PASS || ''
  }
});

let lastEmailTime = 0;
function sendCriticalAlert(server, snippet) {
  const now = Date.now();
  // Throttle to 1 email per 15 minutes maximum to avoid spam
  if (now - lastEmailTime < 15 * 60 * 1000) return;
  lastEmailTime = now;
  
  const mailOptions = {
    from: process.env.SMTP_USER || 'm.saikiran@equence.com',
    to: 'm.saikiran@equence.com',
    subject: `CRITICAL ALERT: Issue detected on ${server}`,
    text: `A critical issue or exception was detected in the live log stream of server ${server}.\n\nSnippet:\n${snippet}`
  };
  
  if (process.env.SMTP_PASS) {
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) console.error('Alert email failed:', error);
      else console.log('Alert email sent:', info.response);
    });
  } else {
    console.log('\n--- ALERT EMAIL MOCKED (No SMTP_PASS configured) ---');
    console.log(mailOptions.subject);
    console.log('------------------------------------------------------\n');
  }
}

const backendRoot = path.resolve(__dirname, '..');
const dataDir = path.join(backendRoot, 'data');
const logsDir = path.join(backendRoot, 'logs');
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir, { recursive: true });

// -- SECURITY AUDIT LOGGING --
const auditLogFile = path.join(logsDir, 'security_audit.log');
function auditLog(user, serverId, action) {
  const timestamp = new Date().toISOString();
  const logLine = `[${timestamp}] USER:${user} SERVER:${serverId} ACTION:${action}\n`;
  fs.appendFile(auditLogFile, logLine, (err) => {
    if(err) console.error("[Audit] Failed to write to audit log:", err);
  });
}

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

function heartbeat() { this.isAlive = true; }
const interval = setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);
wss.on('close', () => clearInterval(interval));

app.use(helmet({
  contentSecurityPolicy: false, // Set to false if you are loading external assets like xterm.js from CDNs
}));
app.use(compression());
app.use(express.json());
app.use(cookieParser());

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 login requests per windowMs
  message: { error: 'Too many login attempts, please try again after 15 minutes' }
});

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

// -- SERVERS CACHE --
let serversCache = [];
const serversFilePath = path.join(dataDir, 'servers.json');

function loadServers() {
  try {
    const data = fs.readFileSync(serversFilePath, 'utf8');
    serversCache = JSON.parse(data);
    console.log('[System] Loaded servers configuration.');
  } catch (err) {
    console.error('[Error] Failed to load servers.json:', err.message);
  }
}

loadServers();
fs.watchFile(serversFilePath, { interval: 2000 }, (curr, prev) => {
  if (curr.mtime !== prev.mtime) {
    console.log('[System] servers.json changed, reloading...');
    loadServers();
  }
});

// -- USERS MANAGEMENT --
let usersCache = [];
const usersFilePath = path.join(dataDir, 'users.json');
const ADMIN_GROUPS = ['infra'];

async function loadUsers() {
  try {
    if (!fs.existsSync(usersFilePath)) {
      // Create default admin with updated credentials
      const salt = await bcrypt.genSalt(10);
      const hash = await bcrypt.hash('bluto@eris', salt);
      const defaultAdmin = {
        id: uuidv4(),
        username: 'ITinfra',
        passwordHash: hash,
        group: 'infra',
        assignedServers: [],
        enabled: true,
      };
      fs.writeFileSync(usersFilePath, JSON.stringify([defaultAdmin], null, 2));
      console.log('--- Initial Admin created! Username: ITinfra, Password: bluto@eris (Group: infra) ---');
    }
    const data = fs.readFileSync(usersFilePath, 'utf8');
    usersCache = JSON.parse(data);
  } catch (err) {
    console.error('[Error] Failed to load users.json:', err.message);
  }
}

function saveUsers() {
  fs.writeFileSync(usersFilePath, JSON.stringify(usersCache, null, 2));
}

loadUsers();

// -- AUTH MIDDLEWARE --
const authMiddleware = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = usersCache.find(u => u.id === decoded.id && u.enabled);
    if (!user) return res.status(401).json({ error: 'Unauthorized or disabled' });
    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const adminMiddleware = (req, res, next) => {
  if (!ADMIN_GROUPS.includes(req.user.group)) return res.status(403).json({ error: 'Forbidden' });
  next();
};

// -- API ROUTES --
app.post('/api/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  const user = usersCache.find(u => u.username === username);
  if (!user || !user.enabled) return res.status(401).json({ error: 'Invalid credentials or disabled account' });
  // Pending invite accounts have empty passwordHash — bcrypt.compare can throw or misbehave
  if (!user.passwordHash || String(user.passwordHash).length < 10) {
    return res.status(401).json({ error: 'Account setup incomplete — use your invite link to set a password' });
  }

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
  
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '24h' });
  res.cookie('token', token, { httpOnly: true, secure: req.secure || req.headers['x-forwarded-proto'] === 'https' });
  res.json({ success: true, user: { username: user.username, group: user.group } });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ username: req.user.username, group: req.user.group });
});

// Admin routes
app.get('/api/users', authMiddleware, adminMiddleware, (req, res) => {
  res.json(usersCache.map(u => ({
    id: u.id, username: u.username, group: u.group, assignedServers: u.assignedServers, enabled: u.enabled
  })));
});

app.post('/api/users', authMiddleware, adminMiddleware, (req, res) => {
  const { username, group, assignedServers } = req.body;
  if (usersCache.find(u => u.username === username)) return res.status(400).json({ error: 'User exists' });
  
  const inviteToken = crypto.randomBytes(32).toString('hex');
  const newUser = {
    id: uuidv4(),
    username,
    passwordHash: '',
    group,
    assignedServers: assignedServers || [],
    enabled: true,
    inviteToken,
    inviteExpiry: Date.now() + 24 * 60 * 60 * 1000,
  };
  usersCache.push(newUser);
  saveUsers();
  res.json({ success: true, inviteLink: `/invite/${inviteToken}` });
});

app.put('/api/users/:id', authMiddleware, adminMiddleware, (req, res) => {
  const user = usersCache.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  
  const { group, assignedServers, enabled } = req.body;
  if (group) user.group = group;
  if (assignedServers) user.assignedServers = assignedServers;
  if (typeof enabled === 'boolean') user.enabled = enabled;
  
  saveUsers();
  res.json({ success: true });
});

app.delete('/api/users/:id', authMiddleware, adminMiddleware, (req, res) => {
  const userToDelete = usersCache.find(u => u.id === req.params.id);
  if (!userToDelete) return res.status(404).json({ error: 'User not found' });
  if (ADMIN_GROUPS.includes(userToDelete.group) && userToDelete.username === 'ITinfra') {
    return res.status(403).json({ error: 'Cannot delete the root administrator' });
  }
  
  usersCache = usersCache.filter(u => u.id !== req.params.id);
  saveUsers();
  res.json({ success: true });
});

app.post('/api/users/:id/invite', authMiddleware, adminMiddleware, (req, res) => {
  const user = usersCache.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  
  user.inviteToken = crypto.randomBytes(32).toString('hex');
  user.inviteExpiry = Date.now() + 24 * 60 * 60 * 1000;
  saveUsers();
  res.json({ success: true, inviteLink: `/invite/${user.inviteToken}` });
});

// -- FLEET AUDIT ZIP EXPORT --
app.post('/api/admin/audit-zip', authMiddleware, adminMiddleware, async (req, res) => {
  const { startDate, endDate, serverIds } = req.body;
  if (!startDate || !endDate) return res.status(400).json({ error: 'Date range required (YYYY-MM-DD)' });

  const serversToAudit = serversCache.filter(s => s.enabled && (!serverIds || serverIds.includes(s.id)));
  
  const archive = archiver('zip', { zlib: { level: 9 } });
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', `attachment; filename="fleet_audit_${startDate}_to_${endDate}.zip"`);
  
  archive.on('error', (err) => {
    console.error('[Audit] Archiver error:', err);
    if (!res.headersSent) res.status(500).send({ error: 'Archive generation failed' });
  });

  archive.pipe(res);

  for (const serverConfig of serversToAudit) {
    await new Promise((resolve) => {
      const conn = new Client();
      conn.on('ready', async () => {
        try {
          const cmd = `sudo journalctl --since "${startDate}" --until "${endDate} 23:59:59" --output=short-iso --no-pager 2>/dev/null || sudo grep -aE "session opened|COMMAND=" /var/log/auth.log /var/log/secure 2>/dev/null`;
          const result = await sshExecFixed(conn, cmd);
          
          if (result.ok && result.stdout && result.stdout.trim().length > 10) {
            const lines = result.stdout.split('\n');
            const userLogs = {};
            let lineCount = 0;
            lines.forEach(line => {
              const trimmed = line.trim();
              if (!trimmed || trimmed.length < 5) return;
              let user = 'system';
              const sudoMatch = trimmed.match(/\s+([a-zA-Z0-9._-]+)\s+:\s+TTY=/);
              const sessionMatch = trimmed.match(/session opened for user\s+([a-zA-Z0-9._-]+)/);
              const userVarMatch = trimmed.match(/user=([a-zA-Z0-9._-]+)/i);
              if (sudoMatch) user = sudoMatch[1];
              else if (sessionMatch) user = sessionMatch[1];
              else if (userVarMatch) user = userVarMatch[1];
              else if (trimmed.includes('(root) CMD')) user = 'root';
              if (!userLogs[user]) userLogs[user] = '';
              userLogs[user] += trimmed + '\n';
              lineCount++;
            });
            if (lineCount > 0) {
              for (const [user, logs] of Object.entries(userLogs)) {
                archive.append(logs, { name: `${serverConfig.id}/${user}/activity.log` });
              }
            } else {
              archive.append(`No specific activity found for ${serverConfig.id}`, { name: `${serverConfig.id}/info.log` });
            }
          } else {
            archive.append(`No activity logs found for the selected period on ${serverConfig.id}.\n\nOutput:\n${result.stdout || 'Empty'}\n\nError:\n${result.stderr || 'None'}`, { name: `${serverConfig.id}/info.log` });
          }
        } catch (err) {
          archive.append(`Audit failed: ${err.message}`, { name: `${serverConfig.id}/error.log` });
        } finally {
          conn.end(); resolve();
        }
      }).on('error', (err) => {
        archive.append(`Connection failed: ${err.message}`, { name: `${serverConfig.id}/connection_error.log` });
        resolve();
      }).connect({
        host: serverConfig.host, port: serverConfig.port || 22,
        username: serverConfig.user, password: serverConfig.password || process.env.SSH_PASSWORD,
        readyTimeout: 15000
      });
    });
  }
  await archive.finalize();
});

// Invite routes
app.post('/api/invite/validate', (req, res) => {
  const { token } = req.body;
  const user = usersCache.find(u => u.inviteToken === token && u.inviteExpiry > Date.now());
  if (!user) return res.status(400).json({ error: 'Invalid or expired invite' });
  res.json({ success: true, username: user.username });
});

app.post('/api/invite/accept', async (req, res) => {
  const { token, password } = req.body;
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password too short' });
  
  const user = usersCache.find(u => u.inviteToken === token && u.inviteExpiry > Date.now());
  if (!user) return res.status(400).json({ error: 'Invalid or expired invite' });
  
  const salt = await bcrypt.genSalt(10);
  user.passwordHash = await bcrypt.hash(password, salt);
  delete user.inviteToken;
  delete user.inviteExpiry;
  saveUsers();
  res.json({ success: true });
});

app.get('/invite/:token', (req, res) => {
  res.redirect('/?invite=' + req.params.token);
});

app.get('/api/list-logs-by-date', authMiddleware, async (req, res) => {
  const { serverId, startDate, endDate, path = '/var/log' } = req.query;
  if (!serverId || typeof serverId !== 'string') return res.status(400).json({ error: 'serverId required' });
  if (!startDate || !endDate) return res.status(400).json({ error: 'startDate and endDate required' });
  const serverConfig = serversCache.find(s => s.id === serverId);
  
  if (!serverConfig || !serverConfig.enabled) return res.status(404).json({ error: 'Server not found' });
  if (!ADMIN_GROUPS.includes(req.user.group) && !req.user.assignedServers.includes(serverId)) {
    return res.status(403).json({ error: 'Access denied' });
  }

  const conn = new Client();
  conn.on('ready', () => {
    // If path is a file, just return it. If directory, search by date range.
    // We use -newermt for date range search on the remote host
    const findCmd = `if [ -f "${path}" ]; then echo "${path}"; else find "${path}" -maxdepth 2 -type f -newermt "${startDate}" ! -newermt "${endDate} 23:59:59" 2>/dev/null; fi`;
    
    conn.exec(findCmd, (err, stream) => {
      if (err) { conn.end(); return res.status(500).json({ error: 'SSH failed' }); }
      let fileList = '';
      stream.on('data', (data) => { fileList += data.toString(); });
      stream.on('close', () => {
        conn.end();
        const files = fileList.split('\n').map(f => f.trim()).filter(Boolean);
        res.json({ files });
      });
    });
  }).on('error', (err) => res.status(500).json({ error: err.message })).connect({
    host: serverConfig.host, port: serverConfig.port || 22,
    username: serverConfig.user, password: serverConfig.password || process.env.SSH_PASSWORD
  });
});

app.post('/api/download-logs', authMiddleware, async (req, res) => {
  const { serverId, files, startDate, endDate } = req.body;
  if (!files || !files.length) return res.status(400).json({ error: 'No files selected' });
  
  const serverConfig = serversCache.find(s => s.id === serverId);
  if (!serverConfig || !serverConfig.enabled) return res.status(404).json({ error: 'Server not found' });
  if (!ADMIN_GROUPS.includes(req.user.group) && !req.user.assignedServers.includes(serverId)) {
    return res.status(403).json({ error: 'Access denied' });
  }

  const conn = new Client();
  conn.on('ready', () => {
    // Generate patterns for filtering
    const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const patterns = [];
    let curr = new Date(startDate);
    const stop = new Date(endDate);
    while (curr <= stop) {
      const m = months[curr.getMonth()];
      const d = curr.getDate();
      const d0Padded = d.toString().padStart(2, '0'); // 01, 02...
      const dSpacePadded = d.toString().padStart(2, ' '); // " 1", " 2"...
      const y = curr.getFullYear();
      const iso = curr.toISOString().split('T')[0];
      
      // Standard Syslog (Apr 30 or Apr  1) - anchored to start of line
      patterns.push(`^${m} ${dSpacePadded}`);
      patterns.push(`^${m} ${d}`);
      
      // Nginx/Apache format ([30/Apr/2026]) - anchored with open bracket
      patterns.push(`\\[${d0Padded}/${m}/${y}`);
      patterns.push(`\\[${d}/${m}/${y}`);
      
      // ISO/Application format (2026-04-30) - anchored to start of line
      patterns.push(`^${iso}`);
      
      curr.setDate(curr.getDate() + 1);
    }
    const grepPattern = patterns.join('|');
    const tmpDir = `/tmp/infra_logs_${Date.now()}`;
    
    // Command to: create tmp dir, filter each file into it, tar it, and cleanup
    let filterCmd = `mkdir -p ${tmpDir}; `;
    files.forEach(f => {
      const base = f.split('/').pop();
      // Use grep to only take lines matching the patterns. 
      // Removed the fallback cp to prevent downloading the whole file if no matches are found.
      filterCmd += `grep -aE "${grepPattern}" "${f}" > "${tmpDir}/${base}" 2>/dev/null || touch "${tmpDir}/${base}"; `;
    });
    filterCmd += `tar -czf - -C ${tmpDir} . ; rm -rf ${tmpDir}`;

    res.setHeader('Content-Type', 'application/gzip');
    res.setHeader('Content-Disposition', `attachment; filename="filtered_logs_${serverId}.tar.gz"`);
    
    conn.exec(filterCmd, (err, stream) => {
      if (err) {
        conn.exec(`rm -rf ${tmpDir}`); // Cleanup on exec error
        conn.end();
        return res.end();
      }
      stream.pipe(res);
      stream.on('close', () => {
        conn.end();
      });
      stream.on('error', () => {
        conn.exec(`rm -rf ${tmpDir}`);
        conn.end();
        res.end();
      });
    });
  }).on('error', (err) => {
    res.status(500).json({ error: err.message });
  }).connect({
    host: serverConfig.host, port: serverConfig.port || 22,
    username: serverConfig.user, password: serverConfig.password || process.env.SSH_PASSWORD
  });
});

// Public UI
app.use(express.static(path.resolve(__dirname, '../../frontend/public')));
app.get('/', (req, res) => {
  res.sendFile(path.resolve(__dirname, '../../frontend/public/index.html'));
});

// Servers list
app.get('/servers', authMiddleware, (req, res) => {
  try {
    let allowedServers = serversCache.map(({ password, ...rest }) => rest);
    if (!ADMIN_GROUPS.includes(req.user.group)) {
      allowedServers = allowedServers.filter(s => req.user.assignedServers.includes(s.id));
    }
    res.json(allowedServers);
  } catch (error) {
    res.status(500).json({ error: 'Failed to read servers configuration' });
  }
});

// --- SMART COMMAND SECURITY (blocklist approach) ---
// Block ONLY destructive/dangerous commands. Everything read-only is allowed.
const BLOCKED_COMMAND_PATTERNS = [
  // Service control
  /\bsystemctl\s+(stop|start|restart|enable|disable|mask|unmask|kill|daemon-reload)\b/i,
  /\bservice\s+\S+\s+(stop|start|restart)\b/i,
  // Process termination
  /\bkill\b/i,
  /\bkillall\b/i,
  /\bpkill\b/i,
  // System shutdown
  /\bshutdown\b/i,
  /\breboot\b/i,
  /\bhalt\b/i,
  /\bpoweroff\b/i,
  /\binit\s+[016]\b/i,
  // File deletion/modification
  /\brm\s+/i,
  /\brmdir\b/i,
  /\btruncate\b/i,
  /\bshred\b/i,
  // Redirection & Overwriting (targeted protection)
  />\s*(\/etc\/|\/boot\/|\/root\/|\/bin\/|\/sbin\/|\/usr\/|\/var\/)/i,
  />>\s*(\/etc\/|\/boot\/|\/root\/|\/bin\/|\/sbin\/|\/usr\/|\/var\/)/i,
  /\|.*tee\b\s*(\/etc\/|\/boot\/|\/root\/|\/bin\/|\/sbin\/|\/usr\/|\/var\/)/i,
  // Low-level disk ops
  /\bmkfs\b/i,
  /\bfdisk\b/i,
  /\bdd\b/i,
  // Privilege escalation
  /\bsudo\b/i,
  /\bsu\s+/i,
  /\bsu$/i,
  // User/password management
  /\bpasswd\b/i,
  /\buseradd\b/i,
  /\buserdel\b/i,
  /\busermod\b/i,
  /\bchpasswd\b/i,
  // Disk/partition operations
  /\bdd\b.*of=/i,
  /\bmkfs\b/i,
  /\bfdisk\b/i,
  /\bparted\b/i,
  /\bmount\b/i,
  /\bumount\b/i,
  // Cron/schedule modification
  /\bcrontab\s+(-e|-r)\b/i,
  // Permission changes
  /\bchmod\s+[0-9]*7[0-9]*\b/i,
  /\bchown\s+root\b/i,
  // Redirect output to files (protect against overwriting)
  /[^|]\s*>\s*\//,
  /\bwget\s+.*-O\s+\//i,
  /\bcurl\s+.*-o\s+\//i,
  // SSH/network attacks
  /\bssh-keygen\b/i,
  /\bssh-copy-id\b/i,
  // Code execution escalation
  /\bpython[23]?\s+-c\b/i,
  /\bperl\s+-e\b/i,
  /\bruby\s+-e\b/i,
  /\bnode\s+-e\b/i,
  /\bbash\s+-c\b/i,
  /\bsh\s+-c\b/i,
];

function validateCommand(cmdStr) {
  const cmd = cmdStr.trim();
  if (!cmd) return false;

  // [WHITELIST EXCEPTION]: Explicitly allow sudo for monitoring and diagnostics
  const sudoWhitelist = /sudo\s+(tail|journalctl|grep|head|cat|zgrep|dmesg|lsblk|lsof|netstat|ss|ip|df|du|free|top|htop|uptime|ps|ls|find|less|more|ifconfig|route|dig|nslookup|ping|traceroute|pvs|vgs|lvs|ethtool|fuser|pv|strace|tcpdump)\b/i;
  if (sudoWhitelist.test(cmd)) return true;

  // Check against every blocked pattern
  for (const pattern of BLOCKED_COMMAND_PATTERNS) {
    if (pattern.test(cmd)) return false;
  }
  return true;
}

function findCommonPrefix(strings) {
  if (!strings.length) return '';
  let prefix = strings[0];
  for (let i = 1; i < strings.length; i++) {
    while (!strings[i].startsWith(prefix)) {
      prefix = prefix.slice(0, -1);
      if (!prefix) return '';
    }
  }
  return prefix;
}

// --- LOG DISCOVERY (server-side, not user-provided commands) ---
function isProbablyLogFile(name) {
  const lower = name.toLowerCase();
  return (
    lower.endsWith('.log') ||
    lower.endsWith('.out') ||
    lower.endsWith('.err') ||
    lower.includes('log') ||
    lower === 'messages' ||
    lower === 'syslog' ||
    lower === 'catalina.out'
  );
}

function sshExecFixed(sshClient, cmd) {
  return new Promise((resolve) => {
    sshClient.exec(cmd, { pty: { term: 'xterm' } }, (err, stream) => {
      if (err) return resolve({ ok: false, stdout: '', stderr: err.message });
      let stdout = '';
      let stderr = '';
      stream.on('data', (d) => { stdout += d.toString(); });
      stream.stderr.on('data', (d) => { stderr += d.toString(); });
      stream.on('close', () => resolve({ ok: true, stdout, stderr }));
    });
  });
}

async function discoverLogsOverSsh(sshClient) {
  // 1) discover services (journald)
  const servicesRes = await sshExecFixed(
    sshClient,
    'systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null || true'
  );
  const services = (servicesRes.stdout || '')
    .split('\n')
    .map(l => l.trim())
    .filter(Boolean)
    .map(l => l.split(/\s+/)[0])
    .filter(s => s && s.endsWith('.service'))
    .slice(0, 500);

  // 2) discover log files using a fast find command across common locations
  // maxdepth 4 prevents infinite scanning, ignores errors
  const findCmd = `find /var/log /opt /srv /data /home -maxdepth 4 -type f \\( -name "*.log" -o -name "*.out" -o -name "*.err" -o -name "*log*" -o -name "messages" -o -name "syslog" -o -name "catalina.out" \\) 2>/dev/null | head -n 600`;
  const filesRes = await sshExecFixed(sshClient, findCmd);
  const files = (filesRes.stdout || '')
    .split('\n')
    .map(l => l.trim())
    .filter(Boolean);

  return { files, services };
}

// WebSocket connection
wss.on('connection', (ws, req) => {
  ws.isAlive = true;
  ws.on('pong', heartbeat);
  // Parse cookies for Auth
  const cookiesHeader = req.headers.cookie;
  let token = null;
  if (cookiesHeader) {
      const parsedCookies = cookiesHeader.split(';').reduce((acc, cookie) => {
          const eqIdx = cookie.indexOf('=');
          if (eqIdx !== -1) {
            const key = cookie.slice(0, eqIdx).trim();
            const value = cookie.slice(eqIdx + 1).trim();
            acc[key] = value;
          }
          return acc;
      }, {});
      token = parsedCookies.token;
  }

  let currentUser = null;
  if (token) {
      try {
          const decoded = jwt.verify(token, JWT_SECRET);
          currentUser = usersCache.find(u => u.id === decoded.id && u.enabled);
      } catch (e) {}
  }

  if (!currentUser) {
      ws.send(JSON.stringify({ type: 'error', data: '\r\nUnauthorized: Invalid or missing token\r\n' }));
      ws.close();
      return;
  }

  let sshClient = null;
  let sshReady = false;
  let currentServerConfig = null;
  
  // Enhanced Shell State
  let shellState = 'IDLE'; // IDLE | RUNNING
  let commandBuffer = '';
  let cursorPos = 0;
  let activeStream = null;
  let metricsInterval = null;
  let commandHistory = [];
  let historyIndex = -1;
  let savedBuffer = '';
  let termCols = 80;
  let termRows = 24;
  let escapeState = 0; // 0=normal, 1=got ESC, 2=got ESC[
  let escapeBuffer = '';

  function getColoredPrompt() {
    const u = currentUser ? currentUser.username : 'user';
    const h = currentServerConfig ? currentServerConfig.id : 'host';
    return `\x1b[1;32m${u}@${h}\x1b[0m:\x1b[1;34m~\x1b[0m$ `;
  }

  function prompt() {
    ws.send(JSON.stringify({ type: 'output', data: `\r\n${getColoredPrompt()}` }));
  }

  function redrawLine() {
    const p = getColoredPrompt();
    // Use \r to go to start of line, then \x1b[J to clear from cursor to end of screen
    // This is safer for multi-line redraws if we don't have perfect wrap tracking
    ws.send(JSON.stringify({ type: 'output', data: `\r\x1b[K${p}${commandBuffer}` }));
    
    // Position cursor if not at the end
    if (cursorPos < commandBuffer.length) {
      const back = commandBuffer.length - cursorPos;
      ws.send(JSON.stringify({ type: 'output', data: `\x1b[${back}D` }));
    }
  }

  function handleEscapeSeq(seq) {
    if (seq === 'A') { // Up
      if (commandHistory.length > 0) {
        if (historyIndex === -1) { savedBuffer = commandBuffer; historyIndex = commandHistory.length - 1; }
        else if (historyIndex > 0) { historyIndex--; }
        commandBuffer = commandHistory[historyIndex];
        cursorPos = commandBuffer.length;
        redrawLine();
      }
    } else if (seq === 'B') { // Down
      if (historyIndex !== -1) {
        if (historyIndex < commandHistory.length - 1) { historyIndex++; commandBuffer = commandHistory[historyIndex]; }
        else { historyIndex = -1; commandBuffer = savedBuffer || ''; }
        cursorPos = commandBuffer.length;
        redrawLine();
      }
    } else if (seq === 'C') { // Right
      if (cursorPos < commandBuffer.length) { cursorPos++; ws.send(JSON.stringify({ type: 'output', data: '\x1b[C' })); }
    } else if (seq === 'D') { // Left
      if (cursorPos > 0) { cursorPos--; ws.send(JSON.stringify({ type: 'output', data: '\x1b[D' })); }
    } else if (seq === 'H' || seq === '1~') { cursorPos = 0; redrawLine(); }
    else if (seq === 'F' || seq === '4~') { cursorPos = commandBuffer.length; redrawLine(); }
    else if (seq === '3~') { // Delete
      if (cursorPos < commandBuffer.length) {
        commandBuffer = commandBuffer.slice(0, cursorPos) + commandBuffer.slice(cursorPos + 1);
        redrawLine();
      }
    }
  }

  function handleTabCompletion() {
    if (!sshClient || !sshReady) return;
    const before = commandBuffer.slice(0, cursorPos);
    const parts = before.split(/\s+/);
    const word = parts[parts.length - 1] || '';
    if (!word) return;
    const compCmd = `compgen -f -- "${word.replace(/"/g, '\\"')}" 2>/dev/null | head -20`;
    sshClient.exec(compCmd, (err, stream) => {
      if (err) return;
      let result = '';
      stream.on('data', (d) => { result += d.toString(); });
      stream.on('close', () => {
        const completions = result.split('\n').filter(Boolean);
        if (!completions.length) return;
        if (completions.length === 1) {
          const rest = completions[0].slice(word.length);
          commandBuffer = commandBuffer.slice(0, cursorPos) + rest + commandBuffer.slice(cursorPos);
          cursorPos += rest.length;
          redrawLine();
        } else {
          const cp = findCommonPrefix(completions);
          if (cp.length > word.length) {
            const rest = cp.slice(word.length);
            commandBuffer = commandBuffer.slice(0, cursorPos) + rest + commandBuffer.slice(cursorPos);
            cursorPos += rest.length;
          }
          ws.send(JSON.stringify({ type: 'output', data: '\r\n' + completions.join('  ') + '\r\n' }));
          redrawLine();
        }
      });
    });
  }

  ws.on('message', (message) => {
    try {
      const msg = JSON.parse(message);
      
      if (msg.action === 'connect') {
        currentServerConfig = serversCache.find(s => s.id === msg.serverId);
        
        if (!currentServerConfig || !currentServerConfig.enabled) {
          ws.send(JSON.stringify({ type: 'error', data: 'Server not found or disabled\r\n' }));
          return;
        }

        if (!ADMIN_GROUPS.includes(currentUser.group) && !currentUser.assignedServers.includes(currentServerConfig.id)) {
            ws.send(JSON.stringify({ type: 'error', data: '\r\nAccess Denied to this server\r\n' }));
            return;
        }

        if (sshClient) sshClient.end();
        if (metricsInterval) clearInterval(metricsInterval);
        metricsInterval = null;
        sshReady = false;
        activeStream = null;
        shellState = 'IDLE';
        commandBuffer = '';
        const sshConn = new Client();
        sshClient = sshConn;

        sshConn.on('ready', () => {
          // Ignore stale sessions if user switched hosts before ready
          if (sshClient !== sshConn) return;
          sshReady = true;
          auditLog(currentUser.username, currentServerConfig.id, 'CONNECTED via SSH');
          ws.send(JSON.stringify({ type: 'connected', data: `\r\nConnected to ${currentServerConfig.group} - ${currentServerConfig.id}\r\n` }));
          
          const fetchMetrics = () => {
            if (!sshReady || sshClient !== sshConn) return;
            // Fetch Mem, CPU, Disk (/), and Network
            const cmd = 'free -m && echo "---" && top -bn1 | head -5 && echo "---" && df -h / | tail -1 && echo "---" && cat /proc/net/dev | grep -v "lo" | tail -1';
            sshConn.exec(cmd, (err, stream) => {
              if (err) return;
              let metricsData = '';
              stream.on('data', (d) => { metricsData += d.toString(); });
              stream.on('close', () => { 
                if (sshClient !== sshConn) return;
                if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'metrics', data: metricsData })); 
              });
            });
          };

          fetchMetrics();
          metricsInterval = setInterval(fetchMetrics, 2000); // High frequency 2s updates

          // Auto-discover logs on the remote host (files + journald services)
          (async () => {
            try {
              const catalog = await discoverLogsOverSsh(sshConn);
              if (sshClient !== sshConn || ws.readyState !== 1) return;
              ws.send(JSON.stringify({ type: 'log_catalog', data: catalog }));
            } catch (e) {
              if (sshClient !== sshConn || ws.readyState !== 1) return;
              ws.send(JSON.stringify({ type: 'log_catalog', data: { files: [], services: [] } }));
            }
          })();

          shellState = 'IDLE';
          commandBuffer = '';
          prompt();
        });

        sshConn.on('error', (err) => {
          if (sshClient !== sshConn) return;
          sshReady = false;
          if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'error', data: `\r\nSSH Error: ${err.message}\r\n` }));
        });
        sshConn.on('close', () => {
          if (sshClient !== sshConn) return;
          sshReady = false;
          if (metricsInterval) clearInterval(metricsInterval);
          metricsInterval = null;
          if (ws.readyState === 1) {
            ws.send(JSON.stringify({ type: 'disconnected', data: `\r\nDisconnected\r\n` }));
          }
          sshClient = null;
          activeStream = null;
          currentServerConfig = null;
        });

        try {
          sshConn.connect({
            host: currentServerConfig.host, port: currentServerConfig.port || 22,
            username: currentServerConfig.user, password: currentServerConfig.password || process.env.SSH_PASSWORD,
            readyTimeout: 15000
          });
        } catch (connErr) {
            ws.send(JSON.stringify({ type: 'error', data: `\r\nConnection failed: ${connErr.message}\r\n` }));
        }

      } else if (msg.action === 'input') {
          const inputData = msg.data;
          if (shellState === 'RUNNING' && activeStream) {
              activeStream.write(inputData); // Forward signals or data to running process
              return;
          }

          if (!sshClient || !sshReady) {
            ws.send(JSON.stringify({ type: 'error', data: 'Not connected — wait for the session to open\r\n' }));
            return;
          }

          if (shellState === 'IDLE') {
              let pendingOutput = '';
              for (let i = 0; i < inputData.length; i++) {
                  const char = inputData[i];
                  const code = char.charCodeAt(0);

                  // Escape sequence state machine
                  if (escapeState === 1) {
                    if (char === '[') { escapeState = 2; escapeBuffer = ''; } else { escapeState = 0; }
                    continue;
                  }
                  if (escapeState === 2) {
                    escapeBuffer += char;
                    if ((char >= 'A' && char <= 'Z') || char === '~') {
                      escapeState = 0; handleEscapeSeq(escapeBuffer); escapeBuffer = '';
                    }
                    continue;
                  }
                  if (code === 27) { escapeState = 1; continue; } // ESC

                  if (char === '\r') { // Enter
                      pendingOutput += '\r\n';
                      const cmd = commandBuffer.trim();
                      commandBuffer = ''; cursorPos = 0; historyIndex = -1; savedBuffer = '';
                      if (!cmd) { 
                        ws.send(JSON.stringify({ type: 'output', data: pendingOutput })); 
                        pendingOutput = ''; 
                        prompt(); 
                        continue; 
                      }
                      if (commandHistory.length === 0 || commandHistory[commandHistory.length - 1] !== cmd) {
                        commandHistory.push(cmd);
                        if (commandHistory.length > 200) commandHistory.shift();
                      }
                      if (!validateCommand(cmd)) {
                          pendingOutput += `\x1b[1;31m✗ Blocked:\x1b[0m Command not permitted by security policy\r\n`;
                          ws.send(JSON.stringify({ type: 'output', data: pendingOutput }));
                          pendingOutput = '';
                          prompt(); 
                          continue;
                      }
                      shellState = 'RUNNING';
                      auditLog(currentUser.username, currentServerConfig.id, `EXECUTED: ${cmd}`);
                      sshClient.exec(cmd, { pty: true }, (err, stream) => {
                          if (err) {
                              ws.send(JSON.stringify({ type: 'output', data: `\r\n\x1b[31mExec error: ${err.message}\x1b[0m\r\n` }));
                              shellState = 'IDLE'; prompt(); return;
                          }
                          activeStream = stream;
                          stream.on('data', (d) => {
                              const dataStr = d.toString('utf-8');
                              ws.send(JSON.stringify({ type: 'output', data: dataStr }));
                              if (/^(sudo\s+)?(tail|journalctl)\b/i.test(cmd.trim())) {
                                 const lowerData = dataStr.toLowerCase();
                                 if (lowerData.includes('fatal') || lowerData.includes('exception')) {
                                    sendCriticalAlert(currentServerConfig.id, dataStr.substring(0, 800));
                                 }
                              }
                          }).on('close', () => { activeStream = null; shellState = 'IDLE'; prompt(); });
                      });
                      break;
                  }
                  if (code === 127 || code === 8) { // Backspace
                      if (cursorPos > 0) {
                        if (cursorPos === commandBuffer.length) {
                          commandBuffer = commandBuffer.slice(0, -1);
                          cursorPos--;
                          pendingOutput += '\b \b';
                        } else {
                          commandBuffer = commandBuffer.slice(0, cursorPos - 1) + commandBuffer.slice(cursorPos);
                          cursorPos--; 
                          if (pendingOutput) { ws.send(JSON.stringify({ type: 'output', data: pendingOutput })); pendingOutput = ''; }
                          redrawLine();
                        }
                      }
                      continue;
                  }
                  if (code === 3) { commandBuffer = ''; cursorPos = 0; historyIndex = -1; pendingOutput += '^C'; ws.send(JSON.stringify({ type: 'output', data: pendingOutput })); pendingOutput = ''; prompt(); continue; } // Ctrl+C
                  if (code === 1) { cursorPos = 0; if (pendingOutput) { ws.send(JSON.stringify({ type: 'output', data: pendingOutput })); pendingOutput = ''; } redrawLine(); continue; } // Ctrl+A
                  if (code === 5) { cursorPos = commandBuffer.length; if (pendingOutput) { ws.send(JSON.stringify({ type: 'output', data: pendingOutput })); pendingOutput = ''; } redrawLine(); continue; } // Ctrl+E
                  if (code === 21) { commandBuffer = ''; cursorPos = 0; if (pendingOutput) { ws.send(JSON.stringify({ type: 'output', data: pendingOutput })); pendingOutput = ''; } redrawLine(); continue; } // Ctrl+U
                  if (code === 11) { commandBuffer = commandBuffer.slice(0, cursorPos); if (pendingOutput) { ws.send(JSON.stringify({ type: 'output', data: pendingOutput })); pendingOutput = ''; } redrawLine(); continue; } // Ctrl+K
                  if (code === 23) { // Ctrl+W delete word
                    if (cursorPos > 0) {
                      let np = cursorPos - 1;
                      while (np > 0 && commandBuffer[np - 1] === ' ') np--;
                      while (np > 0 && commandBuffer[np - 1] !== ' ') np--;
                      commandBuffer = commandBuffer.slice(0, np) + commandBuffer.slice(cursorPos);
                      cursorPos = np; 
                      if (pendingOutput) { ws.send(JSON.stringify({ type: 'output', data: pendingOutput })); pendingOutput = ''; }
                      redrawLine();
                    }
                    continue;
                  }
                  if (code === 12) { pendingOutput += '\x1b[2J\x1b[H'; if (pendingOutput) { ws.send(JSON.stringify({ type: 'output', data: pendingOutput })); pendingOutput = ''; } redrawLine(); continue; } // Ctrl+L
                  if (code === 9) { handleTabCompletion(); continue; } // Tab
                  if (code >= 32) {
                    if (cursorPos === commandBuffer.length) {
                      commandBuffer += char;
                      cursorPos++;
                      pendingOutput += char;
                    } else {
                      commandBuffer = commandBuffer.slice(0, cursorPos) + char + commandBuffer.slice(cursorPos);
                      cursorPos++;
                      if (pendingOutput) { ws.send(JSON.stringify({ type: 'output', data: pendingOutput })); pendingOutput = ''; }
                      redrawLine();
                    }
                  }
              }
              if (pendingOutput) {
                  ws.send(JSON.stringify({ type: 'output', data: pendingOutput }));
              }
          }
      }
 else if (msg.action === 'resize') {
          termCols = msg.cols || termCols;
          termRows = msg.rows || termRows;
          if (activeStream && activeStream.setWindow) {
              activeStream.setWindow(termRows, termCols, 0, 0);
          }
      }
    } catch (e) {
        console.error('WS parsing error:', e);
    }
  });

  ws.on('close', () => {
    if (metricsInterval) clearInterval(metricsInterval);
    metricsInterval = null;
    sshReady = false;
    if (sshClient) { sshClient.end(); sshClient.destroy(); sshClient = null; activeStream = null; currentServerConfig = null; }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Log Monitor Server listening on http://localhost:${PORT}`);
});
