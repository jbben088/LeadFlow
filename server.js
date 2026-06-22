const http   = require('http');
const https  = require('https');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

const PORT = process.env.PORT || 3031;

// Persistent data directory. Defaults to the app folder for local dev; on a
// hosted platform set DATA_DIR to a mounted persistent disk so the SQLite
// database and exports survive redeploys.
const DATA_DIR = process.env.DATA_DIR || __dirname;
try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch {}

// ── SQLite (built into Node.js 22+, no npm install needed) ────────────────────
const { DatabaseSync } = require('node:sqlite');
const db = new DatabaseSync(path.join(DATA_DIR, 'leadflow.db'));

db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS leads     (id TEXT PRIMARY KEY, data TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS research  (id TEXT PRIMARY KEY, module TEXT NOT NULL DEFAULT 'contacts', data TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS users     (username TEXT PRIMARY KEY COLLATE NOCASE, password_hash TEXT NOT NULL, salt TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'member', created_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS sessions  (token TEXT PRIMARY KEY, username TEXT NOT NULL, role TEXT NOT NULL, expires_at INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS settings  (key TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS api_usage (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, input_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0, cost_usd REAL NOT NULL DEFAULT 0, purpose TEXT NOT NULL DEFAULT 'erp_research');
  CREATE INDEX IF NOT EXISTS idx_research_module ON research(module);
  CREATE INDEX IF NOT EXISTS idx_usage_timestamp  ON api_usage(timestamp);
`);

// Purge expired sessions on boot
db.exec(`DELETE FROM sessions WHERE expires_at < ${Date.now()}`);

// ── Helpers ────────────────────────────────────────────────────────────────────
const readJSON = (f, d) => { try { return JSON.parse(fs.readFileSync(path.join(__dirname, f), 'utf8')); } catch { return d; } };
const newSalt  = () => crypto.randomBytes(16).toString('hex');
const newToken = () => crypto.randomBytes(32).toString('hex');
const hashPwd  = (pwd, salt) => crypto.createHash('sha256').update(pwd + salt).digest('hex');
const txn      = fn => { db.exec('BEGIN'); try { fn(); db.exec('COMMIT'); } catch(e) { db.exec('ROLLBACK'); throw e; } };

const SESSION_TTL = 30 * 24 * 60 * 60 * 1000; // 30 days — survives server restarts

// ── SSO / OAuth2 ───────────────────────────────────────────────────────────────
const ALLOWED_DOMAINS = ['redhawkdigital.ai', 'agr-us.com'];

// Short-lived nonce store to prevent CSRF on OAuth callbacks (TTL: 10 min)
const oauthStates = new Map();
const newOAuthState = () => {
  const state = crypto.randomBytes(16).toString('hex');
  oauthStates.set(state, Date.now());
  // Prune stale states
  for (const [k, ts] of oauthStates) { if (Date.now() - ts > 10 * 60 * 1000) oauthStates.delete(k); }
  return state;
};
const verifyOAuthState = state => {
  const ts = oauthStates.get(state);
  if (!ts || Date.now() - ts > 10 * 60 * 1000) return false;
  oauthStates.delete(state);
  return true;
};

// POST helper for OAuth token exchange (no npm deps needed)
const httpsPost = (url, body) => new Promise((resolve, reject) => {
  const parsed = new URL(url);
  const data = new URLSearchParams(body).toString();
  const opts = {
    hostname: parsed.hostname, path: parsed.pathname + parsed.search, method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(data) },
  };
  const req = https.request(opts, res => {
    let d = '';
    res.on('data', c => d += c);
    res.on('end', () => { try { resolve(JSON.parse(d)); } catch(e) { resolve(d); } });
  });
  req.on('error', reject);
  req.write(data);
  req.end();
});

// Decode JWT payload without verifying signature (safe — token came directly from provider over HTTPS)
const decodeJwtPayload = token => {
  try {
    const part = token.split('.')[1];
    return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
  } catch(e) { return null; }
};

// Create or refresh an SSO user session (returns null if domain is not allowed)
const createSsoSession = (email, displayName) => {
  const domain = (email || '').split('@')[1];
  if (!domain || !ALLOWED_DOMAINS.includes(domain.toLowerCase())) return null;

  // Upsert user — SSO users have no usable password
  const existing = db.prepare('SELECT * FROM users WHERE username=?').get(email);
  if (!existing) {
    const isFirst = db.prepare('SELECT COUNT(*) as n FROM users').get().n === 0;
    db.prepare('INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(email, 'sso-only', '', isFirst ? 'admin' : 'member', new Date().toISOString());
  }
  const user = db.prepare('SELECT * FROM users WHERE username=?').get(email);

  const token = newToken();
  db.prepare('INSERT INTO sessions (token, username, role, expires_at) VALUES (?, ?, ?, ?)')
    .run(token, user.username, user.role, Date.now() + SESSION_TTL);
  return { token, username: user.username, role: user.role, displayName: displayName || email };
};

const ssoBaseUrl = () => (getSettings().ssoBaseUrl || `http://localhost:${PORT}`).replace(/\/$/, '');

// ── Migrate existing JSON files on first run ───────────────────────────────────
function migrate() {
  let migrated = false;

  if (db.prepare('SELECT COUNT(*) as n FROM leads').get().n === 0) {
    const data = readJSON('leads-data.json', null);
    if (Array.isArray(data) && data.length) {
      const ins = db.prepare('INSERT OR IGNORE INTO leads (id, data) VALUES (?, ?)');
      txn(() => data.forEach(l => ins.run(l.id, JSON.stringify(l))));
      console.log(`  ✓ Migrated ${data.length} leads from leads-data.json`);
      migrated = true;
    }
  }

  if (db.prepare("SELECT COUNT(*) as n FROM research WHERE module='contacts'").get().n === 0) {
    const data = readJSON('research-data.json', null);
    if (Array.isArray(data) && data.length) {
      const ins = db.prepare("INSERT OR IGNORE INTO research (id, module, data) VALUES (?, 'contacts', ?)");
      txn(() => data.forEach(r => ins.run(r.id, JSON.stringify(r))));
      console.log(`  ✓ Migrated ${data.length} contacts research items from research-data.json`);
      migrated = true;
    }
  }

  if (db.prepare("SELECT COUNT(*) as n FROM research WHERE module='erp'").get().n === 0) {
    const data = readJSON('erp-research-data.json', null);
    if (Array.isArray(data) && data.length) {
      const ins = db.prepare("INSERT OR IGNORE INTO research (id, module, data) VALUES (?, 'erp', ?)");
      txn(() => data.forEach(r => ins.run(r.id, JSON.stringify(r))));
      console.log(`  ✓ Migrated ${data.length} ERP research items from erp-research-data.json`);
      migrated = true;
    }
  }

  if (db.prepare('SELECT COUNT(*) as n FROM users').get().n === 0) {
    const data = readJSON('users.json', null);
    if (Array.isArray(data) && data.length) {
      const ins = db.prepare('INSERT OR IGNORE INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)');
      txn(() => data.forEach(u => ins.run(u.username, u.passwordHash, u.salt, u.role, u.createdAt)));
      console.log(`  ✓ Migrated ${data.length} users from users.json`);
      migrated = true;
    }
  }

  if (db.prepare('SELECT COUNT(*) as n FROM settings').get().n === 0) {
    const data = readJSON('settings.json', null);
    if (data && typeof data === 'object') {
      db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)').run('main', JSON.stringify(data));
      console.log('  ✓ Migrated settings from settings.json');
      migrated = true;
    }
  }

  if (migrated) console.log('  Migration complete. JSON files are now read-only backups.\n');

  // One-time: default empty owner/assignedTo → 'Blair' on research items
  const unowned = db.prepare('SELECT id, data FROM research').all()
    .filter(r => { const d = JSON.parse(r.data); return !d.owner || !d.assignedTo; });
  if (unowned.length) {
    const upd = db.prepare('UPDATE research SET data=? WHERE id=?');
    txn(() => unowned.forEach(r => {
      const d = JSON.parse(r.data);
      if (!d.owner)      d.owner      = 'Blair';
      if (!d.assignedTo) d.assignedTo = 'Blair';
      upd.run(JSON.stringify(d), r.id);
    }));
    console.log(`  ✓ Assigned Blair as owner/assignedTo for ${unowned.length} unassigned research items`);
  }
}
migrate();

// ── Auth helpers ───────────────────────────────────────────────────────────────
const getSession = req => {
  const token = req.headers['x-session-token'];
  if (!token) return null;
  return db.prepare('SELECT username, role FROM sessions WHERE token=? AND expires_at>?').get(token, Date.now()) || null;
};
const requireAuth  = (req, res) => { const s = getSession(req); if (s) return s; jsonRes(res, 401, {ok:false, error:'Unauthorized'}); return null; };
const requireAdmin = (req, res) => { const s = requireAuth(req, res); if (!s) return null; if (s.role === 'admin') return s; jsonRes(res, 403, {ok:false, error:'Admin only'}); return null; };

// ── Response helper ────────────────────────────────────────────────────────────
const jsonRes = (res, status, data) => {
  res.writeHead(status, {'Content-Type':'application/json','Cache-Control':'no-cache','Access-Control-Allow-Origin':'*'});
  res.end(JSON.stringify(data));
};

// ── Body parser ────────────────────────────────────────────────────────────────
const parseBody = req => new Promise(resolve => {
  let d = '';
  req.on('data', c => d += c);
  req.on('end', () => { try { resolve(JSON.parse(d || '{}')); } catch { resolve({}); } });
  req.on('error', () => resolve({}));
});

// ── Routes ─────────────────────────────────────────────────────────────────────
const routes = {};
const R = (method, url, fn) => routes[`${method} ${url}`] = fn;

R('GET', '/api/setup', (req, res) => {
  jsonRes(res, 200, {setupRequired: db.prepare('SELECT COUNT(*) as n FROM users').get().n === 0});
});

R('GET', '/api/sso-config', (req, res) => {
  const s = getSettings();
  jsonRes(res, 200, {
    googleEnabled:    !!(s.googleClientId    && s.googleClientSecret),
    microsoftEnabled: !!(s.microsoftClientId && s.microsoftClientSecret),
    allowedDomains: ALLOWED_DOMAINS,
  });
});

// ── Google OAuth2 ──────────────────────────────────────────────────────────────
R('GET', '/auth/google', (req, res) => {
  const s = getSettings();
  if (!s.googleClientId || !s.googleClientSecret) {
    res.writeHead(400, {'Content-Type':'text/plain'}); return res.end('Google SSO not configured.');
  }
  const state = newOAuthState();
  const params = new URLSearchParams({
    client_id: s.googleClientId,
    redirect_uri: ssoBaseUrl() + '/auth/google/callback',
    response_type: 'code',
    scope: 'openid email profile',
    state,
    access_type: 'online',
    prompt: 'select_account',
  });
  res.writeHead(302, { Location: 'https://accounts.google.com/o/oauth2/v2/auth?' + params.toString() });
  res.end();
});

R('GET', '/auth/google/callback', async (req, res) => {
  const qs = new URL('http://x' + req.url).searchParams;
  const code  = qs.get('code');
  const state = qs.get('state');
  const err   = qs.get('error');
  const base  = ssoBaseUrl();

  if (err || !code || !verifyOAuthState(state)) {
    res.writeHead(302, { Location: '/?sso_error=' + encodeURIComponent(err || 'Invalid or expired login attempt. Please try again.') });
    return res.end();
  }

  const s = getSettings();
  let tokenData;
  try {
    tokenData = await httpsPost('https://oauth2.googleapis.com/token', {
      code, client_id: s.googleClientId, client_secret: s.googleClientSecret,
      redirect_uri: base + '/auth/google/callback', grant_type: 'authorization_code',
    });
  } catch(e) {
    console.error('[sso] Google token exchange failed:', e.message);
    res.writeHead(302, { Location: '/?sso_error=' + encodeURIComponent('Authentication failed. Please try again.') });
    return res.end();
  }

  if (!tokenData.id_token) {
    console.error('[sso] Google: no id_token in response:', JSON.stringify(tokenData));
    res.writeHead(302, { Location: '/?sso_error=' + encodeURIComponent('Authentication failed. Please try again.') });
    return res.end();
  }

  const payload = decodeJwtPayload(tokenData.id_token);
  const email = payload && payload.email;
  const name  = (payload && payload.name) || email;

  const session = createSsoSession(email, name);
  if (!session) {
    console.log('[sso] Google: domain not allowed for', email);
    res.writeHead(302, { Location: '/?sso_error=' + encodeURIComponent('Access denied. Only @redhawkdigital.ai and @agr-us.com accounts may access LeadFlow.') });
    return res.end();
  }

  console.log('[auth] SSO Google login:', email, '(' + session.role + ')');
  res.writeHead(302, { Location: base + '/?sso_token=' + session.token + '&sso_user=' + encodeURIComponent(session.username) + '&sso_role=' + session.role });
  res.end();
});

// ── Microsoft OAuth2 (Entra ID / Azure AD) ────────────────────────────────────
R('GET', '/auth/microsoft', (req, res) => {
  const s = getSettings();
  if (!s.microsoftClientId || !s.microsoftClientSecret) {
    res.writeHead(400, {'Content-Type':'text/plain'}); return res.end('Microsoft SSO not configured.');
  }
  const state = newOAuthState();
  const params = new URLSearchParams({
    client_id: s.microsoftClientId,
    redirect_uri: ssoBaseUrl() + '/auth/microsoft/callback',
    response_type: 'code',
    scope: 'openid email profile',
    state,
    prompt: 'select_account',
  });
  res.writeHead(302, { Location: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?' + params.toString() });
  res.end();
});

R('GET', '/auth/microsoft/callback', async (req, res) => {
  const qs = new URL('http://x' + req.url).searchParams;
  const code  = qs.get('code');
  const state = qs.get('state');
  const err   = qs.get('error_description') || qs.get('error');
  const base  = ssoBaseUrl();

  if (err || !code || !verifyOAuthState(state)) {
    res.writeHead(302, { Location: '/?sso_error=' + encodeURIComponent(err || 'Invalid or expired login attempt. Please try again.') });
    return res.end();
  }

  const s = getSettings();
  let tokenData;
  try {
    tokenData = await httpsPost('https://login.microsoftonline.com/common/oauth2/v2.0/token', {
      code, client_id: s.microsoftClientId, client_secret: s.microsoftClientSecret,
      redirect_uri: base + '/auth/microsoft/callback', grant_type: 'authorization_code',
      scope: 'openid email profile',
    });
  } catch(e) {
    console.error('[sso] Microsoft token exchange failed:', e.message);
    res.writeHead(302, { Location: '/?sso_error=' + encodeURIComponent('Authentication failed. Please try again.') });
    return res.end();
  }

  if (!tokenData.id_token) {
    console.error('[sso] Microsoft: no id_token in response:', JSON.stringify(tokenData));
    res.writeHead(302, { Location: '/?sso_error=' + encodeURIComponent('Authentication failed. Please try again.') });
    return res.end();
  }

  const payload = decodeJwtPayload(tokenData.id_token);
  const email = (payload && (payload.email || payload.preferred_username || payload.upn)) || '';
  const name  = (payload && (payload.name || payload.given_name)) || email;

  const session = createSsoSession(email, name);
  if (!session) {
    console.log('[sso] Microsoft: domain not allowed for', email);
    res.writeHead(302, { Location: '/?sso_error=' + encodeURIComponent('Access denied. Only @redhawkdigital.ai and @agr-us.com accounts may access LeadFlow.') });
    return res.end();
  }

  console.log('[auth] SSO Microsoft login:', email, '(' + session.role + ')');
  res.writeHead(302, { Location: base + '/?sso_token=' + session.token + '&sso_user=' + encodeURIComponent(session.username) + '&sso_role=' + session.role });
  res.end();
});

// ── Auth ───────────────────────────────────────────────────────────────────────
R('POST', '/api/login', async (req, res) => {
  const {username='', password=''} = await parseBody(req);
  const u = username.trim();
  if (!u || !password) return jsonRes(res, 400, {ok:false, error:'Username and password required'});

  if (db.prepare('SELECT COUNT(*) as n FROM users').get().n === 0) {
    const salt = newSalt(), hash = hashPwd(password, salt);
    db.prepare('INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)').run(u, hash, salt, 'admin', new Date().toISOString());
    const token = newToken();
    db.prepare('INSERT INTO sessions (token, username, role, expires_at) VALUES (?, ?, ?, ?)').run(token, u, 'admin', Date.now() + SESSION_TTL);
    console.log(`[auth] Admin account created: "${u}"`);
    return jsonRes(res, 200, {ok:true, token, username:u, role:'admin', setup:true});
  }

  const user = db.prepare('SELECT * FROM users WHERE username=?').get(u);
  if (!user || hashPwd(password, user.salt) !== user.password_hash) {
    console.log(`[auth] Failed login: "${u}"`);
    return jsonRes(res, 401, {ok:false, error:'Invalid username or password'});
  }
  const token = newToken();
  db.prepare('INSERT INTO sessions (token, username, role, expires_at) VALUES (?, ?, ?, ?)').run(token, user.username, user.role, Date.now() + SESSION_TTL);
  console.log(`[auth] Login: ${user.username} (${user.role})`);
  jsonRes(res, 200, {ok:true, token, username:user.username, role:user.role});
});

R('POST', '/api/logout', (req, res) => {
  const token = req.headers['x-session-token'];
  if (token) db.prepare('DELETE FROM sessions WHERE token=?').run(token);
  jsonRes(res, 200, {ok:true});
});

R('GET', '/api/me', (req, res) => {
  const s = getSession(req);
  s ? jsonRes(res, 200, {ok:true, ...s}) : jsonRes(res, 401, {ok:false});
});

// ── Leads ──────────────────────────────────────────────────────────────────────
R('GET', '/api/leads', (req, res) => {
  if (!requireAuth(req, res)) return;
  const rows = db.prepare('SELECT data FROM leads').all();
  jsonRes(res, 200, {ok:true, leads: rows.length ? rows.map(r => JSON.parse(r.data)) : null});
});

R('POST', '/api/leads', async (req, res) => {
  if (!requireAuth(req, res)) return;
  const {leads} = await parseBody(req);
  if (!Array.isArray(leads)) return jsonRes(res, 400, {ok:false, error:'leads must be an array'});
  const del = db.prepare('DELETE FROM leads');
  const ins = db.prepare('INSERT INTO leads (id, data) VALUES (?, ?)');
  txn(() => { del.run(); leads.forEach(l => ins.run(l.id, JSON.stringify(l))); });
  jsonRes(res, 200, {ok:true});
});

// ── Contacts Research ──────────────────────────────────────────────────────────
R('GET', '/api/research', (req, res) => {
  if (!requireAuth(req, res)) return;
  const rows = db.prepare("SELECT data FROM research WHERE module='contacts'").all();
  jsonRes(res, 200, {ok:true, items: rows.length ? rows.map(r => JSON.parse(r.data)) : null});
});

R('POST', '/api/research', async (req, res) => {
  if (!requireAuth(req, res)) return;
  const {items} = await parseBody(req);
  if (!Array.isArray(items)) return jsonRes(res, 400, {ok:false, error:'items must be an array'});
  const del = db.prepare("DELETE FROM research WHERE module='contacts'");
  const ins = db.prepare("INSERT INTO research (id, module, data) VALUES (?, 'contacts', ?)");
  txn(() => { del.run(); items.forEach(r => ins.run(r.id, JSON.stringify(r))); });
  jsonRes(res, 200, {ok:true});
});

// ── Company Research ──────────────────────────────────────────────────────────
R('GET', '/api/company-research', (req, res) => {
  if (!requireAuth(req, res)) return;
  const rows = db.prepare("SELECT data FROM research WHERE module='company'").all();
  jsonRes(res, 200, {ok:true, items: rows.length ? rows.map(r => JSON.parse(r.data)) : null});
});

R('POST', '/api/company-research', async (req, res) => {
  if (!requireAuth(req, res)) return;
  const {items} = await parseBody(req);
  if (!Array.isArray(items)) return jsonRes(res, 400, {ok:false, error:'items must be an array'});
  const del = db.prepare("DELETE FROM research WHERE module='company'");
  const ins = db.prepare("INSERT INTO research (id, module, data) VALUES (?, 'company', ?)");
  txn(() => { del.run(); items.forEach(r => ins.run(r.id, JSON.stringify(r))); });
  jsonRes(res, 200, {ok:true});
});

// ── ERP Research ───────────────────────────────────────────────────────────────
R('GET', '/api/erp-research', (req, res) => {
  if (!requireAuth(req, res)) return;
  const rows = db.prepare("SELECT data FROM research WHERE module='erp'").all();
  jsonRes(res, 200, {ok:true, items: rows.length ? rows.map(r => JSON.parse(r.data)) : null});
});

R('POST', '/api/erp-research', async (req, res) => {
  if (!requireAuth(req, res)) return;
  const {items} = await parseBody(req);
  if (!Array.isArray(items)) return jsonRes(res, 400, {ok:false, error:'items must be an array'});
  const del = db.prepare("DELETE FROM research WHERE module='erp'");
  const ins = db.prepare("INSERT INTO research (id, module, data) VALUES (?, 'erp', ?)");
  txn(() => { del.run(); items.forEach(r => ins.run(r.id, JSON.stringify(r))); });
  jsonRes(res, 200, {ok:true});
});

// ── User management (admin) ────────────────────────────────────────────────────
R('GET', '/api/users', (req, res) => {
  if (!requireAdmin(req, res)) return;
  jsonRes(res, 200, {ok:true, users: db.prepare('SELECT username, role, created_at FROM users').all()});
});

R('POST', '/api/users', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  const {username='', password='', role='member'} = await parseBody(req);
  const u = username.trim();
  if (!u || !password) return jsonRes(res, 400, {ok:false, error:'Username and password required'});
  if (db.prepare('SELECT username FROM users WHERE username=?').get(u)) return jsonRes(res, 409, {ok:false, error:'Username already exists'});
  const salt = newSalt();
  db.prepare('INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)').run(u, hashPwd(password, salt), salt, role, new Date().toISOString());
  jsonRes(res, 200, {ok:true});
});

R('DELETE', '/api/users', async (req, res) => {
  const s = requireAdmin(req, res); if (!s) return;
  const {username} = await parseBody(req);
  if (username === s.username) return jsonRes(res, 400, {ok:false, error:'Cannot remove yourself'});
  db.prepare('DELETE FROM users WHERE username=?').run(username);
  db.prepare('DELETE FROM sessions WHERE username=?').run(username); // revoke all their sessions
  jsonRes(res, 200, {ok:true});
});

R('POST', '/api/change-password', async (req, res) => {
  const s = requireAuth(req, res); if (!s) return;
  const {currentPassword, newPassword} = await parseBody(req);
  const user = db.prepare('SELECT * FROM users WHERE username=?').get(s.username);
  if (!user || hashPwd(currentPassword, user.salt) !== user.password_hash)
    return jsonRes(res, 401, {ok:false, error:'Current password is incorrect'});
  const salt = newSalt();
  db.prepare('UPDATE users SET password_hash=?, salt=? WHERE username=?').run(hashPwd(newPassword, salt), salt, s.username);
  jsonRes(res, 200, {ok:true});
});

R('POST', '/api/reset-password', async (req, res) => {
  const s = requireAdmin(req, res); if (!s) return;
  const {username, newPassword} = await parseBody(req);
  if (!db.prepare('SELECT username FROM users WHERE username=?').get(username)) return jsonRes(res, 404, {ok:false, error:'User not found'});
  const salt = newSalt();
  db.prepare('UPDATE users SET password_hash=?, salt=? WHERE username=?').run(hashPwd(newPassword, salt), salt, username);
  jsonRes(res, 200, {ok:true});
});

// ── Settings ───────────────────────────────────────────────────────────────────
R('GET', '/api/settings', (req, res) => {
  if (!requireAuth(req, res)) return;
  const row = db.prepare('SELECT value FROM settings WHERE key=?').get('main');
  jsonRes(res, 200, {ok:true, settings: row ? JSON.parse(row.value) : null});
});

R('POST', '/api/settings', async (req, res) => {
  if (!requireAuth(req, res)) return;
  const {settings} = await parseBody(req);
  db.prepare('INSERT INTO settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run('main', JSON.stringify(settings));
  jsonRes(res, 200, {ok:true});
});

// ── Pipedrive Export ───────────────────────────────────────────────────────────
function toCsv(leads) {
  const headers = ['Lead Title','First Name','Last Name','Organization','Email','Phone','Lead Source','Expected Close Date','Lead Value Amount','Lead Value Currency','Note'];
  const esc = v => `"${String(v||'').replace(/"/g,'""')}"`;
  const rows = leads.map(l => {
    const parts = (l.name||'').trim().split(' ');
    const note  = [l.painPoint&&`Pain Point: ${l.painPoint}`,l.nextAction&&`Next Action: ${l.nextAction}`,l.serviceLine&&`Service Line: ${l.serviceLine}`,l.platform&&`Platform: ${l.platform}`,l.sourceModule&&`Source: ${l.sourceModule}`].filter(Boolean).join('\n');
    return [
      `${(l.name||'').trim()}${l.org?' — '+l.org:''}`,
      parts[0]||'', parts.slice(1).join(' ')||'',
      l.org||'', l.email||'', l.phone||'', l.source||l.sourceModule||'',
      l.closeDate||'', l.value||'', 'USD', note
    ].map(esc).join(',');
  });
  return [headers.map(esc).join(','), ...rows].join('\r\n');
}

function getSettings() {
  const row = db.prepare('SELECT value FROM settings WHERE key=?').get('main');
  return row ? JSON.parse(row.value) : {};
}
function saveSettings(s) {
  db.prepare('INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run('main', JSON.stringify(s));
}

function runExport() {
  const settings = getSettings();
  const since    = settings.lastExportedAt || '1970-01-01T00:00:00.000Z';
  const all      = db.prepare('SELECT data FROM leads').all().map(r => JSON.parse(r.data));
  const changed  = all.filter(l => (l.updatedAt||l.createdAt||'') > since);
  if (!changed.length) { console.log(`[export] No changes since ${since.slice(0,10)}`); return null; }
  const dateStr  = new Date().toISOString().slice(0,10);
  const outPath  = path.join(DATA_DIR, `pipedrive-export-${dateStr}.csv`);
  fs.writeFileSync(outPath, toCsv(changed), 'utf8');
  settings.lastExportedAt = new Date().toISOString();
  saveSettings(settings);
  console.log(`[export] ${outPath} (${changed.length} leads)`);
  return { outPath, count: changed.length, recipients: settings.exportRecipients||'' };
}

function sendExportEmail(outPath, count, recipients) {
  if (!recipients || !recipients.trim()) {
    console.log('[export] No recipients configured — skipping email. Set exportRecipients in Maintenance → Export Settings.');
    return;
  }
  const settings  = getSettings();
  const fromName  = (settings.exportSenderName||'').trim() || 'LeadFlow · Redhawk Federal Solutions';
  const dateLabel = new Date().toLocaleDateString('en-US',{weekday:'long',month:'long',day:'numeric',year:'numeric'});
  const subject   = `LeadFlow Pipedrive Export — ${count} lead${count!==1?'s':''} — ${dateLabel}`;
  const body      = `LeadFlow Weekly Pipedrive Export\\n\\nDate: ${dateLabel}\\nNew or Updated Leads: ${count}\\n\\nPlease import the attached CSV into Pipedrive → Leads → Import.\\nThis export includes only leads added or modified since the previous export.\\n\\n— ${fromName}`;
  const safePath  = outPath.replace(/\\/g,'\\\\');
  const ps = `
try {
  $o = New-Object -ComObject Outlook.Application
  $m = $o.CreateItem(0)
  $m.To      = "${recipients.replace(/"/g,'\\"')}"
  $m.Subject = "${subject.replace(/"/g,'\\"')}"
  $m.Body    = "${body}"
  $m.Attachments.Add("${safePath}")
  $m.Send()
  Write-Host "sent"
} catch { Write-Error $_.Exception.Message }`;
  const proc = spawn('powershell.exe', ['-NonInteractive','-Command', ps]);
  proc.stdout.on('data', d => { if(d.toString().includes('sent')) console.log(`[export] Email sent → ${recipients}`); });
  proc.stderr.on('data', d => console.error('[export email]', d.toString().trim()));
}

// ── Wednesday 3 PM Export Scheduler ───────────────────────────────────────────
function scheduleWednesdayExport() {
  const now  = new Date();
  const next = new Date(now);
  next.setHours(15, 0, 0, 0);                      // 3:00:00 PM local time
  const dow  = next.getDay();                       // 0=Sun … 3=Wed … 6=Sat
  let   diff = (3 - dow + 7) % 7;                  // days until Wednesday
  if (diff === 0 && now >= next) diff = 7;          // already past 3 PM Wednesday → next week
  next.setDate(next.getDate() + diff);
  const ms  = next - now;
  const hrs = (ms / 36e5).toFixed(1);
  console.log(`  Next Pipedrive export: ${next.toLocaleString('en-US')} (in ${hrs}h)`);
  setTimeout(() => {
    console.log('[export] Running Wednesday 3 PM Pipedrive export…');
    const result = runExport();
    if (result) sendExportEmail(result.outPath, result.count, result.recipients);
    scheduleWednesdayExport();                      // schedule next week
  }, ms);
}
scheduleWednesdayExport();

// ── Nightly ERP Research ───────────────────────────────────────────────────────

// ── API cost tracking ─────────────────────────────────────────────────────────
// Claude Haiku 4.5 pricing (per token)
const HAIKU_PRICE = { input: 0.80 / 1e6, output: 4.00 / 1e6 };
const calcCost = (inp, out) => inp * HAIKU_PRICE.input + out * HAIKU_PRICE.output;

function logUsage(inputTokens, outputTokens, purpose) {
  const cost = calcCost(inputTokens, outputTokens);
  const id   = `u-${Date.now()}-${Math.random().toString(36).slice(2,7)}`;
  db.prepare('INSERT INTO api_usage (id, timestamp, input_tokens, output_tokens, cost_usd, purpose) VALUES (?,?,?,?,?,?)')
    .run(id, new Date().toISOString(), inputTokens, outputTokens, cost, purpose||'erp_research');
  return cost;
}

function getMonthlySpend() {
  const start = new Date(); start.setDate(1); start.setHours(0,0,0,0);
  return db.prepare('SELECT COALESCE(SUM(cost_usd),0) as total FROM api_usage WHERE timestamp>=?').get(start.toISOString()).total;
}

function isUnderBudget() {
  const s = getSettings();
  const limit = parseFloat(s.monthlyApiLimit || '0');
  if (!limit || limit <= 0) return true;   // no limit → always allowed
  return getMonthlySpend() < limit;
}

R('GET', '/api/usage', (req, res) => {
  if (!requireAuth(req, res)) return;
  const now        = new Date();
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();
  const yearStart  = new Date(now.getFullYear(), 0, 1).toISOString();
  const mo  = db.prepare('SELECT COALESCE(SUM(cost_usd),0) as cost, COALESCE(SUM(input_tokens),0) as inp, COALESCE(SUM(output_tokens),0) as out, COUNT(*) as calls FROM api_usage WHERE timestamp>=?').get(monthStart);
  const ytd = db.prepare('SELECT COALESCE(SUM(cost_usd),0) as cost FROM api_usage WHERE timestamp>=?').get(yearStart);
  const s   = getSettings();
  const limit = parseFloat(s.monthlyApiLimit || '0');
  jsonRes(res, 200, {ok:true, monthly:{cost:mo.cost, calls:mo.calls, inputTokens:mo.inp, outputTokens:mo.out}, ytd:{cost:ytd.cost}, limit, remaining: limit>0 ? Math.max(0,limit-mo.cost) : null});
});

// Fetch Google News RSS for a query; returns array of {title, desc} or []
function fetchNewsRSS(query) {
  return new Promise(resolve => {
    const encoded = encodeURIComponent(query);
    const options = {
      hostname: 'news.google.com',
      path: `/rss/search?q=${encoded}&hl=en-US&gl=US&ceid=US:en`,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; LeadFlowBot/1.0)' },
      timeout: 12000,
    };
    const req = https.get(options, res => {
      if (res.statusCode !== 200) { res.resume(); resolve([]); return; }
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        const items = [];
        for (const m of data.matchAll(/<item>([\s\S]*?)<\/item>/g)) {
          const b = m[1];
          const getTag = tag => {
            const m = b.match(new RegExp(`<${tag}[^>]*><!\\[CDATA\\[([\\s\\S]*?)\\]\\]><\\/${tag}>`))||
                      b.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`));
            return m ? m[1].replace(/<[^>]+>/g,'').trim() : '';
          };
          const title = getTag('title');
          const desc  = getTag('description').slice(0,120);
          if (title && !title.toLowerCase().includes('google news')) items.push({title, desc});
        }
        resolve(items.slice(0, 4));
      });
    });
    req.on('error', () => resolve([]));
    req.on('timeout', () => { req.destroy(); resolve([]); });
  });
}

// Call Anthropic Messages API; returns parsed JSON response or null
// Retries once after 65 seconds if a rate-limit (529 / overloaded) error is returned
function callAnthropicAPI(apiKey, messages, maxTokens, _retryCount) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: maxTokens || 4096,
      messages,
    });
    const req = https.request({
      hostname: 'api.anthropic.com',
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
      },
      timeout: 120000,
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        let parsed = null;
        try { parsed = JSON.parse(data); } catch(e) { return resolve(null); }
        // Rate limit or overloaded — retry once after 65 seconds
        if ((res.statusCode === 529 || res.statusCode === 429) && (_retryCount || 0) < 1) {
          const wait = 65000;
          console.warn('[anthropic] Rate limit hit — waiting 65 seconds before retry…');
          setTimeout(() => {
            callAnthropicAPI(apiKey, messages, maxTokens, (_retryCount || 0) + 1).then(resolve).catch(reject);
          }, wait);
        } else {
          resolve(parsed);
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Anthropic API timeout')); });
    req.write(body);
    req.end();
  });
}

// Search Apollo.io for a real decision-maker contact at a given company
function searchApolloContact(apiKey, companyName, suggestedTitle) {
  // Pick title search list based on what Claude suggested
  const ERP_TITLES = [
    'Chief Information Officer','CIO','Chief Technology Officer','CTO',
    'Chief Digital Officer','VP of IT','VP Information Technology',
    'Vice President of IT','SVP IT','SVP of IT','Director of IT',
    'Director of ERP','Director of Information Technology',
    'VP of Operations','VP Operations','Director of Operations',
    'Chief Financial Officer','CFO','Chief Operating Officer','COO',
  ];
  const t = (suggestedTitle||'').toLowerCase();
  // Weight titles based on Claude's suggestion — put closest matches first
  const sorted = [...ERP_TITLES].sort((a,b) => {
    const am = a.toLowerCase().split(' ').some(w=>t.includes(w)&&w.length>2) ? 0 : 1;
    const bm = b.toLowerCase().split(' ').some(w=>t.includes(w)&&w.length>2) ? 0 : 1;
    return am - bm;
  });

  return new Promise(resolve => {
    const body = JSON.stringify({
      q_organization_name: companyName,
      person_titles: sorted.slice(0, 8),
      page: 1,
      per_page: 3,
    });
    const req = https.request({
      hostname: 'api.apollo.io',
      path: '/api/v1/mixed_people/api_search',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-cache',
        'Authorization': `Bearer ${apiKey}`,
        'content-length': Buffer.byteLength(body),
      },
      timeout: 15000,
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const r = JSON.parse(data);
          const p = (r.people||[])[0];
          if (!p) { resolve(null); return; }
          // Search API returns name/title/LinkedIn freely; email+phone require paid enrichment
          resolve({
            contactName:  p.name || `${p.first_name||''} ${p.last_name||''}`.trim(),
            title:        p.title || p.headline || '',
            email:        p.email || '',
            phone:        (p.phone_numbers||[])[0]?.sanitized_number || '',
            linkedInUrl:  p.linkedin_url || p.linkedin_profile_url || '',
            apolloEnriched: true,
          });
        } catch { resolve(null); }
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.write(body);
    req.end();
  });
}

function searchApolloByName(apiKey, personName, orgHint) {
  // Returns promise resolving to array of up to 3 results (or null on failure)
  return new Promise(resolve => {
    const body = JSON.stringify({
      q_person_name: personName,
      ...(orgHint ? { q_organization_name: orgHint } : {}),
      page: 1,
      per_page: 5,
    });
    const req = https.request({
      hostname: 'api.apollo.io',
      path: '/api/v1/mixed_people/api_search',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-cache',
        'Authorization': `Bearer ${apiKey}`,
        'content-length': Buffer.byteLength(body),
      },
      timeout: 15000,
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const r = JSON.parse(data);
          const people = (r.people||[]).slice(0,5).map(p => ({
            contactName: p.name || `${p.first_name||''} ${p.last_name||''}`.trim(),
            title: p.title || p.headline || '',
            company: p.organization_name || (p.organization && p.organization.name) || '',
            email: p.email || '',
            phone: (p.phone_numbers||[])[0]?.sanitized_number || '',
            linkedInUrl: p.linkedin_url || p.linkedin_profile_url || '',
            location: p.city && p.state ? `${p.city}, ${p.state}` : (p.country || ''),
            apolloEnriched: true,
          }));
          resolve(people.length ? people : null);
        } catch { resolve(null); }
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.write(body);
    req.end();
  });
}

async function runNightlyERPResearch() {
  const settings = getSettings();
  const apiKey   = (settings.anthropicApiKey || '').trim();
  if (!apiKey) {
    console.log('[research] Skipping — no Anthropic API key. Add it in Maintenance → Research AI.');
    return { added: 0, skipped: true };
  }
  if (!isUnderBudget()) {
    const spent = getMonthlySpend();
    const limit = parseFloat(settings.monthlyApiLimit || '0');
    console.log(`[research] Monthly budget reached ($${spent.toFixed(4)} / $${limit}). Skipping.`);
    return { added: 0, budgetExceeded: true, spent, limit };
  }

  const erpSystems = settings.erpSystems || ['IFS','Microsoft D365','SAP','Infor','Microsoft Business Central','Deltek'];

  // Gather recent news — ERP systems + expanded signal categories
  const newsBlocks = [];
  for (const erp of erpSystems) {
    const articles = await fetchNewsRSS(`"${erp}" ERP implementation OR migration OR upgrade OR failure OR "over budget" OR "behind schedule"`);
    if (articles.length) {
      newsBlocks.push(`=== ${erp} ===\n` + articles.map(a => `• ${a.title}${a.desc ? ': ' + a.desc : ''}`).join('\n'));
    }
    await new Promise(r => setTimeout(r, 700));
  }
  // Additional signal categories
  const extraQueries = [
    'company "agentic AI" OR "AI transformation" ERP business operations 2025 2026',
    'company "multiple ERP systems" OR "ERP consolidation" OR "ERP rationalization" OR "ERP integration" problems',
    'company "failed ERP" OR "ERP failure" OR "ERP project over budget" OR "ERP delayed" OR "digital transformation failure"',
    'company "business process improvement" OR "process optimization" OR "operational efficiency" consulting 2025 2026',
    'site:linkedin.com "ERP" "looking for" OR "seeking" OR "struggling with" OR "need help" business transformation',
  ];
  for (const q of extraQueries) {
    const articles = await fetchNewsRSS(q);
    if (articles.length) newsBlocks.push(`=== SIGNAL: ${q.slice(0,60)} ===\n` + articles.map(a => `• ${a.title}${a.desc?': '+a.desc:''}`).join('\n'));
    await new Promise(r => setTimeout(r, 600));
  }

  const existingRows     = db.prepare("SELECT data FROM research WHERE module='erp'").all().map(r => JSON.parse(r.data));
  const existingNames    = new Set(existingRows.map(i => (i.company||'').toLowerCase().trim()));
  const existingList     = [...existingNames].slice(0,30).join(', ') || 'none';
  const newsContext      = newsBlocks.length ? `RECENT NEWS ARTICLES:\n${newsBlocks.join('\n\n')}\n\n` : '';

  const today = new Date().toISOString().slice(0,10);
  const prompt = `${newsContext}You are an expert B2B sales intelligence analyst for Redhawk Federal Solutions, a US-based consulting firm specializing in ERP implementations (${erpSystems.join(', ')}), business transformation, and digital experience consulting.

Identify every specific, real company you can find that represents a genuine, high-potential ERP consulting opportunity for Redhawk. Do not cap the list — include as many as you can confidently support with real buying signals. Use the news articles above AND your knowledge of the ERP industry, typical buyer profiles, and recent market activity. Only include a company if you are confident it is a real opportunity; quality is more important than quantity, but do not arbitrarily limit the count.

GEOGRAPHY PRIORITY — this is critical:
- PRIORITIZE US-based companies first and foremost. These are Redhawk's primary target market.
- US-headquartered companies with international divisions or global operations are still "US" — include them.
- You MAY include non-US international companies (e.g. UK, Canada, Australia, India), but only after exhausting strong US opportunities, and clearly mark them as "International".
- Set "geography" to "US" for US-headquartered companies, or the country name (e.g. "UK", "India", "Canada") for non-US companies.

Focus on companies with REAL buying signals across ALL of these categories — do not limit to ERP replacement only:

ERP & SYSTEMS:
- Growing mid-market companies (500–10,000 employees) needing system upgrades or replacements
- Government contractors (Deltek opportunities)
- Manufacturing, aerospace, defense, construction firms (IFS, D365, SAP)
- Companies that recently went public, received funding, or were acquired (system consolidation need)
- Firms publicly mentioning digital transformation or ERP pain points

AI & AGENTIC AI (HIGH PRIORITY — emerging Redhawk opportunity):
- Companies publicly discussing AI strategy, agentic AI, AI agents, or AI-driven automation
- Companies hiring for AI/ML roles indicating active AI investment
- Companies that have announced AI transformation programs or pilots
- Executives posting or quoted about AI challenges, AI adoption difficulties, or needing AI expertise
- Companies trying to integrate AI into existing ERP/business processes

MULTI-ERP / ERP OPTIMIZATION (no new ERP needed — process + integration play):
- Companies running multiple ERP systems across divisions or from M&A (integration opportunity)
- Companies trying to get more out of current ERP without replacing it (optimization/consulting)
- Companies with ERP shelfware — licensed but underutilized modules
- Companies where business processes don't match their ERP configuration

BUSINESS PROCESS ANALYSIS & IMPROVEMENT:
- Companies publicly seeking business process assessments, audits, or optimization
- Companies in sectors undergoing regulatory or operational change requiring process redesign
- Companies that have grown rapidly and whose processes have not kept pace
- Companies post-acquisition needing process harmonization across merged entities

STRUGGLING / FAILED PROJECTS (URGENT opportunity — they need rescue):
- Companies whose ERP or digital transformation project is over budget or behind schedule
- Companies that have publicly announced a failed implementation or system rollback
- Companies replacing a failed system from a competitor
- Companies that have fired their previous consulting firm or SI partner
- Companies with known project governance problems (audit findings, board complaints, press coverage)
- LinkedIn posts or news articles where executives describe project pain, frustration, or failure

LINKEDIN & SOCIAL SIGNALS:
- Any executive quoted in news that originated from a LinkedIn post about technology challenges
- Companies whose job postings on LinkedIn signal active investment (ERP analyst, transformation lead, AI engineer)
- Industry forum or association discussions mentioning company names alongside pain points

Skip these companies already in our pipeline: ${existingList}

SCORING RULES — be strict:
- 8–10 (Hot): ONLY if you have specific, concrete evidence of an ACTIVE project or pain — e.g. an announced ERP replacement, a public RFP, a quoted exec describing the problem, job postings confirming an active initiative, a known compliance deadline, or a merger/acquisition requiring system consolidation. Vague fit is NOT enough.
- 6–7 (Warm): Clear indicators suggest a need is likely coming — growth, new leadership, sector-typical pain — but no confirmed active project.
- 1–5 (Cool): General industry fit only, no meaningful signal found. If you cannot find ANY real signal for a company, score it 1–5 or exclude it entirely.

Return ONLY a JSON array, no other text. Each item must have exactly these fields.
For "signals": 2–5 short specific tags (3–6 words each) explaining WHY this company is flagged — e.g. "SAP ECC End-of-Support", "Failed ERP Rollback", "Active AI Transformation", "M&A System Consolidation", "CIO Quoted on Pain", "LinkedIn Hiring Confirms Project", "ERP Over Budget & Late". Avoid vague tags like "ERP Need" or "Digital Transformation".
[{
  "contactName": "Jane Doe or TBD - CIO",
  "company": "Acme Corp",
  "title": "VP of IT",
  "sector": "Commercial",
  "industry": "Aerospace & Defense",
  "geography": "US",
  "currentPlatform": "SAP ECC or Legacy/Unknown",
  "recommendedServiceLine": "Business Transformation",
  "opportunityScore": 8,
  "signals": ["SAP ECC End-of-Support", "3 ERP Roles on LinkedIn", "CIO Quoted on Pain"],
  "primarySignal": "One sentence — the single strongest buying signal found",
  "urgencyIndicators": "Signal A, Signal B",
  "painPoints": "REQUIRED: Specific, concrete evidence of the business opportunity. Quote news headlines, cite job postings, name the announced project, describe the known compliance deadline, or explain the exact pain. This must be evidence-based — not generic. Example: 'Company announced SAP ECC end-of-support migration in Q1 2026 earnings call. CIO stated they are evaluating S/4HANA and IFS. 3 open ERP architect roles posted on LinkedIn confirm active project.' If no concrete evidence exists, write what is known and keep score at 5 or below.",
  "notes": "2-3 sentences on what Redhawk should lead with and how to approach this opportunity.",
  "linkedInUrl": "",
  "source": "${today} - AI Research"
}]

opportunityScore is 1–10 (integer). Only include verifiable, real companies. Quality over quantity.`;

  console.log(`[research] Calling Anthropic API (${newsBlocks.length} news blocks for context)…`);
  let response;
  try {
    response = await callAnthropicAPI(apiKey, [{ role: 'user', content: prompt }], 8192);
  } catch(e) {
    console.error('[research] API call failed:', e.message);
    return { added: 0, error: e.message };
  }

  if (!response || !response.content || !response.content[0]) {
    const err = (response && response.error && response.error.message) || 'Empty response from API';
    console.error('[research] Bad API response:', err);
    return { added: 0, error: err };
  }

  // Log token usage immediately after successful response
  if (response.usage) {
    const cost = logUsage(response.usage.input_tokens||0, response.usage.output_tokens||0, 'erp_research');
    console.log(`[research] Tokens: ${response.usage.input_tokens} in / ${response.usage.output_tokens} out — cost $${cost.toFixed(4)}`);
  }

  const text = response.content[0].text || '';
  const match = text.match(/\[[\s\S]*\]/);
  if (!match) { console.error('[research] No JSON array in response'); return { added: 0, error: 'No JSON returned' }; }

  let items;
  try { items = JSON.parse(match[0]); } catch { return { added: 0, error: 'JSON parse error' }; }
  if (!Array.isArray(items)) return { added: 0, error: 'Response was not an array' };

  // Apollo enrichment — find real contact data for each company
  const apolloKey = (settings.apolloApiKey || '').trim();
  let apolloHits = 0;
  if (apolloKey) {
    console.log(`[research] Enriching ${items.length} items via Apollo.io…`);
    for (let i = 0; i < items.length; i++) {
      const contact = await searchApolloContact(apolloKey, items[i].company, items[i].title);
      if (contact) {
        items[i] = { ...items[i], ...contact };
        apolloHits++;
        console.log(`[research] Apollo ✓ ${contact.contactName} @ ${items[i].company}${contact.email?' — '+contact.email:''}`);
      } else {
        console.log(`[research] Apollo — no match for ${items[i].company}`);
      }
      await new Promise(r => setTimeout(r, 350)); // stay under rate limit
    }
    console.log(`[research] Apollo enrichment: ${apolloHits}/${items.length} contacts found`);
  }

  const ins = db.prepare("INSERT OR IGNORE INTO research (id, module, data) VALUES (?, 'erp', ?)");
  let added = 0;
  txn(() => {
    for (const item of items) {
      if (!item.company || existingNames.has((item.company||'').toLowerCase().trim())) continue;
      const id = `erp-ai-${Date.now()}-${Math.random().toString(36).slice(2,7)}`;
      const full = {
        id, status: 'New', promotedLeadId: null, owner: 'Blair', assignedTo: 'Blair',
        ...item,
        opportunityScore: Math.min(10, Math.max(1, Math.round(Number(item.opportunityScore)||5))),
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      ins.run(id, JSON.stringify(full));
      existingNames.add(item.company.toLowerCase().trim());
      added++;
    }
  });

  const s = getSettings();
  s.lastERPResearchAt = new Date().toISOString();
  saveSettings(s);
  console.log(`[research] Done — added ${added} of ${items.length} returned items (${apolloHits} Apollo contacts)`);
  return { added, total: items.length, apolloHits };
}

// Schedule nightly at 2:00 AM local time
function scheduleNightlyResearch() {
  const now  = new Date();
  const next = new Date(now);
  next.setHours(2, 0, 0, 0);
  if (now >= next) next.setDate(next.getDate() + 1);
  const ms  = next - now;
  const hrs = (ms / 36e5).toFixed(1);
  console.log(`  Next ERP research:      ${next.toLocaleString('en-US')} (in ${hrs}h)`);
  setTimeout(async () => {
    console.log('[research] Running nightly ERP research job…');
    await runNightlyERPResearch();
    scheduleNightlyResearch();
  }, ms);
}
scheduleNightlyResearch();

// ── Nightly Contacts Research ──────────────────────────────────────────────────
async function runNightlyContactsResearch() {
  const settings = getSettings();
  const apiKey   = (settings.anthropicApiKey || '').trim();
  if (!apiKey) {
    console.log('[contacts] Skipping — no Anthropic API key.');
    return { added: 0, skipped: true };
  }
  if (!isUnderBudget()) {
    const spent = getMonthlySpend();
    const limit = parseFloat(settings.monthlyApiLimit || '0');
    console.log(`[contacts] Monthly budget reached ($${spent.toFixed(4)} / $${limit}). Skipping.`);
    return { added: 0, budgetExceeded: true, spent, limit };
  }

  const erpSystems    = settings.erpSystems || ['IFS','Microsoft D365','SAP','Infor','Microsoft Business Central','Deltek'];
  const existingRows  = db.prepare("SELECT data FROM research WHERE module='contacts'").all().map(r => JSON.parse(r.data));
  const existingNames = new Set(existingRows.map(i => `${(i.contactName||'').toLowerCase()}|${(i.company||'').toLowerCase()}`));
  const existingList  = [...new Set(existingRows.map(i => i.company).filter(Boolean))].slice(0,30).join(', ') || 'none';

  // Fetch news around digital transformation / ERP buying signals for contacts context
  const newsBlocks = [];
  const contactQueries = [
    'digital transformation executive hiring CIO CTO new role',
    `ERP implementation ${erpSystems.slice(0,4).join(' OR ')} decision maker`,
    'company "agentic AI" OR "AI transformation" OR "AI agents" executive 2026',
    'company "failed ERP" OR "ERP over budget" OR "delayed implementation" leadership',
    'company "business process improvement" OR "process assessment" executive consulting',
  ];
  for (const q of contactQueries) {
    const articles = await fetchNewsRSS(q);
    if (articles.length) newsBlocks.push(`=== ${q.slice(0,50)} ===\n` + articles.map(a => `• ${a.title}`).join('\n'));
    await new Promise(r => setTimeout(r, 600));
  }

  const today = new Date().toISOString().slice(0,10);
  const rawContext = newsBlocks.join('\n');
  const newsContext = rawContext.length ? `RECENT NEWS SIGNALS:\n${rawContext.slice(0, 3000)}\n\n` : '';

  const prompt = `${newsContext}You are an expert B2B sales intelligence analyst for Redhawk Federal Solutions, specializing in ERP consulting (${erpSystems.join(', ')}), business transformation, digital experience, cybersecurity, and applied AI.

Identify every individual business leader you can confidently identify as a high-potential sales contact for Redhawk. Do not cap the list — include as many as you can support with real signals. Only include someone if you are confident they represent a genuine, high-quality opportunity; quality over quantity, but do not impose an arbitrary limit.

GEOGRAPHY PRIORITY — this is critical:
- PRIORITIZE contacts at US-based companies first and foremost. These are Redhawk's primary target market.
- Contacts at US-headquartered companies with global operations are still "US" — include them.
- You MAY include contacts at non-US companies (e.g. UK, Canada, Australia), but only after exhausting strong US contacts, and clearly mark them as "International".
- Set "geography" to "US" for US-headquartered companies, or the country name (e.g. "UK", "Canada") for non-US companies.

Target decision makers who show one or more of these buying signals. All six categories are equally important — do NOT limit yourself to ERP replacement signals only:

ERP & SYSTEMS:
- Recently appointed to a new executive role (first 90 days = high opportunity window)
- Leading a company that announced growth, funding, M&A, or digital transformation
- Known to be evaluating or replacing ${erpSystems.join(', ')} or other legacy ERP systems
- Running a government contractor or defense firm needing Deltek/compliance solutions
- Publicly discussing digital transformation challenges or technology modernization
- At a company posting for ERP, IT transformation, or digital roles (signals active investment)
- In manufacturing, aerospace, defense, construction, logistics, healthcare, or federal sectors

AI & AGENTIC AI (HIGH PRIORITY):
- Executives publicly discussing AI strategy, agentic AI, AI agents, or AI automation challenges
- Companies hiring for AI/ML or agentic workflow roles (signals active AI investment)
- Executives quoted about needing AI expertise or struggling with AI adoption
- Companies integrating AI into existing ERP or business operations

MULTI-ERP / ERP OPTIMIZATION (no new ERP — process + integration play):
- Executives at companies running multiple ERP systems from M&A or organic growth
- Leaders trying to optimize or get more value from existing ERP without replacing it
- Companies with misaligned business processes that don't match their ERP configuration

BUSINESS PROCESS ANALYSIS & IMPROVEMENT:
- Executives seeking operational efficiency, process redesign, or business assessments
- Companies post-acquisition needing process harmonization across merged entities
- Companies that have grown rapidly and whose processes have not kept pace

STRUGGLING / FAILED PROJECTS (URGENT — highest scoring opportunity):
- Executives whose ERP or digital transformation project is publicly over budget or behind schedule
- Companies that publicly replaced a failed system or fired their previous SI/consulting firm
- Executives describing project pain, frustration, or failure in public statements or LinkedIn posts

LINKEDIN & SOCIAL SIGNALS:
- Any executive whose public LinkedIn posts describe technology challenges, project struggles, or AI/ERP needs
- Executives at companies with job postings indicating active ERP, AI, or transformation investment

Companies already in our contacts pipeline (skip people from these): ${existingList}

SCORING RULES — be strict:
- 8–10 (Hot): ONLY if there is specific, concrete evidence of an active initiative or pain — e.g. the person just joined a new company and their mandate is known, an exec publicly described a technology challenge, the company has an open ERP/transformation role confirming active work, a news article named this person in the context of a specific project, or a compliance/contract deadline is imminent. General "new CIO" without a known mandate is NOT 8+.
- 6–7 (Warm): Strong circumstantial signals — new executive role, company in transformation, relevant sector — but no confirmed active project.
- 1–5 (Cool): General fit only, no meaningful signal. Exclude if you have nothing concrete.

Return ONLY a JSON array (no other text). Each item must have exactly these fields:
[{
  "contactName": "Jane Doe",
  "company": "Acme Defense Corp",
  "title": "Chief Information Officer",
  "sector": "Federal",
  "industry": "Aerospace & Defense",
  "geography": "US",
  "currentPlatform": "SAP ECC or Legacy/Unknown",
  "recommendedServiceLine": "Business Transformation",
  "opportunityScore": 9,
  "primarySignal": "One sentence — the single strongest buying signal for this person",
  "urgencyIndicators": "New role — 60 days in, Active ERP evaluation",
  "painPoints": "REQUIRED: Specific evidence of the opportunity. Cite the news article, job posting, public statement, or known project that proves there is a real need. Example: 'Jane Doe joined Acme in April 2026 from Boeing where she led a $30M ERP overhaul. Acme has 4 open IFS architect roles on LinkedIn and announced a supply chain modernization initiative in their Q1 earnings. She publicly stated on LinkedIn that legacy systems are her top priority.' If you only have general context, state it honestly and keep the score at 6 or below.",
  "notes": "2-3 sentences on why this person is a strong Redhawk opportunity and what to lead with in outreach.",
  "linkedInUrl": "",
  "source": "${today} - AI Contacts Research"
}]

opportunityScore is 1–10 integer. Only include real, verifiable people. Quality matters — if you are not confident someone is a genuine opportunity, exclude them.`;

  console.log(`[contacts] Calling Anthropic API for contacts research…`);
  let response;
  try {
    response = await callAnthropicAPI(apiKey, [{ role: 'user', content: prompt }], 8192);
  } catch(e) {
    console.error('[contacts] API call failed:', e.message);
    return { added: 0, error: e.message };
  }

  if (!response || !response.content || !response.content[0]) {
    const err = (response && response.error && response.error.message) || 'Empty response';
    console.error('[contacts] Bad API response:', err);
    return { added: 0, error: err };
  }

  if (response.usage) {
    const cost = logUsage(response.usage.input_tokens||0, response.usage.output_tokens||0, 'contacts_research');
    console.log(`[contacts] Tokens: ${response.usage.input_tokens} in / ${response.usage.output_tokens} out — cost $${cost.toFixed(4)}`);
  }

  const text  = response.content[0].text || '';
  const match = text.match(/\[[\s\S]*\]/);
  if (!match) { console.error('[contacts] No JSON array in response'); return { added: 0, error: 'No JSON returned' }; }

  let items;
  try { items = JSON.parse(match[0]); } catch { return { added: 0, error: 'JSON parse error' }; }
  if (!Array.isArray(items)) return { added: 0, error: 'Response was not an array' };

  // Apollo enrichment
  const apolloKey = (settings.apolloApiKey || '').trim();
  let apolloHits = 0;
  if (apolloKey) {
    console.log(`[contacts] Enriching ${items.length} contacts via Apollo.io…`);
    for (let i = 0; i < items.length; i++) {
      const contact = await searchApolloContact(apolloKey, items[i].company, items[i].title);
      if (contact) {
        items[i] = { ...items[i], ...contact };
        apolloHits++;
        console.log(`[contacts] Apollo ✓ ${contact.contactName} @ ${items[i].company}${contact.email?' — '+contact.email:''}`);
      }
      await new Promise(r => setTimeout(r, 350));
    }
    console.log(`[contacts] Apollo enrichment: ${apolloHits}/${items.length} contacts found`);
  }

  const ins = db.prepare("INSERT OR IGNORE INTO research (id, module, data) VALUES (?, 'contacts', ?)");
  let added = 0;
  txn(() => {
    for (const item of items) {
      if (!item.contactName || !item.company) continue;
      const key = `${(item.contactName||'').toLowerCase()}|${(item.company||'').toLowerCase()}`;
      if (existingNames.has(key)) continue;
      const id = `con-ai-${Date.now()}-${Math.random().toString(36).slice(2,7)}`;
      const full = {
        id, status: 'New', promotedLeadId: null, owner: 'Blair', assignedTo: 'Blair',
        signals: (item.urgencyIndicators||'').split(',').map(s=>s.trim()).filter(Boolean),
        ...item,
        opportunityScore: Math.min(10, Math.max(1, Math.round(Number(item.opportunityScore)||5))),
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      ins.run(id, JSON.stringify(full));
      existingNames.add(key);
      added++;
    }
  });

  const s = getSettings();
  s.lastContactsResearchAt = new Date().toISOString();
  saveSettings(s);
  console.log(`[contacts] Done — added ${added} of ${items.length} items (${apolloHits} Apollo contacts)`);
  return { added, total: items.length, apolloHits };
}

// Schedule contacts research at 2:30 AM (offset from ERP at 2:00 AM)
function scheduleNightlyContactsResearch() {
  const now  = new Date();
  const next = new Date(now);
  next.setHours(2, 30, 0, 0);
  if (now >= next) next.setDate(next.getDate() + 1);
  const ms  = next - now;
  const hrs = (ms / 36e5).toFixed(1);
  console.log(`  Next contacts research: ${next.toLocaleString('en-US')} (in ${hrs}h)`);
  setTimeout(async () => {
    console.log('[contacts] Running nightly contacts research job…');
    await runNightlyContactsResearch();
    scheduleNightlyContactsResearch();
  }, ms);
}
scheduleNightlyContactsResearch();

// ── Company/Names Research ─────────────────────────────────────────────────────
async function runNightlyCompanyResearch() {
  const settings = getSettings();
  const apiKey   = (settings.anthropicApiKey || '').trim();
  if (!apiKey) {
    console.log('[company] Skipping — no Anthropic API key.');
    return { added: 0, skipped: true };
  }
  if (!isUnderBudget()) {
    const spent = getMonthlySpend();
    const limit = parseFloat(settings.monthlyApiLimit || '0');
    console.log(`[company] Monthly budget reached ($${spent.toFixed(4)} / $${limit}). Skipping.`);
    return { added: 0, budgetExceeded: true, spent, limit };
  }

  const targetCompanies = (settings.targetCompanies || []).filter(t => t && t.trim());
  if (!targetCompanies.length) {
    console.log('[company] No target companies/names configured. Add them in Maintenance → Companies/Names.');
    return { added: 0, skipped: true, reason: 'no targets' };
  }

  const erpSystems = settings.erpSystems || ['IFS','Microsoft D365','SAP','Infor','Microsoft Business Central','Deltek'];

  // Fetch news for each target company/name (up to 6), including expanded signal categories
  const newsBlocks = [];
  for (const target of targetCompanies.slice(0, 6)) {
    const queries = [
      `"${target}" digital transformation OR ERP OR technology OR business`,
      `"${target}" "agentic AI" OR "AI transformation" OR "AI agents" OR "failed project" OR "over budget"`,
      `"${target}" "business process" OR "process improvement" OR "ERP consolidation" OR "multiple ERP"`,
    ];
    const targetArticles = [];
    for (const q of queries) {
      const articles = await fetchNewsRSS(q);
      targetArticles.push(...articles);
      await new Promise(r => setTimeout(r, 500));
    }
    if (targetArticles.length) {
      newsBlocks.push(`=== ${target} ===\n` + targetArticles.map(a => `• ${a.title}${a.desc ? ': ' + a.desc : ''}`).join('\n'));
    }
  }

  const existingRows  = db.prepare("SELECT data FROM research WHERE module='company'").all().map(r => JSON.parse(r.data));
  const existingNames = new Set(existingRows.map(i => (i.company||'').toLowerCase().trim()));
  const existingList  = [...existingNames].slice(0, 30).join(', ') || 'none';
  const newsContext   = newsBlocks.length ? `RECENT NEWS ARTICLES:\n${newsBlocks.join('\n\n')}\n\n` : '';

  const today = new Date().toISOString().slice(0, 10);
  const targetList = targetCompanies.join(', ');

  const prompt = `${newsContext}You are an expert B2B sales intelligence analyst for Redhawk Federal Solutions, a US-based consulting firm specializing in ERP implementations (${erpSystems.join(', ')}), business transformation, digital experience, cybersecurity, and applied AI consulting.

We have a specific list of target companies and/or contact names we want researched in depth: ${targetList}

For EACH target on this list, provide a detailed opportunity assessment. Research everything you know about them — their technology stack, recent news, leadership, business challenges, growth signals, and how Redhawk's services could help. If a target is a person's name, find what company they are at and research that company and their specific role.

GEOGRAPHY: Note whether the company is US-headquartered ("US") or international (country name).

Companies already in our company research pipeline (skip duplicates): ${existingList}

LOOK FOR ALL OF THESE SIGNAL CATEGORIES — do not limit yourself to ERP replacement only:

ERP & SYSTEMS: ERP evaluation, replacement, upgrade, or implementation. Government contractors needing Deltek. Digital transformation programs.

AI & AGENTIC AI (HIGH PRIORITY): Is this company publicly discussing AI strategy, agentic AI, AI automation, or AI adoption? Are they hiring for AI/ML roles? Has leadership been quoted about AI challenges or needs? Redhawk offers applied AI consulting — this is a top-priority signal.

MULTI-ERP / ERP OPTIMIZATION: Is this company running multiple ERP systems (common after M&A)? Are they trying to consolidate, integrate, or optimize existing ERPs without replacing them? Is there evidence of ERP shelfware or misaligned processes?

BUSINESS PROCESS ANALYSIS & IMPROVEMENT: Has the company announced a process improvement initiative, operational efficiency program, or brought in a consulting firm? Do they have rapid growth or post-merger integration that would strain existing processes?

STRUGGLING / FAILED PROJECTS (HIGHEST PRIORITY — they need a rescue): Is there any public evidence this company has a failed, over-budget, or behind-schedule ERP or transformation project? Did they fire their previous consulting firm or SI partner? Have executives publicly expressed frustration about a project? Audit findings? Board complaints? These represent the most urgent and immediate sales opportunities.

LINKEDIN SIGNALS: Have executives at this company posted publicly about technology challenges, AI needs, project struggles, or digital transformation? Are their job postings signaling active investment in any of these areas?

SCORING RULES — be strict even for named targets:
- 8–10 (Hot): Specific, concrete evidence of an active project, announced initiative, open roles confirming investment, known pain point from public statements, compliance deadline, M&A activity, or — especially — a struggling/failed project that needs rescue.
- 6–7 (Warm): Strong circumstantial fit — relevant sector, growth signals, leadership changes, AI/process signals — but no confirmed active project found.
- 1–5 (Cool): General background only, no meaningful opportunity signal found in research.

Return ONLY a JSON array, no other text. Each item must have exactly these fields.
For "signals": 2–5 short specific tags (3–6 words each) explaining WHY this company is flagged — e.g. "SAP ECC End-of-Support", "Failed ERP Rollback", "Active AI Transformation", "M&A System Consolidation", "CIO Quoted on Pain", "LinkedIn Hiring Confirms Project", "ERP Over Budget & Late". Avoid vague tags like "ERP Need" or "Digital Transformation".
[{
  "contactName": "Jane Doe or TBD - CIO",
  "company": "Acme Corp",
  "title": "VP of IT",
  "sector": "Commercial",
  "industry": "Aerospace & Defense",
  "geography": "US",
  "currentPlatform": "SAP ECC or Legacy/Unknown",
  "recommendedServiceLine": "Business Transformation",
  "opportunityScore": 8,
  "signals": ["SAP ECC End-of-Support", "3 ERP Roles on LinkedIn", "CIO Quoted on Pain"],
  "primarySignal": "One sentence — the single strongest signal found for this specific company",
  "urgencyIndicators": "Signal A, Signal B",
  "painPoints": "REQUIRED: Detailed, evidence-based description of the specific opportunity. This is the most important field. Cite actual news, public statements, job postings, contract announcements, earnings call quotes, LinkedIn posts, or known industry facts that prove there is a real need Redhawk can address. Be specific — name the project, quote the exec, cite the job posting count, reference the contract. Example: 'Acme Corp announced in their March 2026 press release a $45M digital transformation program targeting supply chain and ERP modernization. CEO quoted saying current SAP system cannot support planned 40% headcount growth. Currently posting 6 ERP Business Analyst roles on LinkedIn. IFS is a named evaluation candidate per industry sources.' If research reveals no concrete opportunity, state what IS known and score 5 or below.",
  "notes": "3-4 sentences on Redhawk's best approach — which service line to lead with, what angle to take, and any relationship or competitive considerations.",
  "linkedInUrl": "",
  "source": "${today} - Company Research"
}]

opportunityScore is 1–10 (integer). Be thorough — these are specifically targeted companies we care about, so provide the most detailed, evidence-based assessment you can for each one.`;

  console.log(`[company] Calling Anthropic API for ${targetCompanies.length} targets…`);
  let response;
  try {
    response = await callAnthropicAPI(apiKey, [{ role: 'user', content: prompt }], 8192);
  } catch(e) {
    console.error('[company] API call failed:', e.message);
    return { added: 0, error: e.message };
  }

  if (!response || !response.content || !response.content[0]) {
    const err = (response && response.error && response.error.message) || 'Empty response';
    console.error('[company] Bad API response:', err);
    return { added: 0, error: err };
  }

  if (response.usage) {
    const cost = logUsage(response.usage.input_tokens||0, response.usage.output_tokens||0, 'company_research');
    console.log(`[company] Tokens: ${response.usage.input_tokens} in / ${response.usage.output_tokens} out — cost $${cost.toFixed(4)}`);
  }

  const text  = response.content[0].text || '';
  const match = text.match(/\[[\s\S]*\]/);
  if (!match) { console.error('[company] No JSON array in response'); return { added: 0, error: 'No JSON returned' }; }

  let items;
  try { items = JSON.parse(match[0]); } catch { return { added: 0, error: 'JSON parse error' }; }
  if (!Array.isArray(items)) return { added: 0, error: 'Response was not an array' };

  // Apollo enrichment
  const apolloKey = (settings.apolloApiKey || '').trim();
  let apolloHits = 0;
  if (apolloKey) {
    console.log(`[company] Enriching ${items.length} items via Apollo.io…`);
    for (let i = 0; i < items.length; i++) {
      const contact = await searchApolloContact(apolloKey, items[i].company, items[i].title);
      if (contact) {
        items[i] = { ...items[i], ...contact };
        apolloHits++;
        console.log(`[company] Apollo ✓ ${contact.contactName} @ ${items[i].company}`);
      }
      await new Promise(r => setTimeout(r, 350));
    }
    console.log(`[company] Apollo enrichment: ${apolloHits}/${items.length} contacts found`);
  }

  const ins = db.prepare("INSERT OR IGNORE INTO research (id, module, data) VALUES (?, 'company', ?)");
  let added = 0;
  txn(() => {
    for (const item of items) {
      if (!item.company || existingNames.has((item.company||'').toLowerCase().trim())) continue;
      const id = `company-ai-${Date.now()}-${Math.random().toString(36).slice(2,7)}`;
      const full = {
        id, status: 'New', promotedLeadId: null, owner: 'Blair', assignedTo: 'Blair',
        ...item,
        opportunityScore: Math.min(10, Math.max(1, Math.round(Number(item.opportunityScore)||5))),
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      ins.run(id, JSON.stringify(full));
      existingNames.add(item.company.toLowerCase().trim());
      added++;
    }
  });

  const s = getSettings();
  s.lastCompanyResearchAt = new Date().toISOString();
  saveSettings(s);
  console.log(`[company] Done — added ${added} of ${items.length} items (${apolloHits} Apollo contacts)`);
  return { added, total: items.length, apolloHits };
}

// Schedule company research at 3:00 AM
function scheduleNightlyCompanyResearch() {
  const now  = new Date();
  const next = new Date(now);
  next.setHours(3, 0, 0, 0);
  if (now >= next) next.setDate(next.getDate() + 1);
  const ms  = next - now;
  const hrs = (ms / 36e5).toFixed(1);
  console.log(`  Next company research: ${next.toLocaleString('en-US')} (in ${hrs}h)`);
  setTimeout(async () => {
    console.log('[company] Running nightly company research job…');
    await runNightlyCompanyResearch();
    scheduleNightlyCompanyResearch();
  }, ms);
}
scheduleNightlyCompanyResearch();

R('POST', '/api/run-erp-research', async (req, res) => {
  if (!requireAuth(req, res)) return;
  console.log('[research] Manual ERP research triggered…');
  const result = await runNightlyERPResearch();
  jsonRes(res, 200, { ok: true, ...result });
});

R('POST', '/api/run-contacts-research', async (req, res) => {
  if (!requireAuth(req, res)) return;
  console.log('[contacts] Manual contacts research triggered…');
  const result = await runNightlyContactsResearch();
  jsonRes(res, 200, { ok: true, ...result });
});

R('POST', '/api/run-company-research', async (req, res) => {
  if (!requireAuth(req, res)) return;
  console.log('[company] Manual company research triggered…');
  const result = await runNightlyCompanyResearch();
  jsonRes(res, 200, { ok: true, ...result });
});

// ── Bids/RFQs persistence ──────────────────────────────────────────────────────
R('GET', '/api/bids', (req, res) => {
  if (!requireAuth(req, res)) return;
  const rows = db.prepare("SELECT data FROM research WHERE module='bids'").all();
  jsonRes(res, 200, {ok:true, items: rows.length ? rows.map(r=>JSON.parse(r.data)) : null});
});
R('POST', '/api/bids', async (req, res) => {
  if (!requireAuth(req, res)) return;
  const {items} = await parseBody(req);
  if (!Array.isArray(items)) return jsonRes(res, 400, {ok:false, error:'items must be an array'});
  const del = db.prepare("DELETE FROM research WHERE module='bids'");
  const ins = db.prepare("INSERT INTO research (id, module, data) VALUES (?, 'bids', ?)");
  txn(() => { del.run(); items.forEach(r => ins.run(r.id, JSON.stringify(r))); });
  jsonRes(res, 200, {ok:true});
});

// ── Events persistence ─────────────────────────────────────────────────────────
R('GET', '/api/events', (req, res) => {
  if (!requireAuth(req, res)) return;
  const rows = db.prepare("SELECT data FROM research WHERE module='events'").all();
  jsonRes(res, 200, {ok:true, items: rows.length ? rows.map(r=>JSON.parse(r.data)) : null});
});
R('POST', '/api/events', async (req, res) => {
  if (!requireAuth(req, res)) return;
  const {items} = await parseBody(req);
  if (!Array.isArray(items)) return jsonRes(res, 400, {ok:false, error:'items must be an array'});
  const del = db.prepare("DELETE FROM research WHERE module='events'");
  const ins = db.prepare("INSERT INTO research (id, module, data) VALUES (?, 'events', ?)");
  txn(() => { del.run(); items.forEach(r => ins.run(r.id, JSON.stringify(r))); });
  jsonRes(res, 200, {ok:true});
});

// ── Contact Lookup ─────────────────────────────────────────────────────────────
R('POST', '/api/contact-lookup', async (req, res) => {
  if (!requireAuth(req, res)) return;
  const {name, context} = await parseBody(req);
  if (!name || !name.trim()) return jsonRes(res, 400, {ok:false, error:'name is required'});
  const s = getSettings();
  const apiKey = (s.anthropicApiKey||'').trim();
  if (!apiKey) return jsonRes(res, 400, {ok:false, error:'Anthropic API key not configured. Add it in Maintenance → Research AI.'});

  let apolloResults = null;
  const apolloKey = (s.apolloApiKey||'').trim();
  if (apolloKey) {
    const orgHint = context ? context.match(/(?:at|from|with|@)\s+([A-Z][A-Za-z\s&]+?)(?:\.|,|$)/)?.[1]?.trim() : null;
    apolloResults = await searchApolloByName(apolloKey, name.trim(), orgHint);
  }

  const apolloSection = apolloResults
    ? `Apollo.io found these records:\n${apolloResults.map(p=>`- ${p.contactName} | ${p.title} | ${p.company} | ${p.email||'email unknown'} | ${p.phone||'phone unknown'} | ${p.linkedInUrl||'LinkedIn unknown'}`).join('\n')}\n\n`
    : '';

  const prompt = `${apolloSection}You are a business intelligence researcher. Find current contact information for this person.

Person: ${name.trim()}
Additional context: ${context||'none provided'}

Using the Apollo data above (if any) and your own knowledge, provide the best available contact information. Be honest about confidence — mark estimated/inferred data clearly.

Return ONLY a JSON array of matching people (usually 1, occasionally 2-3 if name is ambiguous):
[{
  "name": "Full Name",
  "title": "Current job title",
  "company": "Current company/organization",
  "email": "email or null",
  "emailNote": "verified|estimated from domain|unknown",
  "phone": "phone or null",
  "phoneNote": "verified|public|unknown",
  "linkedInUrl": "full LinkedIn URL or null",
  "location": "City, State",
  "bio": "1-2 sentences on who this person is professionally",
  "confidence": "high|medium|low",
  "dataSource": "Apollo|AI Knowledge|Estimated"
}]

If you cannot find the person with reasonable confidence, return [].`;

  let response;
  try { response = await callAnthropicAPI(apiKey, [{role:'user', content:prompt}], 3000); }
  catch(e) { return jsonRes(res, 500, {ok:false, error:e.message}); }

  const text = response?.content?.[0]?.text || '';
  const match = text.match(/\[[\s\S]*\]/);
  if (!match) return jsonRes(res, 200, {ok:true, results:[]});
  try { const r = JSON.parse(match[0]); return jsonRes(res, 200, {ok:true, results: Array.isArray(r)?r:[]}); }
  catch { return jsonRes(res, 200, {ok:true, results:[]}); }
});

// ── Wildcard Search ────────────────────────────────────────────────────────────
R('POST', '/api/wildcard-search', async (req, res) => {
  if (!requireAuth(req, res)) return;
  const {query} = await parseBody(req);
  if (!query || !query.trim()) return jsonRes(res, 400, {ok:false, error:'query is required'});
  const s = getSettings();
  const apiKey = (s.anthropicApiKey||'').trim();
  if (!apiKey) return jsonRes(res, 400, {ok:false, error:'Anthropic API key not configured. Add it in Maintenance → Research AI.'});

  let apolloResults = null;
  const apolloKey = (s.apolloApiKey||'').trim();
  if (apolloKey) {
    const orgMatch = query.match(/(?:at|for|from|with)\s+([A-Z][A-Za-z0-9\s&]+?)(?:\s|$)/);
    const orgHint = orgMatch ? orgMatch[1].trim() : null;
    if (orgHint) apolloResults = await searchApolloByName(apolloKey, '', orgHint);
  }

  const apolloSection = apolloResults
    ? `Apollo.io returned these contacts which may be relevant:\n${apolloResults.map(p=>`- ${p.contactName} | ${p.title} | ${p.company} | ${p.email||'no email'} | ${p.linkedInUrl||'no LinkedIn'}`).join('\n')}\n\n`
    : '';

  const prompt = `${apolloSection}You are a business intelligence researcher. Answer this search query by finding the specific people who match:

Query: "${query.trim()}"

Find the real people (by name and title) who match this description. Use the Apollo data above if relevant, plus your own knowledge.

Return ONLY a JSON array of matching people:
[{
  "name": "Full Name",
  "title": "Current job title",
  "company": "Current company/organization",
  "email": "email or null",
  "emailNote": "verified|estimated from domain|unknown",
  "phone": "phone or null",
  "phoneNote": "verified|public|unknown",
  "linkedInUrl": "full LinkedIn URL or null",
  "location": "City, State",
  "bio": "1-2 sentences on who this person is and why they match the query",
  "confidence": "high|medium|low",
  "dataSource": "Apollo|AI Knowledge|Estimated"
}]

Return up to 5 people. If you cannot find anyone with reasonable confidence, return [].`;

  let response;
  try { response = await callAnthropicAPI(apiKey, [{role:'user', content:prompt}], 3000); }
  catch(e) { return jsonRes(res, 500, {ok:false, error:e.message}); }

  const text = response?.content?.[0]?.text || '';
  const match = text.match(/\[[\s\S]*\]/);
  if (!match) return jsonRes(res, 200, {ok:true, results:[]});
  try { const r = JSON.parse(match[0]); return jsonRes(res, 200, {ok:true, results: Array.isArray(r)?r:[]}); }
  catch { return jsonRes(res, 200, {ok:true, results:[]}); }
});

// ── Search Bids/RFQs ───────────────────────────────────────────────────────────
R('POST', '/api/search-bids', async (req, res) => {
  if (!requireAuth(req, res)) return;
  const s = getSettings();
  const apiKey = (s.anthropicApiKey||'').trim();
  if (!apiKey) return jsonRes(res, 400, {ok:false, error:'Anthropic API key not configured.'});

  const erpSystems = s.erpSystems || ['IFS','Microsoft D365','SAP','Infor','Deltek'];
  const today = new Date().toISOString().slice(0,10);

  const newsBlocks = [];
  const bidTerms = [
    'government RFP IT modernization digital transformation open solicitation 2026',
    'federal agency ERP RFQ open bid solicitation due 2026',
    'cybersecurity RFP government contract open solicitation',
    'SAM.gov IT services contract solicitation open',
  ];
  for (const term of bidTerms) {
    const articles = await fetchNewsRSS(term);
    if (articles.length) newsBlocks.push(articles.map(a=>`• ${a.title}: ${a.desc}`).join('\n'));
    await new Promise(r=>setTimeout(r,500));
  }

  const newsSection = newsBlocks.length ? `RECENT PROCUREMENT NEWS:\n${newsBlocks.join('\n')}\n\n` : '';

  const prompt = `${newsSection}You are a government contracts intelligence analyst for Redhawk Federal Solutions, a US consulting firm specializing in: ERP implementations (${erpSystems.join(', ')}), Business Transformation, Digital Experience, Cybersecurity/Zero-Trust, and Applied AI & Data.

Today is ${today}. Identify ONLY currently OPEN and ACTIVE bids, RFPs, RFQs, and contract solicitations that Redhawk could respond to. Focus on:
- Federal civilian agencies (DoD, DHS, VA, HHS, etc.) seeking IT modernization, ERP, digital transformation, or cybersecurity services
- State and local government technology contracts
- Large enterprise opportunities in Redhawk's target industries
- Subcontracting opportunities with prime government contractors

Use the news above AND your knowledge of recent procurement activity. Only include real, verifiable opportunities you are confident exist.

CRITICAL RULES — READ CAREFULLY:
- ONLY include bids/RFPs/RFQs that are CURRENTLY OPEN for responses as of ${today}. The solicitation must still be accepting submissions.
- EXCLUDE anything that is already closed, awarded, cancelled, or past its due date. If the due date is before ${today}, do NOT include it.
- EXCLUDE contract award announcements — those are already decided. Only include open solicitations seeking proposals or quotes.
- EXCLUDE pre-solicitation notices unless they explicitly state responses are currently being accepted.
- If you are not certain a solicitation is still open as of ${today}, do not include it.
- Do NOT cap the number of results. Output EVERY currently open, qualifying bid/RFP/RFQ you can identify with HIGH confidence.
- Cover all relevant categories: federal civilian, DoD, state/local, enterprise, subcontracting.

Return ONLY a JSON array:
[{
  "id": "bid-${today}-1",
  "bidName": "Full solicitation title",
  "bidNumber": "Solicitation/contract number or null",
  "organization": "Issuing agency or company",
  "description": "2-3 sentence description of what is being sought and why Redhawk fits",
  "serviceMatch": "Which Redhawk service line (ERP/Business Transformation/Cybersecurity/Digital Experience/Applied AI)",
  "contactAuthority": "Contracting officer name or null",
  "contactEmail": "Contracting officer email or null",
  "contactPhone": "Phone or null",
  "dueDate": "YYYY-MM-DD or null — must be on or after ${today}",
  "estimatedValue": "Dollar value/range or null",
  "url": "Direct URL to bid posting or null",
  "status": "New",
  "confidence": "high|medium",
  "source": "SAM.gov|News|AI Research",
  "foundAt": "${today}"
}]

Confidence rules:
- "high": You are very confident this solicitation is real, currently open, and the details are accurate.
- "medium": You are reasonably confident it is open and active, but some details may be approximate.
- Never include "low" confidence results — exclude any opportunity you are not at least reasonably confident is open right now.`;

  let response;
  try { response = await callAnthropicAPI(apiKey, [{role:'user', content:prompt}], 16000); }
  catch(e) { return jsonRes(res, 500, {ok:false, error:e.message}); }

  const text = response?.content?.[0]?.text || '';
  const match = text.match(/\[[\s\S]*\]/);
  if (!match) return jsonRes(res, 200, {ok:true, added:0, items:[]});

  let items = [];
  try { items = JSON.parse(match[0]); if (!Array.isArray(items)) items = []; } catch { items = []; }

  const dismissedBidKeys = new Set(getSettings().dismissedBidKeys || []);
  const bidKey = item => `${(item.bidName||'').toLowerCase().trim()}|${(item.organization||'').toLowerCase().trim()}`;
  const filteredItems = items.filter(item => !dismissedBidKeys.has(bidKey(item)));

  const del = db.prepare("DELETE FROM research WHERE module='bids'");
  const ins = db.prepare("INSERT INTO research (id, module, data) VALUES (?, 'bids', ?)");
  const saved = filteredItems.map((item,i) => ({...item, id:`bid-${Date.now()}-${i}`, status:'New'}));
  txn(() => { del.run(); saved.forEach(r => ins.run(r.id, JSON.stringify(r))); });

  const ss = getSettings(); ss.lastBidsSearchAt = new Date().toISOString(); saveSettings(ss);
  jsonRes(res, 200, {ok:true, added:saved.length, items:saved});
});

// ── Search Events/Conferences ──────────────────────────────────────────────────
R('POST', '/api/search-events', async (req, res) => {
  if (!requireAuth(req, res)) return;
  const s = getSettings();
  const apiKey = (s.anthropicApiKey||'').trim();
  if (!apiKey) return jsonRes(res, 400, {ok:false, error:'Anthropic API key not configured.'});

  const erpSystems = s.erpSystems || ['IFS','Microsoft D365','SAP','Infor','Deltek'];
  const today = new Date().toISOString().slice(0,10);

  const newsBlocks = [];
  for (const erp of erpSystems) {
    const articles = await fetchNewsRSS(`"${erp}" conference user group event 2026`);
    if (articles.length) newsBlocks.push(`=== ${erp} ===\n` + articles.map(a=>`• ${a.title}: ${a.desc}`).join('\n'));
    await new Promise(r=>setTimeout(r,500));
  }

  const newsSection = newsBlocks.length ? `RECENT EVENT NEWS:\n${newsBlocks.join('\n\n')}\n\n` : '';
  const prompt = `${newsSection}You are a conference and event intelligence researcher for Redhawk Federal Solutions, an ERP consulting firm focused on ${erpSystems.join(', ')}.

Today is ${today}. Find upcoming ERP vendor conferences, user group meetings, and major industry events for the next 12 months that would be valuable for Redhawk to attend or sponsor. For each ERP vendor on our list, find their major annual conference or user group event.

Also include major general IT/digital transformation conferences where Redhawk's target buyers (CIOs, CTOs, IT directors) attend.

Return ONLY a JSON array:
[{
  "id": "evt-${today}-1",
  "vendor": "ERP vendor name or 'Industry'",
  "eventName": "Official event name",
  "description": "2-3 sentence overview of what the event covers and why Redhawk should attend",
  "eventDate": "YYYY-MM-DD or date range like '2026-09-15 to 2026-09-17'",
  "location": "City, State or 'Virtual'",
  "costToAttend": "Dollar amount or range or 'Free' or 'Unknown'",
  "url": "Registration or event homepage URL or null",
  "registrationCloseDate": "YYYY-MM-DD or null",
  "status": "New",
  "confidence": "high|medium|low",
  "source": "Vendor website|News|AI Research",
  "foundAt": "${today}"
}]

IMPORTANT RULES:
- Do NOT cap the number of results. Output EVERY active, upcoming event you can identify with HIGH confidence.
- Only include events where you have HIGH confidence the event is real, confirmed, and accurately described (correct name, date, location, URL). Do not include anything speculative or uncertain.
- Each event must be upcoming (event date after ${today}) and still open for registration or attendance planning.
- Cover all relevant categories: ERP vendor conferences, user group events, major industry/IT conferences, government IT events — include every real event found.
- If you know of 40 high-confidence events, return all 40. Quality and completeness both matter — do not artificially limit.

Return ONLY a JSON array:
[{
  "id": "evt-${today}-1",
  "vendor": "ERP vendor name or 'Industry'",
  "eventName": "Official event name",
  "description": "2-3 sentence overview of what the event covers and why Redhawk should attend",
  "eventDate": "YYYY-MM-DD or date range like '2026-09-15 to 2026-09-17'",
  "location": "City, State or 'Virtual'",
  "costToAttend": "Dollar amount or range or 'Free' or 'Unknown'",
  "url": "Registration or event homepage URL or null",
  "registrationCloseDate": "YYYY-MM-DD or null",
  "status": "New",
  "confidence": "high|medium",
  "source": "Vendor website|News|AI Research",
  "foundAt": "${today}"
}]

Confidence rules:
- "high": You are very confident this event is real, confirmed, and the details (name, date, location, URL) are accurate.
- "medium": You are reasonably confident it exists and is upcoming, but some details may be approximate.
- Never include "low" confidence results — exclude any event you are not at least reasonably confident about.`;

  let response;
  try { response = await callAnthropicAPI(apiKey, [{role:'user', content:prompt}], 16000); }
  catch(e) { return jsonRes(res, 500, {ok:false, error:e.message}); }

  const text = response?.content?.[0]?.text || '';
  const match = text.match(/\[[\s\S]*\]/);
  if (!match) return jsonRes(res, 200, {ok:true, added:0, items:[]});

  let items = [];
  try { items = JSON.parse(match[0]); if (!Array.isArray(items)) items = []; } catch { items = []; }

  const dismissedEventKeys = new Set(getSettings().dismissedEventKeys || []);
  const evtKey = item => `${(item.eventName||'').toLowerCase().trim()}|${(item.vendor||'').toLowerCase().trim()}`;
  const filteredEvts = items.filter(item => !dismissedEventKeys.has(evtKey(item)));

  const del = db.prepare("DELETE FROM research WHERE module='events'");
  const ins = db.prepare("INSERT INTO research (id, module, data) VALUES (?, 'events', ?)");
  const saved = filteredEvts.map((item,i) => ({...item, id:`evt-${Date.now()}-${i}`, status:'New'}));
  txn(() => { del.run(); saved.forEach(r => ins.run(r.id, JSON.stringify(r))); });

  const ss = getSettings(); ss.lastEventsSearchAt = new Date().toISOString(); saveSettings(ss);
  jsonRes(res, 200, {ok:true, added:saved.length, items:saved});
});

// ── Dismiss Bid ────────────────────────────────────────────────────────────────
R('POST', '/api/dismiss-bid', (req, res) => {
  if (!requireAuth(req, res)) return;
  const {bidName, organization, undo} = req.body || {};
  if (!bidName) return jsonRes(res, 400, {ok:false, error:'bidName required'});
  const key = `${(bidName||'').toLowerCase().trim()}|${(organization||'').toLowerCase().trim()}`;
  const ss = getSettings();
  const set = new Set(ss.dismissedBidKeys || []);
  if (undo) { set.delete(key); } else { set.add(key); }
  ss.dismissedBidKeys = [...set];
  saveSettings(ss);
  // Also update the record in the DB so it survives without a re-search
  const rows = db.prepare("SELECT id, data FROM research WHERE module='bids'").all();
  for (const row of rows) {
    try {
      const d = JSON.parse(row.data);
      const rkey = `${(d.bidName||'').toLowerCase().trim()}|${(d.organization||'').toLowerCase().trim()}`;
      if (rkey === key) {
        d.dismissed = !undo;
        db.prepare("UPDATE research SET data=? WHERE id=?").run(JSON.stringify(d), row.id);
      }
    } catch {}
  }
  jsonRes(res, 200, {ok:true, undo:!!undo});
});

// ── Dismiss Event ──────────────────────────────────────────────────────────────
R('POST', '/api/dismiss-event', (req, res) => {
  if (!requireAuth(req, res)) return;
  const {eventName, vendor, undo} = req.body || {};
  if (!eventName) return jsonRes(res, 400, {ok:false, error:'eventName required'});
  const key = `${(eventName||'').toLowerCase().trim()}|${(vendor||'').toLowerCase().trim()}`;
  const ss = getSettings();
  const set = new Set(ss.dismissedEventKeys || []);
  if (undo) { set.delete(key); } else { set.add(key); }
  ss.dismissedEventKeys = [...set];
  saveSettings(ss);
  const rows = db.prepare("SELECT id, data FROM research WHERE module='events'").all();
  for (const row of rows) {
    try {
      const d = JSON.parse(row.data);
      const rkey = `${(d.eventName||'').toLowerCase().trim()}|${(d.vendor||'').toLowerCase().trim()}`;
      if (rkey === key) {
        d.dismissed = !undo;
        db.prepare("UPDATE research SET data=? WHERE id=?").run(JSON.stringify(d), row.id);
      }
    } catch {}
  }
  jsonRes(res, 200, {ok:true, undo:!!undo});
});

// ── Manual export endpoint ─────────────────────────────────────────────────────
R('POST', '/api/export-leads', (req, res) => {
  if (!requireAuth(req, res)) return;
  const settings = getSettings();
  const since    = settings.lastExportedAt || '1970-01-01T00:00:00.000Z';
  const all      = db.prepare('SELECT data FROM leads').all().map(r => JSON.parse(r.data));
  const changed  = all.filter(l => (l.updatedAt||l.createdAt||'') > since);
  if (!changed.length) { res.writeHead(204, {'Access-Control-Allow-Origin':'*'}); res.end(); return; }
  // Update timestamp before responding
  settings.lastExportedAt = new Date().toISOString();
  saveSettings(settings);
  const dateStr = new Date().toISOString().slice(0,10);
  res.writeHead(200, {
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': `attachment; filename="pipedrive-export-${dateStr}.csv"`,
    'Access-Control-Allow-Origin': '*',
  });
  res.end(toCsv(changed));
  console.log(`[export] Manual export: ${changed.length} leads`);
});

// ── Static files ───────────────────────────────────────────────────────────────
const MIME = {'.html':'text/html','.js':'application/javascript','.css':'text/css','.json':'application/json','.ico':'image/x-icon'};
const serveFile = (res, fp) => fs.readFile(fp, (err, data) => {
  if (err) { res.writeHead(404); res.end('Not found'); return; }
  res.writeHead(200, {'Content-Type':(MIME[path.extname(fp)]||'text/plain')+'; charset=utf-8','Cache-Control':'no-cache'});
  res.end(data);
});

// ── HTTP server ────────────────────────────────────────────────────────────────
http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];
  const key = `${req.method} ${url}`;

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST,DELETE','Access-Control-Allow-Headers':'Content-Type,x-session-token'});
    res.end(); return;
  }

  if (routes[key]) {
    try { await routes[key](req, res); } catch(e) { console.error(e); jsonRes(res, 500, {ok:false, error:'Server error'}); }
    return;
  }

  const safe = url.replace(/\.\./g, '').replace(/^\//, '');
  serveFile(res, path.join(__dirname, safe || 'leads.html'));
}).listen(PORT, () => {
  const users    = db.prepare('SELECT COUNT(*) as n FROM users').get().n;
  const sessions = db.prepare('SELECT COUNT(*) as n FROM sessions WHERE expires_at>?').get(Date.now()).n;
  const leads    = db.prepare('SELECT COUNT(*) as n FROM leads').get().n;
  const research = db.prepare('SELECT COUNT(*) as n FROM research').get().n;
  console.log('─────────────────────────────────────────');
  console.log(`  LeadFlow  →  http://localhost:${PORT}`);
  console.log(`  Database : leadflow.db  (SQLite, WAL mode)`);
  console.log(`  Records  : ${leads} leads · ${research} research items`);
  if (users === 0) console.log('  First run: create admin account at the login screen.');
  else console.log(`  Auth     : ${users} users · ${sessions} active sessions`);
  console.log('─────────────────────────────────────────\n');
});
