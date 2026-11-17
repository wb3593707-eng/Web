require('dotenv').config();
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const { OAuth2Client } = require('google-auth-library');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || '';
const GOOGLE_ID = process.env.GOOGLE_CLIENT_ID || '';
const isProd = process.env.NODE_ENV === 'production';
if (SECRET.length < 32) {
  console.error('Defina JWT_SECRET (mín. 32 caracteres) no arquivo .env. Veja .env.example.');
  process.exit(1);
}

const db = new Database(path.join(__dirname, 'data.db'));
db.exec(`CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT,
  google_sub TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)`);
const byEmail = db.prepare('SELECT * FROM users WHERE email = ?');
const insert = db.prepare('INSERT INTO users(email,password_hash,google_sub) VALUES (?,?,?)');
const setSub = db.prepare('UPDATE users SET google_sub = ? WHERE id = ?');

const googleClient = GOOGLE_ID ? new OAuth2Client(GOOGLE_ID) : null;
const DUMMY_HASH = bcrypt.hashSync('dummy-password', 12); // evita diferença de tempo quando o e-mail não existe

const app = express();
app.set('trust proxy', 1);
app.use(helmet({
  crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' }, // necessário para o login Google
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      'script-src': ["'self'", "'unsafe-inline'", 'https://accounts.google.com'],
      'style-src': ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://accounts.google.com'],
      'font-src': ["'self'", 'https://fonts.gstatic.com'],
      'img-src': ["'self'", 'data:', 'https://api.qrserver.com', 'https://*.googleusercontent.com'],
      'frame-src': ['https://accounts.google.com'],
      'connect-src': ["'self'", 'https://accounts.google.com'],
      'upgrade-insecure-requests': isProd ? [] : null,
    },
  },
}));
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Muitas tentativas. Aguarde alguns minutos.' } });

const cleanEmail = v => (typeof v === 'string' ? v.trim().toLowerCase() : '');
const validEmail = e => e.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);

function startSession(res, user) {
  const token = jwt.sign({ sub: user.id, email: user.email }, SECRET, { expiresIn: '7d' });
  res.cookie('ff_session', token, { httpOnly: true, sameSite: 'lax', secure: isProd, maxAge: 7 * 24 * 3600 * 1000 });
}
function readSession(req) {
  try { return jwt.verify(req.cookies.ff_session, SECRET); } catch { return null; }
}

app.get('/api/config', (_req, res) => res.json({ googleClientId: GOOGLE_ID }));

app.get('/api/me', (req, res) => {
  const s = readSession(req);
  res.json(s ? { email: s.email } : {});
});

app.post('/api/register', authLimiter, async (req, res) => {
  const email = cleanEmail(req.body.email), password = req.body.password;
  if (!validEmail(email)) return res.status(400).json({ error: 'Digite um e-mail válido.' });
  if (typeof password !== 'string' || password.length < 8 || password.length > 72)
    return res.status(400).json({ error: 'A senha deve ter de 8 a 72 caracteres.' });
  if (byEmail.get(email)) return res.status(409).json({ error: 'Este e-mail já tem conta. Use "Entrar".' });
  const hash = await bcrypt.hash(password, 12);
  const info = insert.run(email, hash, null);
  startSession(res, { id: info.lastInsertRowid, email });
  res.json({ email });
});

app.post('/api/login', authLimiter, async (req, res) => {
  const email = cleanEmail(req.body.email), password = req.body.password;
  const user = validEmail(email) ? byEmail.get(email) : null;
  const ok = await bcrypt.compare(typeof password === 'string' ? password : '', user?.password_hash || DUMMY_HASH);
  if (!user || !user.password_hash || !ok) return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
  startSession(res, user);
  res.json({ email: user.email });
});

app.post('/api/google', authLimiter, async (req, res) => {
  if (!googleClient) return res.status(503).json({ error: 'Login Google não configurado no servidor.' });
  try {
    const ticket = await googleClient.verifyIdToken({ idToken: String(req.body.credential || ''), audience: GOOGLE_ID });
    const p = ticket.getPayload();
    if (!p || !p.email || !p.email_verified) return res.status(401).json({ error: 'E-mail do Google não verificado.' });
    const email = p.email.toLowerCase();
    let user = byEmail.get(email);
    if (!user) {
      const info = insert.run(email, null, p.sub);
      user = { id: info.lastInsertRowid, email };
    } else if (!user.google_sub) setSub.run(p.sub, user.id);
    startSession(res, user);
    res.json({ email, name: p.given_name || '' });
  } catch {
    res.status(401).json({ error: 'Não foi possível validar o login do Google.' });
  }
});

app.post('/api/logout', (_req, res) => { res.clearCookie('ff_session'); res.json({ ok: true }); });


// ================= LOJA: estoque, pedidos e pagamento Pix (Mercado Pago) =================
const PRICE_CENTS = 3000;                 // R$ 30,00
const RESERVE_MS = 30 * 60 * 1000;        // reserva da conta e validade do Pix: 30 min
const ENC = Buffer.from(process.env.ENC_KEY || '', 'hex');
if (ENC.length !== 32) { console.error('Defina ENC_KEY (64 caracteres hex) no .env. Veja .env.example.'); process.exit(1); }
if (!process.env.MP_ACCESS_TOKEN) console.warn('AVISO: MP_ACCESS_TOKEN não definido. Checkout ficará desativado.');
if ((process.env.ADMIN_KEY || '').length < 16) console.warn('AVISO: ADMIN_KEY ausente/curta. Painel admin desativado.');

db.exec(`
CREATE TABLE IF NOT EXISTS accounts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  login_enc TEXT NOT NULL, pass_enc TEXT NOT NULL, player_id TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'available',   -- available | reserved | sold
  order_id INTEGER, reserved_until INTEGER
);
CREATE TABLE IF NOT EXISTS orders(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL, account_id INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',     -- pending | paid | expired | failed | refund_needed
  amount INTEGER NOT NULL, mp_id TEXT, qr_code TEXT, qr_base64 TEXT, created_ms INTEGER NOT NULL
);`);

const enc = t => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', ENC, iv);
  const ct = Buffer.concat([c.update(t, 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), ct].map(b => b.toString('base64')).join('.'); };
const dec = s => { const [iv, tag, ct] = s.split('.').map(x => Buffer.from(x, 'base64'));
  const d = crypto.createDecipheriv('aes-256-gcm', ENC, iv); d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString('utf8'); };

const requireAuth = (req, res, next) => {
  const s = readSession(req);
  if (!s) return res.status(401).json({ error: 'Faça login para continuar.' });
  req.user = s; next();
};
const payLimiter = rateLimit({ windowMs: 60 * 1000, limit: 15, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Muitas solicitações. Aguarde um instante.' } });

async function mp(pathname, opts = {}) {
  const r = await fetch('https://api.mercadopago.com' + pathname, { ...opts, headers: {
    Authorization: 'Bearer ' + process.env.MP_ACCESS_TOKEN, 'Content-Type': 'application/json', ...(opts.headers || {}) } });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error('MercadoPago ' + r.status + ' ' + JSON.stringify(j).slice(0, 300));
  return j;
}

function releaseExpired() {
  const now = Date.now();
  db.prepare("UPDATE orders SET status='expired' WHERE status='pending' AND account_id IN (SELECT id FROM accounts WHERE status='reserved' AND reserved_until<?)").run(now);
  db.prepare("UPDATE accounts SET status='available',order_id=NULL,reserved_until=NULL WHERE status='reserved' AND reserved_until<?").run(now);
}
const getOrder = id => db.prepare('SELECT * FROM orders WHERE id=?').get(id);

// Confirma o pagamento CONSULTANDO o Mercado Pago (nunca confia no navegador nem no corpo do webhook).
async function verifyOrder(o) {
  if (!o || !o.mp_id || ['paid', 'refund_needed', 'failed'].includes(o.status)) return o;
  let p;
  try { p = await mp('/v1/payments/' + o.mp_id); } catch (e) { console.error(e.message); return o; }
  if (p.status === 'approved' && Number(p.transaction_amount) === o.amount / 100 && String(p.external_reference) === String(o.id)) {
    db.transaction(() => {
      let ch = db.prepare("UPDATE accounts SET status='sold' WHERE id=? AND order_id=?").run(o.account_id, o.id).changes;
      if (!ch) ch = db.prepare("UPDATE accounts SET status='sold',order_id=? WHERE id=? AND status='available'").run(o.id, o.account_id).changes;
      db.prepare('UPDATE orders SET status=? WHERE id=?').run(ch ? 'paid' : 'refund_needed', o.id); // refund_needed: pagou, mas a conta já saiu do estoque
    })();
  } else if (['cancelled', 'rejected', 'expired'].includes(p.status)) {
    db.transaction(() => {
      db.prepare("UPDATE accounts SET status='available',order_id=NULL,reserved_until=NULL WHERE id=? AND order_id=? AND status='reserved'").run(o.account_id, o.id);
      db.prepare("UPDATE orders SET status='expired' WHERE id=? AND status='pending'").run(o.id);
    })();
  }
  return getOrder(o.id);
}

const reserve = db.transaction(uid => {
  const a = db.prepare("SELECT id FROM accounts WHERE status='available' ORDER BY id LIMIT 1").get();
  if (!a) return null;
  const o = db.prepare("INSERT INTO orders(user_id,account_id,status,amount,created_ms) VALUES (?,?,'pending',?,?)").run(uid, a.id, PRICE_CENTS, Date.now());
  db.prepare("UPDATE accounts SET status='reserved',order_id=?,reserved_until=? WHERE id=?").run(o.lastInsertRowid, Date.now() + RESERVE_MS, a.id);
  return { orderId: Number(o.lastInsertRowid), accountId: a.id };
});
const pub = o => ({ orderId: o.id, status: o.status, qrCode: o.qr_code, qrBase64: o.qr_base64 });

app.get('/api/stock', (_req, res) => {
  releaseExpired();
  res.json({ available: db.prepare("SELECT COUNT(*) n FROM accounts WHERE status='available'").get().n, price: PRICE_CENTS / 100 });
});

app.post('/api/checkout', requireAuth, payLimiter, async (req, res) => {
  if (!process.env.MP_ACCESS_TOKEN) return res.status(503).json({ error: 'Pagamentos ainda não configurados.' });
  releaseExpired();
  let o = db.prepare("SELECT * FROM orders WHERE user_id=? AND status='pending' AND mp_id IS NOT NULL ORDER BY id DESC LIMIT 1").get(req.user.sub);
  if (o) { o = await verifyOrder(o); if (['pending', 'paid'].includes(o.status)) return res.json(pub(o)); }
  const made = reserve(req.user.sub);
  if (!made) return res.status(409).json({ error: 'Estoque esgotado no momento.' });
  try {
    const body = { transaction_amount: PRICE_CENTS / 100, description: 'Conta Free Fire', payment_method_id: 'pix',
      payer: { email: req.user.email }, external_reference: String(made.orderId),
      date_of_expiration: new Date(Date.now() + RESERVE_MS - 3 * 3600e3).toISOString().replace('Z', '-03:00') };
    if (process.env.PUBLIC_URL) body.notification_url = process.env.PUBLIC_URL.replace(/\/$/, '') + '/api/webhook/mp';
    const p = await mp('/v1/payments', { method: 'POST', headers: { 'X-Idempotency-Key': crypto.randomUUID() }, body: JSON.stringify(body) });
    const td = p.point_of_interaction?.transaction_data || {};
    if (!td.qr_code) throw new Error('Resposta sem QR Code');
    db.prepare('UPDATE orders SET mp_id=?,qr_code=?,qr_base64=? WHERE id=?').run(String(p.id), td.qr_code, td.qr_base64 || '', made.orderId);
    res.json(pub(getOrder(made.orderId)));
  } catch (e) {
    console.error(e.message);
    db.prepare("UPDATE orders SET status='failed' WHERE id=?").run(made.orderId);
    db.prepare("UPDATE accounts SET status='available',order_id=NULL,reserved_until=NULL WHERE id=?").run(made.accountId);
    res.status(502).json({ error: 'Não foi possível gerar o Pix. Tente novamente.' });
  }
});

app.get('/api/orders', requireAuth, (req, res) => {
  res.json(db.prepare('SELECT id,status,amount,created_ms FROM orders WHERE user_id=? ORDER BY id DESC LIMIT 50').all(req.user.sub));
});

app.get('/api/orders/:id', requireAuth, payLimiter, async (req, res) => {
  let o = db.prepare('SELECT * FROM orders WHERE id=? AND user_id=?').get(Number(req.params.id), req.user.sub);
  if (!o) return res.status(404).json({ error: 'Pedido não encontrado.' });
  o = await verifyOrder(o);
  const out = { id: o.id, status: o.status };
  if (o.status === 'paid') {
    const a = db.prepare('SELECT * FROM accounts WHERE id=?').get(o.account_id);
    out.account = { login: dec(a.login_enc), password: dec(a.pass_enc), playerId: a.player_id };
  }
  res.json(out);
});

app.post('/api/webhook/mp', (req, res) => {
  res.sendStatus(200);
  const id = String(req.body?.data?.id || req.query['data.id'] || '');
  const o = id && db.prepare('SELECT * FROM orders WHERE mp_id=?').get(id);
  if (o) verifyOrder(o).catch(() => {});
});

// ---- admin (chave no cabeçalho x-admin-key) ----
const adminOk = req => { const k = Buffer.from(String(req.get('x-admin-key') || '')), a = Buffer.from(process.env.ADMIN_KEY || '');
  return a.length >= 16 && k.length === a.length && crypto.timingSafeEqual(k, a); };
app.post('/api/admin/accounts', authLimiter, (req, res) => {
  if (!adminOk(req)) return res.status(401).json({ error: 'Chave inválida.' });
  const items = Array.isArray(req.body.items) ? req.body.items.slice(0, 500) : [];
  const ins = db.prepare('INSERT INTO accounts(login_enc,pass_enc,player_id) VALUES (?,?,?)');
  let added = 0;
  db.transaction(() => { for (const i of items) if (i && i.login && i.password) { ins.run(enc(String(i.login)), enc(String(i.password)), String(i.playerId || '')); added++; } })();
  res.json({ added });
});
app.get('/api/admin/summary', authLimiter, (req, res) => {
  if (!adminOk(req)) return res.status(401).json({ error: 'Chave inválida.' });
  releaseExpired();
  res.json({
    accounts: db.prepare('SELECT status, COUNT(*) n FROM accounts GROUP BY status').all(),
    orders: db.prepare('SELECT status, COUNT(*) n FROM orders GROUP BY status').all(),
    refundNeeded: db.prepare("SELECT o.id, o.mp_id, u.email FROM orders o JOIN users u ON u.id=o.user_id WHERE o.status='refund_needed'").all(),
  });
});
// ===========================================================================================

app.use(express.static(path.join(__dirname, 'public')));
app.listen(PORT, () => console.log(`Servidor em http://localhost:${PORT}`));
