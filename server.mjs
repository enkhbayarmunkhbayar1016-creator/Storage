// Inventory server with workers, photos, categories, low-stock alerts and a movement log.
// Zero dependencies. Needs Node 22.5+.  Run: node --experimental-sqlite server.mjs
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const dir = path.dirname(fileURLToPath(import.meta.url));
const UPLOADS = path.join(dir, 'uploads');
fs.mkdirSync(UPLOADS, { recursive: true });

const PORT = process.env.PORT || 3000;
const MAX_ITEMS = Number(process.env.MAX_ITEMS || 5000);
const MAX_PHOTO = 5 * 1024 * 1024;
const EXT = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/gif': 'gif' };
const db = new DatabaseSync(process.env.DB_FILE || path.join(dir, 'inventory.db'));

db.exec(`
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, hash TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('admin','worker')));
CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS categories (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS items (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL,
  category_id INTEGER REFERENCES categories(id),
  price REAL,                       -- NULL = no price / free
  stock REAL NOT NULL DEFAULT 0,
  unit TEXT NOT NULL DEFAULT 'ширхэг',
  low_threshold REAL NOT NULL DEFAULT 5,
  photo TEXT
);
CREATE TABLE IF NOT EXISTS movements (id INTEGER PRIMARY KEY, item_id INTEGER, item_name TEXT, user_id INTEGER, username TEXT, delta INTEGER NOT NULL, note TEXT, ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
`);

const hash = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
const send = (res, code, body) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
const readRaw = (req, limit) => new Promise((ok, fail) => {
  const chunks = []; let n = 0;
  req.on('data', (c) => { n += c.length; if (n > limit) { fail(new Error('too large')); req.destroy(); } else chunks.push(c); });
  req.on('end', () => ok(Buffer.concat(chunks)));
});
const readJson = async (req) => { const b = await readRaw(req, 1e6); try { return b.length ? JSON.parse(b) : {}; } catch { throw new Error('bad json'); } };
const getUser = (req) => db.prepare('SELECT u.id,u.username,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?').get((req.headers.authorization || '').replace('Bearer ', ''));

const itemView = (i) => ({ ...i, photo: i.photo ? `/uploads/${i.photo}` : null, status: i.stock === 0 ? 'out' : i.stock <= i.low_threshold ? 'low' : 'ok' });
const ITEM_SQL = 'SELECT i.*, c.name AS category FROM items i LEFT JOIN categories c ON c.id=i.category_id';
const UNITS = ['ширхэг', 'кг', 'метр'];
const qty = (n) => Math.round(n * 1000) / 1000;
const isQty = (n) => typeof n === 'number' && Number.isFinite(n) && n >= 0;
const validItem = (b) => b.name && isQty(b.stock) && (b.unit == null || UNITS.includes(b.unit)) && (b.price == null || (typeof b.price === 'number' && b.price >= 0)) && (b.lowThreshold == null || isQty(b.lowThreshold));
const logMove = (item, user, delta, note) => db.prepare('INSERT INTO movements (item_id,item_name,user_id,username,delta,note) VALUES (?,?,?,?,?,?)').run(item.id, item.name, user.id, user.username, delta, note || null);

// access: 'public' | 'user' (any logged-in) | 'admin'
const routes = [];
const route = (method, p, access, fn) => routes.push({ method, re: new RegExp(`^${p.replace(/:id/g, '(\\d+)')}$`), access, fn });

route('GET', '/api/status', 'public', (c) => send(c.res, 200, { needsSetup: db.prepare('SELECT COUNT(*) c FROM users').get().c === 0 }));

// First account becomes the super admin; afterwards only an admin can create users.
route('POST', '/api/register', 'public', async (c) => {
  if (db.prepare('SELECT COUNT(*) c FROM users').get().c > 0) return send(c.res, 403, { error: 'super admin already exists' });
  const b = await readJson(c.req);
  if (!b.username || !b.password || b.password.length < 8) return send(c.res, 400, { error: 'username and password (min 8 chars) required' });
  const salt = crypto.randomBytes(16).toString('hex');
  db.prepare("INSERT INTO users (username,salt,hash,role) VALUES (?,?,?,'admin')").run(b.username, salt, hash(b.password, salt));
  send(c.res, 201, { ok: true });
});
route('POST', '/api/login', 'public', async (c) => {
  const b = await readJson(c.req);
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(b.username || '');
  if (!u || hash(b.password || '', u.salt) !== u.hash) return send(c.res, 401, { error: 'invalid credentials' });
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions VALUES (?,?)').run(token, u.id);
  send(c.res, 200, { token, username: u.username, role: u.role });
});
route('GET', '/api/me', 'user', (c) => send(c.res, 200, c.user));

// Workers
route('GET', '/api/users', 'admin', (c) => send(c.res, 200, db.prepare('SELECT id,username,role FROM users ORDER BY username').all()));
route('POST', '/api/users', 'admin', async (c) => {
  const b = await readJson(c.req);
  if (!b.username || !b.password || b.password.length < 8) return send(c.res, 400, { error: 'username and password (min 8 chars) required' });
  const role = b.role === 'admin' ? 'admin' : 'worker';
  const salt = crypto.randomBytes(16).toString('hex');
  try { db.prepare('INSERT INTO users (username,salt,hash,role) VALUES (?,?,?,?)').run(b.username, salt, hash(b.password, salt), role); }
  catch { return send(c.res, 409, { error: 'username taken' }); }
  send(c.res, 201, { ok: true });
});
route('DELETE', '/api/users/:id', 'admin', (c, id) => {
  if (id === c.user.id) return send(c.res, 400, { error: 'cannot delete yourself' });
  db.prepare('DELETE FROM sessions WHERE user_id=?').run(id);
  db.prepare('DELETE FROM users WHERE id=?').run(id);
  send(c.res, 200, { ok: true });
});

// Categories
route('GET', '/api/categories', 'user', (c) => send(c.res, 200, db.prepare('SELECT c.*, (SELECT COUNT(*) FROM items WHERE category_id=c.id) AS items FROM categories c ORDER BY name').all()));
route('POST', '/api/categories', 'admin', async (c) => {
  const b = await readJson(c.req);
  if (!b.name) return send(c.res, 400, { error: 'name required' });
  try { const r = db.prepare('INSERT INTO categories (name) VALUES (?)').run(b.name); send(c.res, 201, { id: Number(r.lastInsertRowid) }); }
  catch { send(c.res, 409, { error: 'category exists' }); }
});
route('DELETE', '/api/categories/:id', 'admin', (c, id) => {
  if (db.prepare('SELECT 1 FROM items WHERE category_id=?').get(id)) return send(c.res, 409, { error: 'category still has items' });
  db.prepare('DELETE FROM categories WHERE id=?').run(id);
  send(c.res, 200, { ok: true });
});

// Items
route('GET', '/api/items', 'user', (c) => {
  const u = new URL(c.req.url, 'http://x').searchParams;
  let sql = `${ITEM_SQL} WHERE 1=1`; const args = [];
  if (u.get('category')) { sql += ' AND i.category_id=?'; args.push(Number(u.get('category'))); }
  if (u.get('q')) { sql += ' AND i.name LIKE ?'; args.push(`%${u.get('q')}%`); }
  if (u.get('status') === 'low') sql += ' AND i.stock>0 AND i.stock<=i.low_threshold';
  if (u.get('status') === 'out') sql += ' AND i.stock=0';
  send(c.res, 200, db.prepare(sql + ' ORDER BY i.name').all(...args).map(itemView));
});
route('POST', '/api/items', 'user', async (c) => {
  const b = await readJson(c.req);
  if (!validItem(b)) return send(c.res, 400, { error: 'Нэр, үлдэгдэл (0 буюу их), нэгж (ширхэг/кг/метр) шаардлагатай' });
  if (db.prepare('SELECT COUNT(*) n FROM items').get().n >= MAX_ITEMS) return send(c.res, 409, { error: `limit ${MAX_ITEMS} items reached` });
  const r = db.prepare('INSERT INTO items (name,category_id,price,stock,unit,low_threshold) VALUES (?,?,?,?,?,?)')  .run(b.name, b.categoryId ?? null, b.price ?? null, qty(b.stock), b.unit || 'ширхэг', b.lowThreshold ?? 5);
  const id = Number(r.lastInsertRowid);
    if (b.stock > 0) logMove({ id, name: b.name }, c.user, qty(b.stock), 'анхны үлдэгдэл');
  send(c.res, 201, { id });
});
route('PUT', '/api/items/:id', 'user', async (c, id) => {
  const b = await readJson(c.req);
  if (!validItem(b)) return send(c.res, 400, { error: 'invalid item' });
  const old = db.prepare('SELECT * FROM items WHERE id=?').get(id);
  if (!old) return send(c.res, 404, { error: 'not found' });
  db.prepare('UPDATE items SET name=?,category_id=?,price=?,stock=?,unit=?,low_threshold=? WHERE id=?')  .run(b.name, b.categoryId ?? null, b.price ?? null, qty(b.stock), b.unit || 'ширхэг', b.lowThreshold ?? old.low_threshold, id);
    if (qty(b.stock) !== old.stock) logMove({ id, name: b.name }, c.user, qty(b.stock - old.stock), 'гараар засварласан');
  send(c.res, 200, { ok: true });
});
// Take (negative) or add (positive) stock; every change is logged with the worker's name.
route('POST', '/api/items/:id/adjust', 'user', async (c, id) => {
  const b = await readJson(c.req);
  const item = db.prepare('SELECT * FROM items WHERE id=?').get(id);
  if (!item) return send(c.res, 404, { error: 'not found' });
  if (typeof b.delta !== 'number' || !Number.isFinite(b.delta) || qty(b.delta) === 0) return send(c.res, 400, { error: 'Тоо хэмжээ буруу байна' });
  const delta = qty(b.delta), next = qty(item.stock + delta);
  if (next < 0) return send(c.res, 409, { error: 'Үлдэгдэл хүрэлцэхгүй байна' });
  db.prepare('UPDATE items SET stock=? WHERE id=?').run(next, id);
  logMove(item, c.user, delta, b.note);
  send(c.res, 200, { stock: next });
});
route('POST', '/api/items/:id/photo', 'user', async (c, id) => {
  const ext = EXT[(c.req.headers['content-type'] || '').split(';')[0]];
  if (!ext) return send(c.res, 415, { error: 'jpeg, png, webp or gif only' });
  const item = db.prepare('SELECT photo FROM items WHERE id=?').get(id);
  if (!item) return send(c.res, 404, { error: 'not found' });
  const data = await readRaw(c.req, MAX_PHOTO);
  const file = `${id}-${Date.now()}.${ext}`;
  fs.writeFileSync(path.join(UPLOADS, file), data);
  if (item.photo) fs.rmSync(path.join(UPLOADS, item.photo), { force: true });
  db.prepare('UPDATE items SET photo=? WHERE id=?').run(file, id);
  send(c.res, 200, { photo: `/uploads/${file}` });
});
route('DELETE', '/api/items/:id', 'admin', (c, id) => {
  const item = db.prepare('SELECT * FROM items WHERE id=?').get(id);
  if (!item) return send(c.res, 404, { error: 'not found' });
  if (item.photo) fs.rmSync(path.join(UPLOADS, item.photo), { force: true });
  logMove(item, c.user, -item.stock, 'бараа устгасан');
  db.prepare('DELETE FROM items WHERE id=?').run(id);
  send(c.res, 200, { ok: true });
});

// Dashboard: what is leaving and what is low
route('GET', '/api/summary', 'user', (c) => {
  const n = (w) => db.prepare(`SELECT COUNT(*) n FROM items WHERE ${w}`).get().n;
  send(c.res, 200, {
    // top-taken rows are per item; quantities may be mixed units, so the unit is returned too
    total: n('1=1'), low: n('stock>0 AND stock<=low_threshold'), out: n('stock=0'),
    lowItems: db.prepare(`${ITEM_SQL} WHERE i.stock<=i.low_threshold ORDER BY i.stock LIMIT 50`).all().map(itemView),
    topLeaving: db.prepare("SELECT m.item_name AS name, -SUM(m.delta) AS taken, i.unit FROM movements m LEFT JOIN items i ON i.id=m.item_id WHERE m.delta<0 AND m.ts>=datetime('now','-7 days') GROUP BY m.item_id ORDER BY taken DESC LIMIT 10").all(),
  });
});
route('GET', '/api/movements', 'user', (c) => send(c.res, 200, db.prepare('SELECT * FROM movements ORDER BY id DESC LIMIT 100').all()));

const MIME = { '.jpg': 'image/jpeg', '.png': 'image/png', '.webp': 'image/webp', '.gif': 'image/gif' };
http.createServer(async (req, res) => {
  const p = new URL(req.url, 'http://x').pathname;
  if (req.method === 'GET' && p === '/') { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return res.end(fs.readFileSync(path.join(dir, 'index.html'))); }
  if (req.method === 'GET' && p.startsWith('/uploads/')) {
    const f = path.join(UPLOADS, path.basename(p));
    if (!fs.existsSync(f)) return send(res, 404, { error: 'not found' });
    res.writeHead(200, { 'Content-Type': MIME[path.extname(f)] || 'application/octet-stream', 'Cache-Control': 'public, max-age=86400' });
    return fs.createReadStream(f).pipe(res);
  }
  for (const r of routes) {
    const m = r.re.exec(p);
    if (r.method !== req.method || !m) continue;
    const user = getUser(req);
    if (r.access !== 'public' && !user) return send(res, 401, { error: 'login required' });
    if (r.access === 'admin' && user.role !== 'admin') return send(res, 403, { error: 'admin only' });
    try { return await r.fn({ req, res, user }, m[1] && Number(m[1])); }
    catch (e) { return send(res, 400, { error: e.message }); }
  }
  send(res, 404, { error: 'not found' });
}).listen(PORT, () => console.log(`Inventory running at http://localhost:${PORT}`));
