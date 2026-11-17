/** Taxi Lakay Cloudflare Worker + D1
 * Auth: signed HMAC tokens; password storage: PBKDF2-SHA256.
 * Data access is role/ownership checked. Existing D1 records are preserved.
 */
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Max-Age': '86400'
};
const encoder = new TextEncoder();
const now = () => Date.now();
const uid = () => `taxi-${now()}-${crypto.randomUUID()}`;
const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...CORS }
});
const fail = (message, status = 400) => json({ error: message }, status);
const safeEqual = (a, b) => {
  if (a.length !== b.length) return false;
  let x = 0; for (let i = 0; i < a.length; i++) x |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return x === 0;
};
function b64u(bytes) {
  let s = ''; for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function unb64u(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const raw = atob(s); return Uint8Array.from(raw, c => c.charCodeAt(0));
}
async function hmacKey(secret) {
  return crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
async function makeToken(user, env) {
  if (!env.JWT_SECRET || String(env.JWT_SECRET).length < 32) throw new Error('JWT_SECRET pa konfigire oswa li twò kout.');
  const head = b64u(encoder.encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const payload = b64u(encoder.encode(JSON.stringify({ sub: user.id, iat: Math.floor(now()/1000), exp: Math.floor(now()/1000) + 60*60*24*7 })));
  const data = `${head}.${payload}`;
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(env.JWT_SECRET), encoder.encode(data));
  return `${data}.${b64u(new Uint8Array(sig))}`;
}
async function readToken(req, env) {
  const raw = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
  if (!raw || !env.JWT_SECRET) return null;
  const p = raw.split('.'); if (p.length !== 3) return null;
  try {
    const ok = await crypto.subtle.verify('HMAC', await hmacKey(env.JWT_SECRET), unb64u(p[2]), encoder.encode(`${p[0]}.${p[1]}`));
    if (!ok) return null;
    const claims = JSON.parse(new TextDecoder().decode(unb64u(p[1])));
    if (!claims.sub || !claims.exp || claims.exp < Math.floor(now()/1000)) return null;
    return claims.sub;
  } catch { return null; }
}
async function passwordHash(password, saltBytes = crypto.getRandomValues(new Uint8Array(16))) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: saltBytes, iterations: 210000, hash: 'SHA-256' }, key, 256);
  return `pbkdf2$210000$${b64u(saltBytes)}$${b64u(new Uint8Array(bits))}`;
}
async function verifyPassword(password, stored, oldSalt) {
  if (String(stored).startsWith('pbkdf2$')) {
    const [, iter, salt, expected] = stored.split('$');
    const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: unb64u(salt), iterations: Number(iter), hash: 'SHA-256' }, key, 256);
    return safeEqual(b64u(new Uint8Array(bits)), expected);
  }
  // Backward compatibility with the previous Worker hash; upgraded on next successful login.
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(`${oldSalt}|${password}`));
  const hex = [...new Uint8Array(digest)].map(x => x.toString(16).padStart(2, '0')).join('');
  return safeEqual(hex, String(stored));
}
async function schema(env) {
  if (!env.DB) throw new Error('Binding D1 DB pa konekte.');
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
    phone TEXT UNIQUE NOT NULL, role TEXT NOT NULL, password_hash TEXT NOT NULL,
    salt TEXT, profile_json TEXT DEFAULT '{}', status TEXT DEFAULT 'aktif', created_at INTEGER NOT NULL
  )`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS records (
    collection TEXT NOT NULL, id TEXT NOT NULL, value_json TEXT NOT NULL,
    idempotency_key TEXT, PRIMARY KEY (collection, id)
  )`).run();
  await env.DB.prepare(`CREATE UNIQUE INDEX IF NOT EXISTS idx_records_idem
    ON records(collection, idempotency_key) WHERE idempotency_key IS NOT NULL`).run();
  // Older databases may have a NOT NULL salt column; keep it populated for compatibility.
}
async function userFor(req, env) {
  const id = await readToken(req, env); if (!id) return null;
  const row = await env.DB.prepare('SELECT id,name,email,phone,role,password_hash,salt,profile_json,status FROM users WHERE id=?').bind(id).first();
  if (!row || row.status === 'bloke' || row.status === 'refize') return null;
  let profile = {}; try { profile = JSON.parse(row.profile_json || '{}'); } catch {}
  return { id: row.id, name: row.name, email: row.email, phone: row.phone, role: row.role, profile, status: row.status };
}
const isAdmin = u => u?.role === 'admin';
const phoneOf = v => String(v?.phone || v?.account_phone || v?.passenger_phone || v?.driver_phone || v?.sender_phone || '').trim();
const owns = (v, u) => {
  const p = u.phone;
  return !!p && [v?.phone, v?.account_phone, v?.passenger_phone, v?.driver_phone, v?.sender_phone].some(x => String(x || '') === p);
};
const allowedCollections = new Set(['taxi_accounts','taxi_requests','taxi_ratings','taxi_fee_payments','taxi_notifications','taxi_reports','taxi_warnings','taxi_unblock_requests','taxi_settings','taxi_chats','taxi_chat_messages','taxi_notification_settings']);
async function chatIds(env, u) {
  const rows = await env.DB.prepare("SELECT id,value_json FROM records WHERE collection='taxi_chats' LIMIT 1000").all();
  const ids = new Set();
  for (const r of rows.results || []) { try { const v = JSON.parse(r.value_json); if ((v.participants || []).map(String).includes(u.phone)) ids.add(r.id); } catch {} }
  return ids;
}
async function canSee(env, u, coll, id, v) {
  if (isAdmin(u)) return true;
  if (!allowedCollections.has(coll)) return false;
  if (coll === 'taxi_accounts') return id === u.id || (v.role === 'chofe' && (v.status === 'verifye' || v.status === 'apwouve') && v.available === true);
  if (coll === 'taxi_requests') {
    const assigned = String(v.driver_phone || v.assigned_driver_phone || '');
    const state = String(v.status || v.etat || '').toLowerCase();
    const openForDrivers = u.role === 'chofe' && !assigned && ['pending','an_attant','annatant','nouvo','requested','recherche','ap tann'].includes(state);
    return owns(v, u) || openForDrivers;
  }
  if (coll === 'taxi_fee_payments' || coll === 'taxi_notifications' || coll === 'taxi_reports' || coll === 'taxi_unblock_requests' || coll === 'taxi_notification_settings') return owns(v, u);
  if (coll === 'taxi_ratings') return true;
  if (coll === 'taxi_warnings' || coll === 'taxi_settings') return false;
  if (coll === 'taxi_chats') return (v.participants || []).map(String).includes(u.phone);
  if (coll === 'taxi_chat_messages') {
    const chats = await chatIds(env, u); return chats.has(String(v.chat_id || ''));
  }
  return false;
}
async function canWrite(env, u, coll, id, v, mode) {
  if (isAdmin(u)) return true;
  if (!allowedCollections.has(coll)) return false;
  if (coll === 'taxi_accounts') return id === u.id && String(v.phone || u.phone) === u.phone && ['pasaje','chofe'].includes(v.role || u.role);
  if (coll === 'taxi_requests') {
    if (mode === 'create') return String(v.account_phone || v.passenger_phone || v.phone || '') === u.phone;
    return owns(v, u) || String(v.driver_phone || '') === u.phone;
  }
  if (coll === 'taxi_ratings' || coll === 'taxi_reports') return mode === 'create' && String(v.passenger_phone || v.account_phone || v.phone || '') === u.phone;
  if (coll === 'taxi_fee_payments' || coll === 'taxi_unblock_requests') return String(v.driver_phone || v.phone || '') === u.phone;
  if (coll === 'taxi_notifications') return false;
  if (coll === 'taxi_notification_settings') return String(v.phone || '') === u.phone;
  if (coll === 'taxi_chats') return (v.participants || []).map(String).includes(u.phone);
  if (coll === 'taxi_chat_messages') {
    if (mode === 'create' && String(v.sender_phone || '') !== u.phone) return false;
    const chats = await chatIds(env, u); return chats.has(String(v.chat_id || ''));
  }
  return false;
}
async function listRecords(env, u, coll) {
  if (!allowedCollections.has(coll)) throw new Error('Koleksyon sa a pa otorize.');
  const rows = await env.DB.prepare('SELECT id,value_json FROM records WHERE collection=? ORDER BY rowid DESC LIMIT 1000').bind(coll).all();
  const out = [];
  for (const r of rows.results || []) {
    let v = {}; try { v = JSON.parse(r.value_json); } catch {}
    if (await canSee(env, u, coll, r.id, v)) out.push({ id: r.id, value: v });
  }
  return out;
}
async function handle(req, env) {
  const url = new URL(req.url);
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  if (url.pathname.startsWith('/api/')) await schema(env);

  if (url.pathname === '/api/health' && req.method === 'GET') {
    await env.DB.prepare('SELECT 1 AS ok').first();
    return json({ ok: true, service: 'Taxi Lakay API', database: 'connected' });
  }

  if (url.pathname === '/api/auth/register' && req.method === 'POST') {
    const b = await req.json().catch(() => ({}));
    const email = String(b.email || '').trim().toLowerCase();
    const password = String(b.password || '');
    const name = String(b.full_name || b.name || '').trim();
    const phone = String(b.phone || b.profile?.phone || '').trim();
    const wantedRole = String(b.role || b.profile?.role || 'pasaje').toLowerCase();
    const adminEmail = String(env.ADMIN_EMAIL || 'djerbyvictorin8@gmail.com').trim().toLowerCase();
    const isAdminSignup = email === adminEmail;
    if (isAdminSignup && (!env.ADMIN_BOOTSTRAP_KEY || !safeEqual(String(b.admin_secret || ''), String(env.ADMIN_BOOTSTRAP_KEY)))) return fail('Kle sekirite administratè a pa kòrèk oswa li poko konfigire.', 403);
    const role = isAdminSignup ? 'admin' : (wantedRole === 'chofe' ? 'chofe' : 'pasaje');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail('Mete yon adrès imèl ki valab.');
    if (password.length < 8) return fail('Modpas la dwe gen omwen 8 karaktè.');
    if (!name || !phone) return fail('Non ak nimewo telefòn obligatwa.');
    const exists = await env.DB.prepare('SELECT id FROM users WHERE email=? OR phone=?').bind(email, phone).first();
    if (exists) return fail('Imèl oswa nimewo telefòn sa deja anrejistre.', 409);
    const id = uid();
    const stored = await passwordHash(password);
    const profile = { ...(b.profile || {}), name, phone, email, role };
    await env.DB.prepare('INSERT INTO users (id,name,email,phone,role,password_hash,salt,profile_json,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)')
      .bind(id, name, email, phone, role, stored, '', JSON.stringify(profile), 'aktif', now()).run();
    const account = { ...profile, zone: profile.zone || 'Kap-Ayisyen', rating: role === 'chofe' ? '5.0' : '4.9', available: false, status: role === 'chofe' ? 'an_attant' : 'aktif', created_label: new Date().toISOString() };
    await env.DB.prepare('INSERT OR REPLACE INTO records (collection,id,value_json) VALUES (?,?,?)').bind('taxi_accounts', id, JSON.stringify(account)).run();
    const user = { id, name, email, phone, role, profile, status: 'aktif' };
    return json({ token: await makeToken(user, env), user });
  }

  if (url.pathname === '/api/auth/login' && req.method === 'POST') {
    const b = await req.json().catch(() => ({}));
    const email = String(b.email || '').trim().toLowerCase();
    const row = await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(email).first();
    if (!row || !(await verifyPassword(String(b.password || ''), row.password_hash, row.salt || ''))) return fail('Imèl oswa modpas la pa kòrèk.', 401);
    if (row.status === 'bloke') return fail('Kont sa a bloke. Kontakte sipò.', 403);
    if (row.status === 'refize') return fail('Kont sa a te refize pa administratè a.', 403);
    let profile = {}; try { profile = JSON.parse(row.profile_json || '{}'); } catch {}
    const adminEmail = String(env.ADMIN_EMAIL || 'djerbyvictorin8@gmail.com').trim().toLowerCase();
    let role = row.role;
    if (email === adminEmail && row.role !== 'admin') {
      if (!env.ADMIN_BOOTSTRAP_KEY || !safeEqual(String(b.admin_secret || ''), String(env.ADMIN_BOOTSTRAP_KEY))) return fail('Kle sekirite administratè a pa kòrèk oswa li poko konfigire.', 403);
      role = 'admin';
    } else if (email !== adminEmail && row.role === 'admin') { role = 'pasaje'; }
    if (role !== row.role) await env.DB.prepare('UPDATE users SET role=? WHERE id=?').bind(role, row.id).run();
    if (!String(row.password_hash).startsWith('pbkdf2$')) {
      const upgraded = await passwordHash(String(b.password || ''));
      await env.DB.prepare('UPDATE users SET password_hash=?,salt=? WHERE id=?').bind(upgraded, '', row.id).run();
    }
    const user = { id: row.id, name: row.name, email: row.email, phone: row.phone, role, profile: { ...profile, role }, status: row.status };
    return json({ token: await makeToken(user, env), user });
  }

  if (url.pathname === '/api/auth/me' && req.method === 'GET') {
    const me = await userFor(req, env); if (!me) return fail('Sesyon an ekspire. Konekte ankò.', 401);
    const rec = await env.DB.prepare('SELECT value_json FROM records WHERE collection=? AND id=?').bind('taxi_accounts', me.id).first();
    let value = { ...me.profile, id: me.id, name: me.name, email: me.email, phone: me.phone, role: me.role, status: me.status };
    if (rec) { try { value = { ...value, ...JSON.parse(rec.value_json), role: me.role }; } catch {} }
    return json({ user: { id: me.id, email: me.email, name: me.name, phone: me.phone, role: me.role, profile: value, status: me.status } });
  }

  if (url.pathname === '/api/actions' && req.method === 'POST') {
    const me = await userFor(req, env); if (!me) return fail('Ou dwe konekte pou fè aksyon sa a.', 401);
    const b = await req.json().catch(() => ({})); const action = String(b.action || ''); const a = b.args || {};
    if (action === 'profile.me') {
      const r = await env.DB.prepare('SELECT value_json FROM records WHERE collection=? AND id=?').bind('taxi_accounts', me.id).first();
      let value = { ...me.profile, id: me.id, name: me.name, phone: me.phone, role: me.role };
      if (r) { try { value = { ...value, ...JSON.parse(r.value_json), role: me.role }; } catch {} }
      return json({ data: { id: me.id, value } });
    }
    if (action === 'profile.bootstrap') {
      const r = await env.DB.prepare('SELECT value_json FROM records WHERE collection=? AND id=?').bind('taxi_accounts', me.id).first();
      let old = {}; if (r) { try { old = JSON.parse(r.value_json); } catch {} }
      const requested = String(a.role || a.profile?.role || me.role).toLowerCase();
      const role = isAdmin(me) ? 'admin' : (requested === 'chofe' ? 'chofe' : 'pasaje');
      const value = { ...old, ...(a.profile || {}), name: a.name || me.name, phone: me.phone, email: me.email, role, id: me.id };
      await env.DB.prepare('UPDATE users SET role=?,profile_json=? WHERE id=?').bind(role, JSON.stringify(value), me.id).run();
      await env.DB.prepare('INSERT OR REPLACE INTO records (collection,id,value_json) VALUES (?,?,?)').bind('taxi_accounts', me.id, JSON.stringify(value)).run();
      return json({ data: { id: me.id, value } });
    }
    if (action === 'records.list') {
      const coll = String(a.collection || '');
      const records = await listRecords(env, me, coll);
      return json({ data: { records } });
    }
    if (action === 'records.create') {
      const coll = String(a.collection || ''); const value = a.value && typeof a.value === 'object' ? a.value : {};
      if (!allowedCollections.has(coll)) return fail('Koleksyon sa a pa otorize.');
      if (!await canWrite(env, me, coll, '', value, 'create')) return fail('Ou pa gen dwa kreye done sa a.', 403);
      if (a.idempotency_key) {
        const dup = await env.DB.prepare('SELECT id,value_json FROM records WHERE collection=? AND idempotency_key=?').bind(coll, String(a.idempotency_key)).first();
        if (dup) { let v = {}; try { v = JSON.parse(dup.value_json); } catch {} return json({ data: { id: dup.id, value: v } }); }
      }
      const id = uid();
      await env.DB.prepare('INSERT INTO records (collection,id,value_json,idempotency_key) VALUES (?,?,?,?)').bind(coll, id, JSON.stringify(value), a.idempotency_key ? String(a.idempotency_key) : null).run();
      return json({ data: { id, value } });
    }
    if (action === 'records.replace') {
      const coll = String(a.collection || ''); const id = String(a.id || '');
      if (!allowedCollections.has(coll) || !id) return fail('Koleksyon oswa ID pa valab.');
      const oldRow = await env.DB.prepare('SELECT value_json FROM records WHERE collection=? AND id=?').bind(coll, id).first();
      if (!oldRow) return fail('Done sa a pa egziste.', 404);
      let old = {}; try { old = JSON.parse(oldRow.value_json); } catch {}
      const value = a.value && typeof a.value === 'object' ? a.value : {};
      if (!await canSee(env, me, coll, id, old) || !await canWrite(env, me, coll, id, { ...old, ...value }, 'replace')) return fail('Ou pa gen dwa modifye done sa a.', 403);
      if (!isAdmin(me)) {
        // A user cannot change ownership, role, approval status, or admin-controlled money records.
        if ((coll === 'taxi_accounts' || coll === 'taxi_notification_settings') && String(value.phone || me.phone) !== me.phone) return fail('Ou pa ka chanje pwopriyetè done sa a.', 403);
        if (coll === 'taxi_accounts') {
          if (String(value.role || old.role) !== String(old.role) || String(value.status || old.status) !== String(old.status)) return fail('Se administratè a sèlman ki ka chanje wòl oswa apwobasyon kont lan.', 403);
          if (old.role === 'chofe' && !['verifye','apwouve'].includes(String(old.status)) && value.available === true) return fail('Kont chofè a dwe apwouve anvan li vin disponib.', 403);
        }
        if (['taxi_fee_payments','taxi_unblock_requests','taxi_ratings','taxi_reports'].includes(coll)) return fail('Se administratè a sèlman ki ka modifye dosye sa a apre li fin kreye.', 403);
        if (coll === 'taxi_chats') {
          const before = (old.participants || []).map(String).sort().join('|');
          const after = (value.participants || []).map(String).sort().join('|');
          if (before !== after) return fail('Ou pa ka chanje patisipan konvèsasyon an.', 403);
        }
      }
      await env.DB.prepare('UPDATE records SET value_json=? WHERE collection=? AND id=?').bind(JSON.stringify(value), coll, id).run();
      if (coll === 'taxi_accounts' && id === me.id && !isAdmin(me)) await env.DB.prepare('UPDATE users SET profile_json=? WHERE id=?').bind(JSON.stringify(value), me.id).run();
      return json({ data: { id, value } });
    }
    if (action === 'records.delete') {
      const coll = String(a.collection || ''); const id = String(a.id || '');
      if (!allowedCollections.has(coll) || !id) return fail('Koleksyon oswa ID pa valab.');
      const row = await env.DB.prepare('SELECT value_json FROM records WHERE collection=? AND id=?').bind(coll, id).first();
      if (!row) return json({ data: { deleted: false } });
      let v = {}; try { v = JSON.parse(row.value_json); } catch {}
      if (!isAdmin(me) && !(coll === 'taxi_chats' && (v.participants || []).map(String).includes(me.phone)) && !(coll === 'taxi_chat_messages' && await canSee(env, me, coll, id, v))) return fail('Ou pa gen dwa efase done sa a.', 403);
      await env.DB.prepare('DELETE FROM records WHERE collection=? AND id=?').bind(coll, id).run();
      return json({ data: { deleted: true } });
    }
    return fail(`Aksyon pa rekonèt: ${action}`, 400);
  }
  return null;
}
export default {
  async fetch(req, env, ctx) {
    try {
      const url = new URL(req.url);
      if (url.pathname.startsWith('/api/')) {
        const response = await handle(req, env);
        if (response) return response;
        return fail('API route pa egziste.', 404);
      }
      if (env.ASSETS) return env.ASSETS.fetch(req);
      return json({ error: 'Assets pa konfigire.' }, 500);
    } catch (err) {
      console.error('Taxi Lakay Worker error:', err?.stack || err);
      return json({ error: 'Erè sèvè Taxi Lakay la. Verifye D1 ak sekrè Worker yo.' }, 500);
    }
  }
};
