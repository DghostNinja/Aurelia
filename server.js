const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PUBLIC_DIR = path.join(__dirname, 'public');
const ROUTER = {};

// ============================================================
// LAB CONFIG — each flag mirrors a real-world root cause.
// Flipping these removes the flavour you are testing.
// ============================================================
const CONFIG = {
  host: '127.0.0.1',
  port: 3000,
  secret: 'velare-lab-secret-2e4b6a8c1d0f',
  // (vuln) verification never checks token expiry -> expired JWTs are honoured
  ignoreExpiration: true,
  // (vuln) server accepts unsigned `alg:"none"` tokens -> forged identities
  allowAlgNone: true,
  // (vuln) revoked (logged-out) tokens are never cross-checked -> replay works
  checkRevocation: false,
  // (vuln) amounts above this still execute server-side, response says rejected
  dailyLimit: 5000,
};

// ============================================================
// In-memory bank
// ============================================================
const users = {
  'alice@velare.io': {
    email: 'alice@velare.io',
    name: 'Alice Chen', role: 'user', initials: 'AC',
    password: 'Aurora!2026', otp: '603391',
    device: { id: 'mbp7f3', label: 'MacBook Pro' },
  },
  'nathan@velare.io': {
    email: 'nathan@velare.io',
    name: 'Nathan Cole', role: 'user', initials: 'NC',
    password: 'Hanso!1984', otp: '772014',
    device: { id: 'xps12a', label: 'XPS 13' },
  },
  'admin@velare.io': {
    email: 'admin@velare.io',
    name: 'Sofia Reyes', role: 'admin', initials: 'SR',
    password: 'Vault!Admin2026', otp: '915562',
    device: { id: 'lob9c', label: 'ThinkPad' },
  },
};

let balances = {};
let ledger = {};
const revoked = new Set();
const issued = []; // token vault: {jti, sub, via, exp, iat, used}
let labs = freshLabs();

// ============================================================
// The 8 cases — each is a separate, self-contained scenario.
// ============================================================
function freshLabs() {
  return {
    1: { id: 1, title: 'Status code flip', group: 'Response-level trust', done: false },
    2: { id: 2, title: 'Envelope + body trust', group: 'Response-level trust', done: false },
    3: { id: 3, title: 'JWT that ignores logout', group: 'Session lifecycle', done: false },
    4: { id: 4, title: 'OTP verification bypass', group: 'Second factor', done: false },
    5: { id: 5, title: 'Device authorisation bypass', group: 'Second factor', done: false },
    6: { id: 6, title: 'Transfer settles on rejected verdict', group: 'Transactions', done: false },
    7: { id: 7, title: 'Expired JWT still accepted', group: 'Token integrity', done: false },
    8: { id: 8, title: 'Unsigned alg:none JWT', group: 'Token integrity', done: false },
  };
}

function reseed() {
  for (const email of Object.keys(users)) {
    balances[email] = email === 'admin@velare.io' ? 214000.0 : 47820.75;
    ledger[email] = seedLedger(email);
  }
  revoked.clear();
  issued.length = 0;
  labs = freshLabs();
}

function seedLedger(email) {
  const now = Date.now();
  const names = email === 'admin@velare.io'
    ? [{ who: 'Rebalance Fund', dir: 'in', amt: 21200 }, { who: 'Ops. reserve', dir: 'out', amt: 1260 }]
    : [{ who: 'Northwind Studio', dir: 'in', amt: 6840 }, { who: 'Costa Café', dir: 'out', amt: 12.5 }, { who: 'Salary · Meridian Ltd', dir: 'in', amt: 9200 }];
  return names.map((n, i) => ({
    id: `tx-${email.split('@')[0]}-${i}`,
    counterparty: n.who,
    amount: n.amt,
    dir: n.dir,
    note: n.dir === 'in' ? 'Incoming transfer' : 'Card payment',
    ts: now - (i + 1) * 86400000,
    status: 'cleared',
  }));
}

// ============================================================
// JWT — hand rolled so every vulnerability is visible
// ============================================================
const b64u = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
const b64uDec = (s) => JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));
const randHex = (n) => crypto.randomBytes(n).toString('hex');

function sign(payload, expSeconds = 900, tokenRef) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  payload = { ...payload, iat: now, exp: now + expSeconds, jti: randHex(8) };
  const body = `${b64u(header)}.${b64u(payload)}`;
  const sig = crypto.createHmac('sha256', CONFIG.secret).update(body).digest('base64url');
  issued.unshift({ jti: payload.jti, sub: payload.sub, via: payload.via, exp: payload.exp, iat: payload.iat, tokenRef, ns: 'hs256' });
  return `${body}.${sig}`;
}

function signUnsigned(payload, tokenRef) {
  const header = { alg: 'none', typ: 'JWT' };
  payload = { ...payload, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 900, jti: randHex(8) };
  issued.unshift({ jti: payload.jti, sub: payload.sub, via: payload.via, exp: payload.exp, iat: payload.iat, ns: 'unsigned', tokenRef });
  return `${b64u(header)}.${b64u(payload)}.`;
}

function verify(token) {
  const parts = (token || '').split('.');
  if (parts.length < 2) throw new Error('MALFORMED_TOKEN');
  const header = b64uDec(parts[0]);
  const payload = b64uDec(parts[1]);

  if (header.alg === 'none') {
    if (!CONFIG.allowAlgNone) throw new Error('ALG_NONE_REJECTED');
  } else if (header.alg === 'HS256') {
    const expected = crypto.createHmac('sha256', CONFIG.secret)
      .update(`${parts[0]}.${parts[1]}`).digest('base64url');
    const given = parts[2];
    if (!given || given.length !== expected.length ||
        !crypto.timingSafeEqual(Buffer.from(given), Buffer.from(expected))) {
      throw new Error('BAD_SIGNATURE');
    }
  } else {
    throw new Error('UNSUPPORTED_ALG ' + header.alg);
  }

  if (CONFIG.ignoreExpiration !== true && payload.exp && payload.exp * 1000 < Date.now()) {
    throw new Error('TOKEN_EXPIRED');
  }
  return payload;
}

// ============================================================
// Helpers
// ============================================================
const send = (res, status, body) => {
  if (!res.headersSent) {
    res.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    });
  }
  res.end(JSON.stringify(body));
};

const money = (n) => n.toLocaleString('en-US', { style: 'currency', currency: 'USD' });

function audit(method, url, status) {
  if (process.stdout.isTTY) console.log(`  ${method} ${url} -> ${status}`);
}

function mark(id) {
  if (labs[id] && !labs[id].done) {
    labs[id].done = true;
    return true;
  }
  return false;
}

const summary = () => {
  const out = [];
  for (const k of [1, 2, 3, 4, 5, 6, 7, 8]) {
    const l = labs[k];
    out.push({ id: l.id, title: l.title, group: l.group, done: l.done });
  }
  return out;
};

// The token gate. Marks a case whenever a token that *should* have been
// rejected is actually accepted and used — that is the exploit event.
function authenticate(token) {
  if (!token) return { error: 'MISSING_TOKEN' };
  try {
    const payload = verify(token);
    const entry = issued.find((t) => t.jti === payload.jti);

    if (payload.exp && payload.exp * 1000 < Date.now()) mark(7);            // expired accepted
    if (!entry || entry.ns === 'unsigned') mark(8);                          // forged accepted
    if (payload.via === 'login_fail') mark(1);                               // failed-login session accepted
    if (payload.via === 'unlock_fail') mark(2);                              // rejected-unlock session accepted
    if (payload.via === 'otp_fail') mark(4);                                 // unverified OTP session accepted
    if (payload.via === 'device_fail') mark(5);                              // unmatched device session accepted
    if (entry && revoked.has(payload.jti)) {
      if (CONFIG.checkRevocation) return { error: 'TOKEN_REVOKED' };
      mark(3);                                                              // logged-out session accepted
    }
    if (entry) entry.used = true;
    if (!users[payload.sub]) return { error: 'UNKNOWN_SUBJECT' };
    return { payload, token };
  } catch (e) {
    return { error: e.message };
  }
}

function bearer(req) {
  const auth = req.headers['authorization'] || '';
  const alt = req.headers['x-session-token'] || '';
  return (auth.startsWith('Bearer ') ? auth.slice(7) : alt).trim();
}

// ============================================================
// CASE 01 — Status code flip
// The client trusts `res.ok` only. A failed sign-in still ships a signed
// token inside the 401 body. Rewriting 401 -> 200 is the whole exploit.
// ============================================================
route('POST', '/api/auth/signin', (req, res, body) => {
  const { email, password } = body;
  const user = users[email];

  if (!user || user.password !== password) {
    const leaktoken = sign({ sub: user ? email : (email || 'unknown'), via: 'login_fail', name: user ? user.name : 'Unknown User', role: user ? user.role : 'user' }, 900, 'c1');
    return send(res, 401, {
      success: false,
      message: 'Invalid email or password.',
      token: leaktoken,
      envelope: 'AUTH_FAILED',
    });
  }
  const token = sign({ sub: email, via: 'login_pass', name: user.name, role: user.role });
  send(res, 200, {
    success: true, token, user: { email, name: user.name, role: user.role, initials: user.initials },
  });
});

route('GET', '/api/auth/session', (req, res) => {
  const sess = authenticate(bearer(req));
  if (sess.error) return send(res, 401, { authorized: false, message: 'Not authenticated.' });
  const email = sess.payload.sub;
  const u = users[email];
  send(res, 200, {
    authorized: true,
    account: { email, name: u.name, initials: u.initials, role: u.role },
    balance: balances[email],
    transactions: ledger[email].slice(0, 3),
  });
});

// ============================================================
// CASE 02 — Envelope + body trust
// Here the client checks BOTH the status line AND the body flag. Flipping
// the status to 200 alone does nothing — you must also rewrite the error
// body (`unlocked:false -> true`). Realistic dual-gate trust bug.
// ============================================================
route('POST', '/api/limits/request', (req, res, body) => {
  const { email } = body;
  const user = users[email];
  if (!user) return send(res, 404, { success: false, message: 'Account not found.' });

  // Account is genuinely under manual review. The endpoint still hands out a
  // session token inside the rejected envelope.
  const session = sign({ sub: email, via: 'unlock_fail', name: user.name, role: user.role }, 900, 'c2');
  return send(res, 401, {
    success: false,
    message: 'Account is under manual review.',
    error: 'REVIEW_REQUIRED',
    unlocked: false,
    session,
  });
});

route('GET', '/api/limits/status', (req, res) => {
  const sess = authenticate(bearer(req));
  if (sess.error) return send(res, 401, { authorized: false, message: 'Not authenticated.' });
  const email = sess.payload.sub;
  const u = users[email];
  send(res, 200, {
    authorized: true,
    unlocked: true,
    panel: {
      email,
      name: u.name,
      balance: balances[email],
      permits: ['high_value_withdrawal', 'statement_export', 'beneficiary_edit'],
      reviewed: 'cleared_for_high_value',
    },
  });
});

// ============================================================
// CASE 03 — JWT that ignores logout
// "Sign out" adds the token to the revoked set, but the authenticator never
// checks it — so a logged-out token keeps working. Replay the old token.
// ============================================================
route('GET', '/api/session/issue', (req, res) => {
  const u = users['alice@velare.io'];
  const token = sign({ sub: u.email, via: 'case3', name: u.name, role: u.role }, 900, 'c3');
  send(res, 200, { token, user: { email: u.email, name: u.name } });
});

route('POST', '/api/session/revoke', (req, res, body) => {
  const token = body.token || bearer(req);
  if (token) {
    try {
      const p = verify(token);
      revoked.add(p.jti);
    } catch { /* stale token: mark revoked anyway */ }
  }
  send(res, 200, { success: true, message: 'Signed out.' });
});

route('GET', '/api/session/check', (req, res) => {
  const sess = authenticate(bearer(req));
  if (sess.error) return send(res, 401, { authorized: false, message: 'Not authenticated.' });
  const email = sess.payload.sub;
  const u = users[email];
  send(res, 200, {
    authorized: true,
    session: { email, name: u.name, jti: sess.payload.jti, expiresAt: sess.payload.exp * 1000 },
    balance: balances[email],
  });
});

// ============================================================
// CASE 04 — OTP verification bypass
// Wrong codes return verified:false but the sessionToken is valid on its
// own. Flipping verified -> true in the body unlocks the continuation.
// ============================================================
route('POST', '/api/verify/otp', (req, res, body) => {
  const { email, code } = body;
  const user = users[email];
  if (!user) return send(res, 404, { success: false, message: 'Account not found.' });

  const valid = String(code) === user.otp;
  const sessionToken = sign({ sub: email, via: valid ? 'otp_pass' : 'otp_fail', name: user.name, role: user.role }, 900, 'c4');

  if (!valid) {
    return send(res, 200, {
      verified: false, message: 'Incorrect security code.',
      sessionToken,
    });
  }
  send(res, 200, { verified: true, message: 'Code accepted.', sessionToken });
});

route('GET', '/api/verify/status', (req, res) => {
  const sess = authenticate(bearer(req));
  if (sess.error) return send(res, 401, { authorized: false, message: 'Not authenticated.' });
  const email = sess.payload.sub;
  const u = users[email];
  send(res, 200, {
    activated: true,
    session: { email, name: u.name, factor: 'otp', verified: true },
    balance: balances[email],
  });
});

// ============================================================
// CASE 05 — Device authorisation bypass
// Same envelope mistake as OTP, separate page and endpoint. A mismatched
// device still receives a valid grant. Flip match -> true.
// ============================================================
route('POST', '/api/devices/authorize', (req, res, body) => {
  const { email, deviceId } = body;
  const user = users[email];
  if (!user) return send(res, 404, { success: false, message: 'Account not found.' });

  const match = user.device.id === deviceId;
  const grant = sign({ sub: email, via: match ? 'device_pass' : 'device_fail', name: user.name, role: user.role }, 900, 'c5');

  if (!match) {
    return send(res, 200, {
      match: false, message: 'Device not recognised.',
      grant,
    });
  }
  send(res, 200, { match: true, message: 'Device recognised.', grant });
});

route('GET', '/api/devices/session', (req, res) => {
  const sess = authenticate(bearer(req));
  if (sess.error) return send(res, 401, { authorized: false, message: 'Not authenticated.' });
  const email = sess.payload.sub;
  const u = users[email];
  send(res, 200, {
    activated: true,
    session: { email, name: u.name, factor: 'device', match: true },
    balance: balances[email],
  });
});

// ============================================================
// CASE 06 — Transfer settles on rejected verdict
// Over-limit transfers execute server-side and return 403 with a receipt.
// Rewriting 403 -> 200 flips only the client's view; money already moved.
// ============================================================
route('POST', '/api/transfers/send', (req, res, body) => {
  const sess = authenticate(bearer(req));
  if (sess.error) return send(res, 401, { accepted: false, message: 'Not authenticated.' });

  const { to, amount } = body;
  const amt = Number(amount);
  if (!to || !Number.isFinite(amt) || amt <= 0) return send(res, 400, { accepted: false, message: 'Invalid request.' });
  if (!users[to]) return send(res, 400, { accepted: false, message: 'Recipient not found.', to });

  const from = sess.payload.sub;
  if (amt > balances[from]) return send(res, 402, { accepted: false, code: 'INSUFFICIENT_FUNDS', message: 'Insufficient funds.' });

  const overLimit = amt > CONFIG.dailyLimit;
  // Execution happens BEFORE the response decides the verdict.
  balances[from] -= amt;
  balances[to] += amt;
  const receipt = { id: `rc-${randHex(6)}`, from, to, amount: amt, ts: Date.now(), status: 'cleared' };
  ledger[from].unshift({ id: receipt.id, counterparty: users[to].name, amount: amt, dir: 'out', note: '', ts: receipt.ts, status: 'cleared' });
  ledger[to].unshift({ id: receipt.id, counterparty: users[from].name, amount: amt, dir: 'in', note: '', ts: receipt.ts, status: 'cleared' });

  if (overLimit) {
    mark(6);
    return send(res, 403, {
      accepted: false, code: 'DAILY_LIMIT', message: 'Blocked by daily limit policy.',
      receipt, // <-- the transfer already cleared server-side
    });
  }
  send(res, 200, { accepted: true, message: 'Transfer completed.', receipt });
});

route('GET', '/api/transfers/balance', (req, res) => {
  const sess = authenticate(bearer(req));
  if (sess.error) return send(res, 401, { balance: 0 });
  send(res, 200, { balance: balances[sess.payload.sub] });
});

// ============================================================
// CASE 07 — Expired JWT still accepted
// A token that already expired keeps working because expiry is never
// checked. Serve one, then use it.
// ============================================================
route('GET', '/api/session/recovery', (req, res) => {
  const u = users['alice@velare.io'];
  const token = sign({ sub: u.email, via: 'case7', name: u.name, role: u.role }, -120, 'c7');
  send(res, 200, { token, expiredAt: (Math.floor(Date.now() / 1000) - 120) * 1000, user: { email: u.email, name: u.name } });
});

route('GET', '/api/session/recover', (req, res) => {
  const sess = authenticate(bearer(req));
  if (sess.error) return send(res, 401, { authorized: false, message: 'Not authenticated.' });
  const email = sess.payload.sub;
  const u = users[email];
  send(res, 200, {
    authorized: true,
    session: { email, name: u.name, jti: sess.payload.jti, exp: sess.payload.exp * 1000, expired: true },
    balance: balances[email],
  });
});

// ============================================================
// CASE 08 — Unsigned alg:none JWT
// The server accepts tokens with an empty signature. A "forged" admin token
// is issued on request — paste it anywhere and it works.
// ============================================================
route('GET', '/api/support/token', (req, res) => {
  const admin = users['admin@velare.io'];
  const token = signUnsigned({ sub: admin.email, via: 'case8', name: admin.name, role: 'admin' }, 'c8');
  send(res, 200, { token, user: { email: admin.email, name: admin.name, role: 'admin' } });
});

route('GET', '/api/support/session', (req, res) => {
  const sess = authenticate(bearer(req));
  if (sess.error) return send(res, 401, { authorized: false, message: 'Not authenticated.' });
  const email = sess.payload.sub;
  const u = users[email];
  send(res, 200, {
    authorized: true,
    session: { email, name: u.name, role: u.role, signed: false, jti: sess.payload.jti },
    balance: balances[email],
    vault: { permits: ['account_admin', 'hsm_rotate', 'payout_release'] },
  });
});

// ============================================================
// Lab-wide endpoints
// ============================================================
route('GET', '/api/meta', (req, res) =>
  send(res, 200, { cases: summary() }));

route('GET', '/api/labs/artifacts', (req, res) =>
  send(res, 200, {
    vault: [
      { id: 'c3-live', caseId: 3, kind: 'a token you are already holding' },
      { id: 'c7-expired', caseId: 7, kind: 'expired before you signed out' },
      { id: 'c8-forged', caseId: 8, kind: 'no signature at all' },
    ],
  }));

route('POST', '/api/meta/reset', (req, res) => {
  reseed();
  send(res, 200, { success: true, message: 'Lab state reset.', cases: summary() });
});

route('POST', '/api/jwt/decode', (req, res, body) => {
  try {
    const parts = (body.token || '').split('.');
    const header = b64uDec(parts[0]);
    const payload = b64uDec(parts[1]);
    const expired = payload.exp * 1000 < Date.now();
    send(res, 200, { header, payload, expired, expAt: payload.exp * 1000 });
  } catch {
    send(res, 400, { message: 'Not a valid JWT.' });
  }
});

// ============================================================
// Dispatcher
// ============================================================
function route(method, pattern, handler) {
  ROUTER[method + ' ' + pattern] = handler;
}

const serveStatic = (res, file) => {
  const filePath = path.join(PUBLIC_DIR, file);
  if (!filePath.startsWith(PUBLIC_DIR) || !fs.existsSync(filePath)) {
    res.writeHead(404); res.end('not found'); return;
  }
  const ext = path.extname(filePath);
  const mime = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml' }[ext] || 'application/octet-stream';
  res.writeHead(200, { 'Content-Type': mime, 'Cache-Control': 'no-store' });
  fs.createReadStream(filePath).pipe(res);
};

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const key = `${req.method} ${url.pathname}`;
  const handler = ROUTER[key];

  if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) return serveStatic(res, 'index.html');
  if (req.method === 'GET' && (url.pathname === '/styles.css' || url.pathname === '/app.js')) return serveStatic(res, url.pathname.slice(1));
  if (req.method === 'GET' && url.pathname === '/favicon.ico') {
    res.writeHead(204, { 'Content-Type': 'image/x-icon' }); return res.end();
  }
  if (req.method === 'OPTIONS') {
    res.writeHead(204); return res.end();
  }

  if (!handler) {
    audit(req.method, url.pathname, 404);
    return send(res, 404, { message: 'Not found.' });
  }

  let raw = '';
  req.on('data', (c) => { raw += c; if (raw.length > 1e6) req.destroy(); });
  req.on('end', () => {
    let body = {};
    if (raw) {
      try { body = JSON.parse(raw); } catch {
        audit(req.method, url.pathname, 400);
        return send(res, 400, { message: 'Invalid JSON.' });
      }
    }
    handler(req, res, body);
    audit(req.method, url.pathname, res.statusCode);
  });
});

reseed();
server.listen(CONFIG.port, CONFIG.host, () => {
  console.log('');
  console.log('  AURELIA — response-integrity case lab');
  console.log('  ──────────────────────────────────────');
  console.log(`  local : http://${CONFIG.host}:${CONFIG.port}`);
  console.log('  cases : 8 independent scenarios, open /api/meta');
  console.log('  creds : alice@velare.io / Aurora!2026   (admin: admin@velare.io / Vault!Admin2026)');
  console.log('  otp   : 603391 · 772014 · 915562       (alice · nathan · admin)');
  console.log('  face  : mbp7f3 · xps12a · lob9c         (alice · nathan · admin)');
  console.log('  note  : intentionally vulnerable · keep it local.');
  console.log('');
});