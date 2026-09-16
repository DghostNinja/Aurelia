(() => {
  'use strict';

  // ---------------------------------------------------------------
  // state
  // ---------------------------------------------------------------
  const state = {
    proxy: false,      // built-in interceptor OFF by default -> use Burp/ZAP
    auth: null,        // authenticated session token (from Sign in)
    session: null,     // last account object returned after signing in
    portal: 'primary', // 'primary' | 'legacy' sign-in flow
    tokens: {},        // per-flow session tokens (keyed by flow id)
  };

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => [...document.querySelectorAll(sel)];
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const money = (n) => (n ?? 0).toLocaleString('en-US', { style: 'currency', currency: 'USD' });
  const short = (s, n = 30) => (s.length > n ? s.slice(0, n) + '…' : s);
  const pretty = (d) => JSON.stringify(d, null, 2);
  const when = (t) => new Date(t).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });

  // ---------------------------------------------------------------
  // toast
  // ---------------------------------------------------------------
  function toast(msg, kind = '') {
    const t = document.createElement('div');
    t.className = 'toast ' + kind;
    t.textContent = msg;
    $('#toasts').appendChild(t);
    setTimeout(() => t.remove(), 4200);
  }

  async function copyText(text) {
    try { await navigator.clipboard.writeText(text); return true; }
    catch {
      const ta = document.createElement('textarea');
      ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      let ok = false;
      try { ok = document.execCommand('copy'); } catch { ok = false; }
      ta.remove(); return ok;
    }
  }

  // ---------------------------------------------------------------
  // interceptor
  // ---------------------------------------------------------------
  let interceptedResolver = null;

  function openInterceptor({ path, status, body }) {
    $('#ix-sub').textContent = path;
    $('#ix-status').value = String(status);
    $('#ix-body').value = pretty(body);
    $('#ix-body').dataset.original = pretty(body);
    $('#interceptor').classList.remove('hidden');
    $('#ix-status').focus();
    $('#ix-status').select();
    return new Promise((resolve) => { interceptedResolver = resolve; });
  }

  function closeInterceptor(result) {
    $('#interceptor').classList.add('hidden');
    interceptedResolver && interceptedResolver(result);
    interceptedResolver = null;
  }

  $('#ix-apply').addEventListener('click', () => {
    const status = parseInt($('#ix-status').value, 10) || 200;
    let data;
    try { data = JSON.parse($('#ix-body').value); } catch { data = { text: $('#ix-body').value }; }
    closeInterceptor({ status, data, modified: true });
  });

  $('#ix-copy').addEventListener('click', async () => {
    const original = $('#ix-body').dataset.original;
    $('#ix-body').value = original;
    if (await copyText(original)) toast('Original body copied.', 'ok');
    else toast('Couldn\'t write to clipboard.', 'err');
  });

  $('#ix-close').addEventListener('click', () => {
    $('#interceptor').classList.add('hidden');
    interceptedResolver && interceptedResolver(null);
    interceptedResolver = null;
  });

  function shouldIntercept(path, status, body) {
    if (!state.proxy) return false;
    if (status >= 400) return true;
    if (body) {
      if (body.verified === false) return true;
      if (body.match === false) return true;
      if (body.authorized === false) return true;
      if (body.accepted === false) return true;
    }
    return false;
  }

  function interceptorTask(path, orig) {
    return () => new Promise((resolve) => {
      if (!shouldIntercept(path, orig.status, orig.data)) return resolve({ status: orig.status, data: orig.data, modified: false });
      const payload = { status: orig.status, data: orig.data, modified: false };
      openInterceptor({ path, status: orig.status, body: orig.data }).then((m) => resolve(m || payload));
    });
  }

  // ---------------------------------------------------------------
  // api client
  // ---------------------------------------------------------------
  const log = [];

  async function api(method, path, body, tokenOverride) {
    const token = tokenOverride;
    const init = { method, headers: {} };
    if (body) { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(body); }
    if (token) init.headers['Authorization'] = 'Bearer ' + token;

    const t0 = performance.now();
    const rawRes = await fetch(path, init);
    let data;
    const text = await rawRes.text();
    try { data = JSON.parse(text); } catch { data = { raw: text }; }

    const orig = { status: rawRes.status, data, token };
    const applied = await interceptorTask(path, orig)();
    log.unshift({
      method, path, origStatus: orig.status, status: applied.status,
      modified: applied.modified, ms: Math.round(performance.now() - t0),
      token: token ? short(token, 14) + '…' : '(none)',
    });
    if (log.length > 60) log.length = 60;
    renderLog();
    return { ...applied, ok: applied.status >= 200 && applied.status < 300 };
  }

  function renderLog() {
    const el = $('#pl-entries');
    if (!el) return;
    el.innerHTML = log.map((e, i) => {
      const cls = e.status < 300 ? 's2' : e.status < 500 ? 's4' : 's5';
      return `<div class="pl-e" data-i="${i}">
        <span class="pl-status ${cls}">${e.status}</span>
        <span class="pl-method">${e.method}</span> ${esc(e.path)}${e.modified ? ' <span class="pl-edit">edited</span>' : ''}
      </div>`;
    }).join('');
  }

  // ---------------------------------------------------------------
  // routing
  // ---------------------------------------------------------------
  const routes = {};
  function go(route) { location.hash = route; }
  function currentRoute() { return (location.hash || '#/').slice(1); }

  function handleRoute() {
    const r = currentRoute();
    const fn = routes[r] || routes['/'];
    Promise.resolve(fn()).then(() => {
      const navAuth = $('#nav-auth');
      if (navAuth) {
        const authed = !!state.auth;
        navAuth.textContent = authed ? 'Account' : 'Sign in';
        navAuth.dataset.route = authed ? '/dashboard' : '/signin';
      }
      $$('#navbar a').forEach((a) => a.classList.toggle('active', a.dataset.route === r));
      $('#view').scrollTop = 0;
      window.scrollTo(0, 0);
    });
  }

  window.addEventListener('hashchange', handleRoute);
  document.addEventListener('click', (e) => {
    const el = e.target.closest('[data-route]');
    if (el) { e.preventDefault(); go(el.dataset.route); }
  });

  function view(inner) {
    $('#view').innerHTML = `<section class="page">${inner}</section>`;
  }

  // ---------------------------------------------------------------
  // password eye toggle
  // ---------------------------------------------------------------
  function pwField(id, label, placeholder) {
    return `
      <label>${label}</label>
      <div class="pw-wrap">
        <input class="input pw-input" id="${id}" type="password" placeholder="${placeholder || '••••••••'}" autocomplete="off" spellcheck="false">
        <button type="button" class="pw-eye" data-for="${id}" aria-label="Show password" tabindex="-1">
          <svg class="eye-open" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M2 12s3.5-6.5 10-6.5S22 12 22 12s-3.5 6.5-10 6.5S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>
          <svg class="eye-closed" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.6" style="display:none"><path d="M3 3l18 18"/><path d="M10.6 5.1A9.7 9.7 0 0 1 12 5c6.5 0 10 7 10 7a17.4 17.4 0 0 1-3 3.8"/><path d="M6.1 6.6A16.8 16.8 0 0 0 2 12s3.5 7 10 7a9.7 9.7 0 0 0 4.2-.9"/></svg>
        </button>
      </div>`;
  }

  document.addEventListener('click', (e) => {
    const eye = e.target.closest('.pw-eye');
    if (!eye) return;
    const input = document.getElementById(eye.dataset.for);
    if (!input) return;
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    eye.querySelector('.eye-open').style.display = show ? 'none' : 'block';
    eye.querySelector('.eye-closed').style.display = show ? 'block' : 'none';
    input.focus();
  });

  // ---------------------------------------------------------------
  // shared bits
  // ---------------------------------------------------------------
  function sectionHead(title, sub) {
    return `<div class="sec-head"><h1>${esc(title)}</h1><p>${sub}</p></div>`;
  }

  function kv(pairs) {
    return `<div class="kv">${pairs.map(([k, v]) => `<div class="kv-r"><span>${k}</span><b>${v}</b></div>`).join('')}</div>`;
  }

  function successCard(title, pairs) {
    return `<div class="success-card">${esc(title)}</div>${kv(pairs)}`;
  }

  function clearMsgs(...ids) {
    ids.forEach((id) => {
      const el = $(id);
      if (!el) return;
      el.innerHTML = '';
      el.textContent = '';
      el.style.display = 'none';
    });
  }

  const CASES = [
    { id: 1, title: 'Status code flip', group: 'Response-level trust', diff: 'Apprentice', route: '/signin', ico: '◈',
      desc: 'The client trusts only the status line. A failed login still ships a signed JWT inside the 401 body — flipping 401 → 200 authenticates you.' },
    { id: 2, title: 'Envelope + body trust', group: 'Response-level trust', diff: 'Apprentice', route: '/access', ico: '▲',
      desc: 'The client validates the status line AND a body flag. Flipping the status to 200 alone does nothing — you must rewrite the error body too.' },
    { id: 3, title: 'JWT that ignores logout', group: 'Session lifecycle', diff: 'Practitioner', route: '/sessions', ico: '◫',
      desc: 'Signing out adds the token to a revoked set the server never checks. Issue a session, sign out, then keep using the same token.' },
    { id: 4, title: 'OTP response manipulation', group: 'Second factor', diff: 'Apprentice', route: '/verify', ico: '⑂',
      desc: 'A wrong code returns verified:false but still ships a valid sessionToken. Flip the flag — or replay the same code — and the session holds.' },
    { id: 5, title: 'Device binding bypass', group: 'Second factor', diff: 'Apprentice', route: '/devices', ico: '⌘',
      desc: 'An unrecognised device still receives a session grant with match:false. Flip match → true and a device that was never enrolled is bound.' },
    { id: 6, title: 'Settlement before verdict', group: 'Transactions', diff: 'Practitioner', route: '/transfers', ico: '⇄',
      desc: 'Over-limit transfers execute server-side, then the API returns 403 with a receipt. The money moved before the verdict was written.' },
    { id: 7, title: 'Expired JWT accepted', group: 'Token integrity', diff: 'Apprentice', route: '/recovery', ico: '◯',
      desc: 'Token expiry is never checked. A recovery token that already expired is still honoured when presented.' },
    { id: 8, title: 'Unsigned alg:none JWT', group: 'Token integrity', diff: 'Expert', route: '/support', ico: '◍',
      desc: 'The server accepts tokens with an empty signature. A forged admin token works anywhere it is presented.' },
  ];

  function caseHead(id) {
    const c = CASES.find((x) => x.id === id);
    return `
      <div class="case-head">
        <a class="back" data-route="/" title="All exercises">← Labs</a>
        <div class="case-head-body">
          <div class="case-head-kicker">Case ${String(id).padStart(2, '0')} · ${c.group}</div>
          <h1>${esc(c.title)}</h1>
          <p>${esc(c.desc)}</p>
          <div class="case-pills">
            <span class="pill diff">${esc(c.diff)}</span>
            <span class="pill">Use the Interceptor (or own proxy) to edit the response</span>
          </div>
        </div>
      </div>`;
  }

  function tokenBlock(label, id, value) {
    return `
      <div class="field">
        <div class="spread" style="margin-bottom:6px">
          <label style="margin:0">${label}</label>
          <button class="btn ghost xs" id="${id}-copy">Copy</button>
        </div>
        <textarea class="input mono" id="${id}" rows="3" spellcheck="false" style="font-size:12px;resize:vertical">${value ? esc(value) : ''}</textarea>
      </div>`;
  }

  // ---------------------------------------------------------------
  // LABS INDEX  (PortSwigger-style case list)
  // ---------------------------------------------------------------
  routes['/'] = async () => {
    let done = {};
    try { done = Object.fromEntries((await (await fetch('/api/meta')).json()).cases.map((c) => [c.id, c.done])); } catch {}

    let solved = Object.values(done).filter(Boolean).length;
    view(`
      <div class="sec-head" style="margin-top:16px">
        <h1>Response Integrity Labs</h1>
        <p>Every exercise reproduces a real response-handling flaw observed in production banking APIs. Open one and demonstrate the exploit with the built-in editor — or your own proxy.</p>
      </div>

      <div class="case-grid">
        ${CASES.map((c) => `
          <a class="case-card" data-route="${c.route}">
            <div class="case-num">${String(c.id).padStart(2, '0')}</div>
            <div class="case-info">
              <div class="case-title">${esc(c.title)}${done[c.id] ? ' <span class="check">✓</span>' : ''}</div>
              <div class="case-meta"><span>${esc(c.group)}</span><span class="dot-sep">·</span><span>${esc(c.diff)}</span></div>
              <div class="case-desc">${esc(c.desc)}</div>
            </div>
            <div class="case-go">Open →</div>
          </a>`).join('')}
      </div>

      <div class="sec-head" style="margin-top:48px">
        <h2 class="sec-title">Environment</h2>
        <p>${solved} of ${CASES.length} exercises exploited this session. Credentials below drive every flow.</p>
      </div>

      <div class="env-card">
        <p class="muted tiny mb8">Client credentials for the exercises. Data resets on restart.</p>
        <div class="env-table">
          <div class="env-row">
            <span class="mono">alice@velare.io</span>
            <b class="mono">Aurora!2026</b>
            <span class="mono">otp 603391</span>
            <span class="mono">device mbp7f3</span>
          </div>
          <div class="env-row muted">
            <span class="mono">nathan@velare.io</span>
            <span class="mono dim">••••••••</span>
            <span class="mono">otp 772014</span>
            <span class="mono">device xps12a</span>
          </div>
          <div class="env-row muted">
            <span class="mono">admin@velare.io</span>
            <span class="mono dim">••••••••</span>
            <span class="mono">otp 915562</span>
            <span class="mono">device lob9c</span>
          </div>
        </div>
      </div>

      <div class="footer-note">
        <span class="muted tiny">All state resets with the button below.</span>
        <button class="btn ghost xs" id="reset-lab">Reset data</button>
      </div>`);

    $('#reset-lab').addEventListener('click', async () => {
      await fetch('/api/meta/reset', { method: 'POST' });
      state.tokens = {};
      toast('Lab data reset.', 'ok');
      go('/');
    });
  };

  // ---------------------------------------------------------------
  // SIGN IN  (status flip)
  // ---------------------------------------------------------------
  routes['/signin'] = () => {
    view(`
      ${caseHead(1)}
      <div class="auth-wrap">
        <div class="card auth-card">
          <div class="seg" id="portal-seg">
            <button type="button" class="seg-btn active" data-portal="primary">Primary portal</button>
            <button type="button" class="seg-btn" data-portal="legacy">Legacy portal</button>
          </div>
          <div class="err" id="si-err"></div>
          <div class="field">
            <label>Client email</label>
            <input class="input" id="si-email" type="email" placeholder="you@residency.io" spellcheck="false" autocomplete="username">
          </div>
          <div class="field">${pwField('si-pass', 'Password')}</div>
          <button class="btn primary" id="btn-si" style="width:100%">Sign in</button>
          <div id="si-result"></div>
          <div id="si-exchange" class="hidden"></div>
        </div>
      </div>`);
    $$('#portal-seg .seg-btn').forEach((b) => b.addEventListener('click', () => {
      state.portal = b.dataset.portal;
      clearMsgs('#si-err', '#si-result');
      $('#si-exchange').classList.add('hidden');
      $$('#portal-seg .seg-btn').forEach((x) => x.classList.toggle('active', x === b));
    }));
    $('#btn-si').addEventListener('click', doSignIn);
    $('#si-pass').addEventListener('keydown', (e) => e.key === 'Enter' && doSignIn());
    ['#si-email', '#si-pass'].forEach((sel) =>
      $(sel).addEventListener('input', () => clearMsgs('#si-err', '#si-result')));
  };

  async function doSignIn() {
    const email = $('#si-email').value.trim().toLowerCase();
    const password = $('#si-pass').value;
    const legacy = state.portal === 'legacy';
    clearMsgs('#si-err', '#si-result');
    $('#si-exchange').classList.add('hidden');
    const err = $('#si-err');
    if (!password) { err.textContent = 'Enter your password.'; err.style.display = 'block'; return; }
    const btn = $('#btn-si'); btn.disabled = true; btn.textContent = 'Signing in…';

    if (legacy) {
      const r = await api('POST', '/api/auth/signin/legacy', { email, password });
      btn.disabled = false; btn.textContent = 'Sign in';
      if (r.data.success && r.data.account) {
        state.session = r.data.account;
        $('#si-result').innerHTML = successCard('Credentials accepted.', [
          ['Client', esc(r.data.account.name)],
          ['Portal', 'Legacy'],
          ['Session token', 'Not issued — requested separately'],
        ]);
        const x = $('#si-exchange'); x.classList.remove('hidden');
        x.innerHTML = `<button class="btn gold" id="btn-ex" style="width:100%">Begin session</button>`;
        $('#btn-ex').addEventListener('click', async () => {
          const ex = await api('POST', '/api/auth/exchange', { email, role: state.session.role });
          if (ex.data.token) {
            state.auth = ex.data.token;
            state.session = ex.data.account;
            go('/dashboard');
          } else {
            err.textContent = ex.data.message || 'Exchange failed.';
            err.style.display = 'block';
          }
        });
      } else {
        err.textContent = r.data.message || (r.ok ? 'No session token was returned.' : 'Unable to sign in.');
        err.style.display = 'block';
      }
      return;
    }

    // primary portal: session token ships inside the response body
    const r = await api('POST', '/api/auth/signin', { email, password });
    btn.disabled = false; btn.textContent = 'Sign in';

    const tok = r.data.token;
    if (tok) state.tokens.signin = tok;
    if ((r.data.success === true || r.ok) && tok) {
      state.auth = tok;
      state.session = r.data.user;
      go('/dashboard');
    } else {
      err.textContent = r.data.message || 'Unable to sign in.';
      err.style.display = 'block';
    }
  }

  // ---------------------------------------------------------------
  // DASHBOARD  (authenticated client area)
  // ---------------------------------------------------------------
  routes['/dashboard'] = async () => {
    if (!state.auth) {
      view(`
        ${sectionHead('Client area', 'Your private banking space.')}
        <div class="card">
          <p class="muted mb8">Sign in to open your account.</p>
          <button class="btn primary" data-route="/signin">Sign in</button>
        </div>`);
      return;
    }
    const r = await api('GET', '/api/auth/session', null, state.auth);
    if (!r.data.account) {
      state.auth = null;
      view(`
        ${sectionHead('Client area', 'Your private banking space.')}
        <div class="card">
          <p class="muted mb8">Your session is no longer accepted. Sign in again.</p>
          <button class="btn primary" data-route="/signin">Sign in</button>
        </div>`);
      return;
    }
    const a = r.data.account;
    view(`
      <div class="hero">
        <div class="eyebrow">Client area</div>
        <h1>Welcome back,<br>${esc(a.name.split(' ')[0])}.</h1>
        <p>${esc(a.role === 'admin' ? 'Relationship administrator' : 'Private client')} · balance <b>${money(r.data.balance)}</b></p>
      </div>

      <div class="grid2" style="align-items:start; margin-top:44px">
        <div class="card">
          <div class="kv">
            <div class="kv-r"><span>Status</span><b>Session active</b></div>
            <div class="kv-r"><span>Client</span><b>${esc(a.name)}</b></div>
            <div class="kv-r"><span>Email</span><b class="mono">${esc(a.email)}</b></div>
            <div class="kv-r"><span>Role</span><b>${esc(a.role)}</b></div>
            <div class="kv-r"><span>Available balance</span><b class="mono">${money(r.data.balance)}</b></div>
          </div>
          <div class="field" style="display:flex; gap:10px; flex-wrap:wrap; margin-top:20px">
            <button class="btn primary" data-route="/transfers">Transfer</button>
            <button class="btn ghost" data-route="/verify">Two-step</button>
            <button class="btn ghost" data-route="/devices">Devices</button>
            <button class="btn ghost" data-route="/sessions">Sessions</button>
          </div>
          <div style="margin-top:18px">
            <button class="btn danger xs" id="btn-out">Sign out</button>
          </div>
        </div>
        <div class="card subtle">
          <div class="muted tiny mb8" style="letter-spacing:.2em;text-transform:uppercase;font-weight:600">Recent transactions</div>
          ${r.data.transactions.map((t) => `
            <div class="tx">
              <div class="tx-ico ${t.dir === 'in' ? 'in' : 'out'}">${t.dir === 'in' ? '↓' : '↑'}</div>
              <div style="min-width:0">
                <div class="tx-name">${esc(t.counterparty)}</div>
                <div class="tx-note">${t.dir === 'in' ? 'Incoming transfer' : 'Card payment'}</div>
              </div>
              <b class="mono ${t.dir === 'in' ? 'in' : 'out'}">${t.dir === 'in' ? '+' : '−'}${money(t.amount)}</b>
            </div>`).join('')}
        </div>
      </div>`);
    $('#btn-out').addEventListener('click', async () => {
      await api('POST', '/api/session/revoke', { token: state.auth });
      state.auth = null;
      state.session = null;
      toast('Signed out.', 'ok');
      go('/');
    });
  };

  // ---------------------------------------------------------------
  // TRANSFERS  (settles on rejected verdict)
  // ---------------------------------------------------------------
  routes['/transfers'] = async () => {
    if (!state.auth) {
      view(`
${caseHead(6)}
      <div class="card">
        <p class="muted mb8">Sign in to authorise transfers.</p>
        <button class="btn primary" data-route="/signin">Sign in</button>
      </div>`);
      return;
    }
    const s = await (await fetch('/api/transfers/balance', { headers: { Authorization: 'Bearer ' + state.auth } })).json();
    view(`
      ${caseHead(6)}
      <div class="grid2" style="align-items:start">
        <div class="card">
          <div class="spread" style="margin-bottom:18px">
            <span class="muted tiny">Available balance</span>
            <b class="mono">${money(s.balance)}</b>
          </div>
          <div class="err" id="tx-err"></div>
          <div class="field">
            <label>Recipient</label>
            <input class="input" id="tx-to" value="nathan@velare.io" spellcheck="false">
          </div>
          <div class="field">
            <label>Amount</label>
            <div class="qty"><span>$</span><input id="tx-amt" inputmode="decimal" value="1200"></div>
          </div>
          <div class="field">
            <label>Reference</label>
            <input class="input" id="tx-note" placeholder="Optional note" spellcheck="false" value="Allocation">
          </div>
          <button class="btn primary" id="btn-tx" style="width:100%">Authorise transfer</button>
          <div id="tx-result"></div>
        </div>
        <div class="card subtle">
          <div class="muted tiny mb8" style="letter-spacing:.2em;text-transform:uppercase;font-weight:600">Transfer details</div>
          <ul class="tx-list">
            <li class="tx"><div class="tx-ico in" style="background:transparent">◷</div><div style="min-width:0"><div class="tx-name">Settlement</div><div class="tx-note">Instant within Aurelia · same-day for scheduled flows</div></div></li>
            <li class="tx"><div class="tx-ico out" style="background:transparent">c</div><div style="min-width:0"><div class="tx-name">Fees</div><div class="tx-note">No charge on internal treasuries</div></div></li>
            <li class="tx"><div class="tx-ico in" style="background:transparent">≡</div><div style="min-width:0"><div class="tx-name">Reports</div><div class="tx-note">Confirmations appear in your statement</div></div></li>
          </ul>
        </div>
      </div>`);

    $('#btn-tx').addEventListener('click', doTransfer);
    $('#tx-amt').addEventListener('keydown', (e) => e.key === 'Enter' && doTransfer());
    $('#tx-note').addEventListener('keydown', (e) => e.key === 'Enter' && doTransfer());
    ['#tx-to', '#tx-amt', '#tx-note'].forEach((sel) =>
      $(sel).addEventListener('input', () => clearMsgs('#tx-err', '#tx-result')));
  };

  async function doTransfer() {
    const to = $('#tx-to').value.trim().toLowerCase();
    const amount = Number($('#tx-amt').value);
    const note = $('#tx-note').value;
    clearMsgs('#tx-err', '#tx-result');
    const err = $('#tx-err');
    const btn = $('#btn-tx'); btn.disabled = true; btn.textContent = 'Settling…';
    const r = await api('POST', '/api/transfers/send', { to, amount, note }, state.auth);
    btn.disabled = false; btn.textContent = 'Authorise transfer';

    const bal = (await (await fetch('/api/transfers/balance', { headers: { Authorization: 'Bearer ' + state.auth } })).json()).balance;

    if (r.ok && r.data.accepted) {
      $('#tx-result').innerHTML = successCard('Transfer complete.', [
        ['Receipt', `<span class="mono">${esc(r.data.receipt.id)}</span>`],
        ['Amount', money(amount)],
        ['New balance', `<span class="mono">${money(bal)}</span>`],
      ]);
    } else if (r.ok && r.data.receipt) {
      $('#tx-result').innerHTML = successCard('Transfer complete.', [
        ['Receipt', `<span class="mono">${esc(r.data.receipt.id)}</span>`],
        ['Amount', money(amount)],
        ['New balance', `<span class="mono">${money(bal)}</span>`],
      ]);
    } else if (r.data.receipt) {
      err.textContent = r.data.message || 'We couldn\'t complete this transfer.';
      err.style.display = 'block';
    } else {
      err.textContent = r.data.message || 'We couldn\'t complete this transfer.';
      err.style.display = 'block';
    }
  }

  // ---------------------------------------------------------------
  // TWO-STEP VERIFICATION  (OTP bypass)
  // ---------------------------------------------------------------
  routes['/verify'] = () => {
    view(`
      ${caseHead(4)}
      <div class="auth-wrap" style="margin-top:8px">
        <div class="card auth-card">
          <div class="err" id="v-err"></div>
          <div class="field">
            <label>Client</label>
            <input class="input" id="v-email" type="email" placeholder="you@residency.io" spellcheck="false">
          </div>
          <div class="otp-dots">
            ${Array.from({ length: 6 }, (_, i) => `<input maxlength="1" data-i="${i}" inputmode="numeric">`).join('')}
          </div>
          <button class="btn primary" id="btn-v" style="width:100%; margin-top:26px">Verify code</button>
          <div id="v-result"></div>
        </div>
      </div>`);

    const boxes = $$('.otp-dots input');
    boxes.forEach((b, i) => {
      b.addEventListener('input', () => {
        clearMsgs('#v-err', '#v-result');
        b.value = b.value.replace(/\D/g, '');
        if (b.value && i < 5) boxes[i + 1].focus();
      });
      b.addEventListener('keydown', (e) => { if (e.key === 'Backspace' && !b.value && i > 0) boxes[i - 1].focus(); });
    });
    boxes.forEach((b) => b.addEventListener('input', () => {
      if (boxes.every((x) => x.value)) doVerify(boxes.map((x) => x.value).join(''));
    }));
    $('#btn-v').addEventListener('click', () => doVerify(boxes.map((b) => b.value).join('')));
    $('#v-email').addEventListener('input', () => clearMsgs('#v-err', '#v-result'));
  };

  async function doVerify(code) {
    const email = $('#v-email').value.trim().toLowerCase();
    clearMsgs('#v-err', '#v-result');
    const err = $('#v-err');
    if (code.length !== 6) { err.textContent = 'Enter the full six-digit code.'; err.style.display = 'block'; return; }
    const btn = $('#btn-v'); if (btn) { btn.disabled = true; btn.textContent = 'Checking…'; }
    const r = await api('POST', '/api/verify/otp', { email, code });
    if (btn) { btn.disabled = false; btn.textContent = 'Verify code'; }

    const tok = r.data.sessionToken;
    if (tok) state.tokens.verify = tok;

    if (tok && r.data.verified === true) {
      const s = await api('GET', '/api/verify/status', null, tok);
      if (s.data.session) {
        $('#v-result').innerHTML = successCard('Identity verified.', [
          ['Client', esc(s.data.session.name)],
          ['Factor', 'Security code'],
          ['Balance', `<span class="mono">${money(s.data.balance)}</span>`],
        ]);
      }
    } else {
      err.textContent = r.data.message || 'That code doesn\'t match.';
      err.style.display = 'block';
    }
  }

  // ---------------------------------------------------------------
  // DEVICES  (device authorisation bypass)
  // ---------------------------------------------------------------
  routes['/devices'] = () => {
    view(`
      ${caseHead(5)}
      <div class="grid2" style="align-items:start">
        <div class="card">
          <div class="face-ring">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2"><circle cx="12" cy="8" r="3.4"/><path d="M5 19c1-4 4-6 7-6s6 2 7 6"/></svg>
          </div>
          <div class="err" id="d-err"></div>
          <div class="field">
            <label>Client</label>
            <input class="input" id="d-email" type="email" placeholder="you@residency.io" spellcheck="false">
          </div>
          <div class="field">
            <label>Device id</label>
            <input class="input" id="d-device" placeholder="Device reference" spellcheck="false" autocomplete="off">
          </div>
          <button class="btn primary" id="btn-d" style="width:100%">Authorise this device</button>
          <div id="d-result"></div>
        </div>
        <div class="card subtle">
          <div class="muted tiny mb8" style="letter-spacing:.2em;text-transform:uppercase;font-weight:600">Enrolled devices</div>
          <div class="kv">
            <div class="kv-r"><span>MacBook Pro</span><b class="mono">mbp7f3</b></div>
            <div class="kv-r"><span>iPhone 15 Pro</span><b class="mono">· 8841</b></div>
          </div>
        </div>
      </div>`);
    $('#btn-d').addEventListener('click', doDevice);
    $('#d-device').addEventListener('keydown', (e) => e.key === 'Enter' && doDevice());
    ['#d-email', '#d-device'].forEach((sel) =>
      $(sel).addEventListener('input', () => clearMsgs('#d-err', '#d-result')));
  };

  async function doDevice() {
    const email = $('#d-email').value.trim().toLowerCase();
    const dev = $('#d-device').value.trim();
    clearMsgs('#d-err', '#d-result');
    const err = $('#d-err');
    const btn = $('#btn-d'); btn.disabled = true; btn.textContent = 'Checking device…';
    const r = await api('POST', '/api/devices/authorize', { email, deviceId: dev || 'unknown' });
    btn.disabled = false; btn.textContent = 'Authorise this device';

    const tok = r.data.grant;
    if (tok) state.tokens.device = tok;

    if (tok && r.data.match === true) {
      const s = await api('GET', '/api/devices/session', null, tok);
      if (s.data.session) {
        $('#d-result').innerHTML = successCard('Device authorised.', [
          ['Client', esc(s.data.session.name)],
          ['Device', dev || '—'],
          ['Balance', `<span class="mono">${money(s.data.balance)}</span>`],
        ]);
      }
    } else {
      err.textContent = r.data.message || 'This device wasn\'t recognised.';
      err.style.display = 'block';
    }
  }

  // ---------------------------------------------------------------
  // CASE 03 — Session not revoked on logout
  // ---------------------------------------------------------------
  routes['/sessions'] = () => {
    view(`
      ${caseHead(3)}
      <div class="card" style="max-width:620px">
        <div class="muted tiny mb8" style="letter-spacing:.2em;text-transform:uppercase;font-weight:600">Setup</div>
        <p class="muted tiny mb8">Step 1: issue a session. Step 2: sign it out. Step 3: present the same token again.</p>
        <div class="field" style="display:flex; gap:10px; flex-wrap:wrap">
          <button class="btn primary sm" id="ss-issue">New session</button>
          <button class="btn danger sm" id="ss-logout">Sign out</button>
          <button class="btn gold sm" id="ss-check">Check session</button>
        </div>
        ${tokenBlock('Session token', 'ss-token', state.tokens.session)}
        <div id="ss-result"></div>
      </div>`);

    $('#ss-token').addEventListener('input', () => clearMsgs('#ss-result'));
    $('#ss-issue').addEventListener('click', async () => {
      clearMsgs('#ss-result');
      const r = await api('GET', '/api/session/issue');
      if (r.data.token) {
        state.tokens.session = r.data.token;
        $('#ss-token').value = r.data.token;
        $('#ss-result').innerHTML = successCard('Session started.', [
          ['Client', esc(r.data.user.name)],
          ['Token', `<span class="mono">${short(r.data.token, 46)}</span>`],
        ]);
      }
    });
    $('#ss-logout').addEventListener('click', async () => {
      clearMsgs('#ss-result');
      const tok = $('#ss-token').value.trim();
      if (!tok) return toast('No session to sign out.', 'err');
      const r = await api('POST', '/api/session/revoke', { token: tok });
      if (r.data.success) {
        $('#ss-result').innerHTML = successCard('Signed out.', [
          ['Status', 'Session closed'],
        ]);
      }
    });
    $('#ss-check').addEventListener('click', async () => {
      clearMsgs('#ss-result');
      const tok = $('#ss-token').value.trim();
      if (!tok) return toast('No session to check.', 'err');
      const r = await api('GET', '/api/session/check', null, tok);
      if (r.data.session) {
        $('#ss-result').innerHTML = successCard('Session active.', [
          ['Client', esc(r.data.session.email)],
          ['Balance', `<span class="mono">${money(r.data.balance)}</span>`],
          ['Token', `<span class="mono">${short(r.data.session.jti, 12)}</span>`],
        ]);
      } else {
        $('#ss-result').innerHTML = `<div class="kv"><div class="kv-r"><span>Status</span><b>Session closed</b></div></div>`;
      }
    });
    $('#ss-copy').addEventListener('click', async () => {
      if (await copyText($('#ss-token').value.trim())) toast('Token copied.', 'ok');
    });
  };

  // ---------------------------------------------------------------
  // CASE 07 — Expired JWT accepted
  // ---------------------------------------------------------------
  routes['/recovery'] = () => {
    view(`
      ${caseHead(7)}
      <div class="card" style="max-width:620px">
        <div class="muted tiny mb8" style="letter-spacing:.2em;text-transform:uppercase;font-weight:600">Setup</div>
        <p class="muted tiny mb8">Request a recovery token, then present it. It retired before it was even issued.</p>
        <div class="field" style="display:flex; gap:10px; flex-wrap:wrap">
          <button class="btn primary sm" id="rc-issue">Issue recovery token</button>
          <button class="btn gold sm" id="rc-use">Use token</button>
        </div>
        ${tokenBlock('Recovery token', 'rc-token', state.tokens.recovery)}
        <div id="rc-result"></div>
      </div>`);

    $('#rc-token').addEventListener('input', () => clearMsgs('#rc-result'));
    $('#rc-issue').addEventListener('click', async () => {
      clearMsgs('#rc-result');
      const r = await api('GET', '/api/session/recovery');
      if (r.data.token) {
        state.tokens.recovery = r.data.token;
        $('#rc-token').value = r.data.token;
        $('#rc-result').innerHTML = successCard('Recovery token issued.', [
          ['Client', esc(r.data.user.name)],
          ['Retired at', when(r.data.expiredAt)],
        ]);
      }
    });
    $('#rc-use').addEventListener('click', async () => {
      clearMsgs('#rc-result');
      const tok = $('#rc-token').value.trim();
      if (!tok) return toast('No token to use.', 'err');
      const r = await api('GET', '/api/session/recover', null, tok);
      if (r.data.session) {
        $('#rc-result').innerHTML = successCard('Access restored.', [
          ['Client', esc(r.data.session.name)],
          ['Balance', `<span class="mono">${money(r.data.balance)}</span>`],
        ]);
      } else {
        $('#rc-result').innerHTML = `<div class="kv"><div class="kv-r"><span>Status</span><b>Token not accepted</b></div></div>`;
      }
    });
    $('#rc-copy').addEventListener('click', async () => {
      if (await copyText($('#rc-token').value.trim())) toast('Token copied.', 'ok');
    });
  };

  // ---------------------------------------------------------------
  // CASE 08 — Unsigned alg:none JWT
  // ---------------------------------------------------------------
  routes['/support'] = () => {
    view(`
      ${caseHead(8)}
      <div class="card" style="max-width:620px">
        <div class="muted tiny mb8" style="letter-spacing:.2em;text-transform:uppercase;font-weight:600">Setup</div>
        <p class="muted tiny mb8">Request a pass-through token, then present it. The signature is empty.</p>
        <div class="field" style="display:flex; gap:10px; flex-wrap:wrap">
          <button class="btn primary sm" id="sp-issue">Issue support token</button>
          <button class="btn gold sm" id="sp-use">Use token</button>
        </div>
        ${tokenBlock('Support token', 'sp-token', state.tokens.support)}
        <div id="sp-result"></div>
      </div>`);

    $('#sp-token').addEventListener('input', () => clearMsgs('#sp-result'));
    $('#sp-issue').addEventListener('click', async () => {
      clearMsgs('#sp-result');
      const r = await api('GET', '/api/support/token');
      if (r.data.token) {
        state.tokens.support = r.data.token;
        $('#sp-token').value = r.data.token;
        $('#sp-result').innerHTML = successCard('Support token issued.', [
          ['Advisor', esc(r.data.user.name)],
        ]);
      }
    });
    $('#sp-use').addEventListener('click', async () => {
      clearMsgs('#sp-result');
      const tok = $('#sp-token').value.trim();
      if (!tok) return toast('No token to use.', 'err');
      const r = await api('GET', '/api/support/session', null, tok);
      if (r.data.session) {
        $('#sp-result').innerHTML = successCard('Support access enabled.', [
          ['Advisor', esc(r.data.session.name)],
          ['Scope', esc(r.data.session.role)],
          ['Balance', `<span class="mono">${money(r.data.balance)}</span>`],
        ]);
      } else {
        $('#sp-result').innerHTML = `<div class="kv"><div class="kv-r"><span>Status</span><b>Token not accepted</b></div></div>`;
      }
    });
    $('#sp-copy').addEventListener('click', async () => {
      if (await copyText($('#sp-token').value.trim())) toast('Token copied.', 'ok');
    });
  };

  // ---------------------------------------------------------------
  // HIGHER LIMITS  (envelope + body trust)
  // ---------------------------------------------------------------
  routes['/access'] = () => {
    if (!state.auth) {
      view(`
${caseHead(2)}
      <div class="card">
        <p class="muted mb8">Sign in to request higher limits.</p>
        <button class="btn primary" data-route="/signin">Sign in</button>
      </div>`);
      return;
    }
    view(`
      ${caseHead(2)}
      <div class="auth-wrap" style="margin-top:8px">
        <div class="card auth-card">
          <div class="err" id="a-err"></div>
          <div class="field">
            <label>Client</label>
            <input class="input" id="a-email" type="email" placeholder="you@residency.io" spellcheck="false">
          </div>
          <div class="kv" style="margin-bottom:20px">
            <div class="kv-r"><span>Current daily limit</span><b class="mono">$5,000</b></div>
            <div class="kv-r"><span>Requested</span><b class="mono">$50,000</b></div>
          </div>
          <button class="btn primary" id="btn-a" style="width:100%">Submit request</button>
          <div id="a-result"></div>
        </div>
      </div>`);
    $('#btn-a').addEventListener('click', doAccess);
    $('#a-email').addEventListener('keydown', (e) => e.key === 'Enter' && doAccess());
    $('#a-email').addEventListener('input', () => clearMsgs('#a-err', '#a-result'));
  };

  async function doAccess() {
    const email = $('#a-email').value.trim().toLowerCase();
    clearMsgs('#a-err', '#a-result');
    const err = $('#a-err');
    const btn = $('#btn-a'); btn.disabled = true; btn.textContent = 'Submitting…';
    const r = await api('POST', '/api/limits/request', { email });
    btn.disabled = false; btn.textContent = 'Submit request';

    const session = r.data.session;
    if (session) state.tokens.access = session;

    if (r.ok && r.data.unlocked === true && session) {
      const s = await api('GET', '/api/limits/status', null, session);
      if (s.data.panel) {
        const p = s.data.panel;
        $('#a-result').innerHTML = successCard('Request approved.', [
          ['Client', esc(p.name)],
          ['New allowance', `<span class="mono">${money(p.balance)}</span>`],
          ['Permits', esc(p.permits.join(', '))],
        ]);
      }
    } else if (session) {
      err.textContent = r.data.message || 'Your request is still under review.';
      err.style.display = 'block';
    } else {
      err.textContent = r.data.message || 'We couldn\'t process your request.';
      err.style.display = 'block';
    }
  }

  // ---------------------------------------------------------------
  // chrome / tooling
  // ---------------------------------------------------------------
  $('#inspector-toggle').addEventListener('click', () => {
    state.proxy = !state.proxy;
    $('#proxy-dot').classList.toggle('on', state.proxy);
    toast(state.proxy ? 'Interception armed.' : 'Interception off — responses pass through.', '');
  });

  $('#pl-close').addEventListener('click', () => $('#proxy-log').classList.add('hidden'));
  $('#pl-clear').addEventListener('click', () => { log.length = 0; renderLog(); });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'p' && (e.metaKey || e.ctrlKey)) { e.preventDefault(); $('#proxy-log').classList.toggle('hidden'); }
    if (e.key === 'Escape') { $('#interceptor').classList.add('hidden'); $('#proxy-log').classList.add('hidden'); }
  });

  document.querySelector('.brand').addEventListener('click', () => go('/'));

  // ---------------------------------------------------------------
  // boot
  // ---------------------------------------------------------------
  $('#proxy-dot').classList.toggle('on', state.proxy);
  handleRoute();
})();