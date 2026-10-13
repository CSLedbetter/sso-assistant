// Everything is rendered with textContent, so nothing pasted or returned can inject markup.
const $ = (id) => document.getElementById(id);
const state = { ticket: null };
const DEFAULT_SP = { entity_id: 'https://sso.example-sp.com/saml/conn_01NORTHWIND', acs_url: 'https://sso.example-sp.com/saml/conn_01NORTHWIND/acs', cert_fingerprint: '', client_id: '' };
const SP_FIELDS = { entity_id: 'sp-entity', acs_url: 'sp-acs', cert_fingerprint: 'sp-fp', client_id: 'sp-client' };

const el = (tag, props = {}) => Object.assign(document.createElement(tag), props);

// ---------- tickets ----------
function setSp(sp) { for (const [k, id] of Object.entries(SP_FIELDS)) $(id).value = sp?.[k] || ''; }
function getSp() { return Object.fromEntries(Object.entries(SP_FIELDS).map(([k, id]) => [k, $(id).value.trim()])); }

function ticketButton(t) {
  const b = el('button', { type: 'button', className: 'ticket' });
  b.setAttribute('aria-pressed', 'false');
  for (const [cls, text] of [['t-id', [t.id, t.plan, t.idp].filter(Boolean).join(' · ')], ['t-sub', t.subject], ['t-who', [t.from_name, t.company].filter(Boolean).join(', ')]]) {
    if (text) b.append(el('span', { className: cls, textContent: text }));
  }
  b.addEventListener('click', () => {
    document.querySelectorAll('.ticket').forEach((x) => x.setAttribute('aria-pressed', 'false'));
    b.setAttribute('aria-pressed', 'true');
    state.ticket = t;
    $('input').value = t.body;
    setSp(t.sp || DEFAULT_SP);
    $('ticket-chip').textContent = `${t.id}: ${t.subject}${t.source ? ` (from ${t.source})` : ''}`;
    $('ticket-chip').hidden = false;
    countChars();
    if (window.matchMedia('(max-width: 860px)').matches) $('input').scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
  return b;
}

async function loadQueue() {
  let tickets = [];
  try { tickets = await (await fetch('/tickets.json')).json(); } catch { /* empty queue */ }
  for (const t of tickets) { const li = el('li'); li.append(ticketButton(t)); $('tickets').append(li); }
}

// A ticket handed over from another tool arrives in the URL fragment, which never reaches the server.
function readHandoff() {
  const m = location.hash.match(/^#ticket=([A-Za-z0-9_-]+)$/);
  if (!m) return null;
  try {
    const bin = atob(m[1].replace(/-/g, '+').replace(/_/g, '/'));
    const t = JSON.parse(new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0))));
    const s = (v, n) => (typeof v === 'string' ? v.slice(0, n) : '');
    const ticket = { id: s(t.id, 40), subject: s(t.subject, 200), body: s(t.body, 20000), plan: s(t.plan, 40), from_name: s(t.from_name, 80), source: s(t.source, 40) || 'another tool' };
    return ticket.id && ticket.body ? ticket : null;
  } catch { return null; }
}

// ---------- run ----------
function countChars() { $('count').textContent = `${$('input').value.length.toLocaleString()} / 20,000`; updateButtons(); }
function updateButtons() {
  const has = $('input').value.trim().length >= 10;
  $('check-only').disabled = !has;
  const approved = Boolean(window.DemoAuth?.approved);
  $('explain').disabled = !approved || !has;
  $('explain').title = approved ? '' : 'Sign in and get approved to run live calls';
}
$('input').addEventListener('input', () => {
  if (state.ticket && $('input').value !== state.ticket.body) { state.ticket = null; $('ticket-chip').hidden = true; }
  countChars();
});
$('clear').addEventListener('click', () => {
  $('input').value = ''; state.ticket = null; $('ticket-chip').hidden = true; setSp(DEFAULT_SP);
  document.querySelectorAll('.ticket').forEach((x) => x.setAttribute('aria-pressed', 'false'));
  countChars(); $('input').focus();
});

async function post(path, signedIn) {
  const t = state.ticket;
  const headers = { 'content-type': 'application/json' };
  if (signedIn) headers.authorization = `Bearer ${window.DemoAuth.token()}`;
  const res = await fetch(path, {
    method: 'POST', headers,
    body: JSON.stringify({ input: $('input').value, sp: getSp(), ticket: t ? { id: t.id, subject: t.subject, plan: t.plan, idp: t.idp } : null }),
  });
  const body = await res.json().catch(() => ({ error: 'The server sent back something unexpected.' }));
  return { ok: res.ok, status: res.status, body };
}

function showLoading(msg) {
  const out = $('result');
  out.hidden = false; out.className = 'panel result loading';
  out.replaceChildren(el('p', { textContent: msg }));
}
function showError(msg, analysis) {
  const out = $('result');
  out.className = 'panel result';
  out.replaceChildren(el('p', { className: 'error', textContent: msg }));
  if (analysis) out.append(checksBlock(analysis));
}

$('check-only').addEventListener('click', async () => {
  showLoading('Decoding and checking…');
  try {
    const r = await post('/api/check', false);
    if (!r.ok) throw new Error(r.body.error || `Request failed (${r.status}).`);
    const out = $('result');
    out.className = 'panel result';
    out.replaceChildren(checksBlock(r.body.analysis));
  } catch (err) { showError(err.message); }
});

$('explain').addEventListener('click', async () => {
  showLoading('Running the checks, then asking Claude to explain…');
  $('explain').disabled = true;
  try {
    const r = await post('/api/diagnose', true);
    if (!r.ok) return showError(r.body.error || `Request failed (${r.status}).`, r.body.analysis);
    render(r.body);
    window.DemoAuth.afterCall(r.body.remaining_usd);
  } catch (err) { showError(err.message); } finally { updateButtons(); }
});

const KIND = { saml: 'SAML response', oidc_token: 'OIDC ID token', oidc_error: 'OIDC error from the IdP', scim_error: 'SCIM error', dns: 'DNS lookup', text: 'Ticket text only' };

function checksBlock(a) {
  const frag = $('tpl-checks').content.cloneNode(true);
  const f = (n) => frag.querySelector(`[data-f="${n}"]`);
  f('kind').textContent = `What code found: ${KIND[a.kind] || a.kind}${a.encoding ? ` (${a.encoding})` : ''}`;
  const order = { fail: 0, warn: 1, info: 2, pass: 3 };
  f('checks').replaceChildren(...[...a.checks].sort((x, y) => order[x.status] - order[y.status]).map((c) => {
    const li = el('li');
    const body = el('div');
    body.append(el('b', { textContent: c.title }), el('span', { className: 'd', textContent: c.detail }));
    li.append(el('span', { className: `st ${c.status}`, textContent: c.status.toUpperCase() }), body);
    return li;
  }));
  const rows = Object.entries(a.facts || {}).filter(([, v]) => v != null && v !== '' && !(Array.isArray(v) && !v.length));
  f('facts').replaceChildren(...rows.flatMap(([k, v]) => [
    el('dt', { textContent: k.replace(/_/g, ' ') }),
    el('dd', { textContent: typeof v === 'object' ? (Array.isArray(v) ? v.map((x) => (typeof x === 'object' ? JSON.stringify(x) : x)).join(', ') : JSON.stringify(v)) : String(v) }),
  ]));
  return frag;
}

function render(data) {
  const r = data.result;
  const out = $('result');
  out.className = 'panel result';
  out.replaceChildren($('tpl-result').content.cloneNode(true));
  const f = (n) => out.querySelector(`[data-f="${n}"]`);
  const list = (node, items) => node.replaceChildren(...items.map((x) => el('li', { textContent: x })));
  f('headline').textContent = r.headline;
  const side = { idp: 'Fix is in their identity provider', claude_settings: 'Fix is in their Claude SSO settings', dns: 'Fix is in their DNS', both: 'Fix spans more than one place', anthropic: 'Needs Anthropic', unclear: 'Side unclear' }[r.whose_side];
  const badges = [[side, r.whose_side], [`${r.confidence} confidence`, '']];
  if (r.escalate_to_engineering) badges.push(['Escalate', 'esc']);
  f('badges').replaceChildren(...badges.map(([t, c]) => el('span', { className: `badge ${c}`, textContent: t })));
  f('checks-slot').replaceWith(checksBlock(data.analysis));
  f('cause').textContent = r.likely_cause;
  f('affected').textContent = r.who_is_affected;
  list(f('evidence'), r.evidence);
  list(f('steps'), r.fix_steps);
  if (r.questions_for_customer.length) list(f('questions'), r.questions_for_customer); else f('questions-wrap').remove();
  f('docs').replaceChildren(...r.docs.map((d) => {
    const li = el('li');
    li.append(el('a', { href: d.url, textContent: d.title, target: '_blank', rel: 'noopener' }), el('span', { textContent: d.why }));
    return li;
  }));
  f('admin').textContent = r.admin_reply;
  f('exec').textContent = r.exec_summary;
  if (r.escalate_to_engineering) { f('escalate').hidden = false; f('escalation').textContent = r.escalation_note; }
  f('meta').textContent = `${data.model} · ${data.seconds} s · this run cost $${data.cost_usd.toFixed(4)}${data.redactions ? ` · removed ${data.redactions} secret${data.redactions > 1 ? 's' : ''}` : ''}`;
  out.querySelectorAll('.copy').forEach((b) => b.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(b.dataset.copy === 'admin' ? r.admin_reply : r.exec_summary); b.textContent = 'Copied'; } catch { b.textContent = 'Select and copy'; }
    setTimeout(() => { b.textContent = 'Copy'; }, 1800);
  }));
  out.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

(async function start() {
  setSp(DEFAULT_SP);
  await loadQueue();
  const h = readHandoff();
  if (h) {
    const label = el('p', { className: 'handoff-label', textContent: `Handed off from ${h.source}` });
    const ul = el('ul', { className: 'handoff' });
    const li = el('li'); const btn = ticketButton(h); li.append(btn); ul.append(li);
    $('handoff-slot').append(label, ul);
    btn.click();
  }
  window.DemoAuth?.onChange(updateButtons);
  countChars();
})();
