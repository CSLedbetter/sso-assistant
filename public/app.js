// Everything is rendered with textContent, so nothing pasted or returned can inject markup.
const $ = (id) => document.getElementById(id);
const state = { ticket: null };
const DEFAULT_SP = { entity_id: 'https://sso.example-sp.com/saml/conn_01NORTHWIND', acs_url: 'https://sso.example-sp.com/saml/conn_01NORTHWIND/acs', cert_fingerprint: '', client_id: '', rp_id: '', origin: '', challenge: '', passkey_policy: 'any' };
const SP_FIELDS = { entity_id: 'sp-entity', acs_url: 'sp-acs', cert_fingerprint: 'sp-fp', client_id: 'sp-client', rp_id: 'sp-rpid', origin: 'sp-origin', challenge: 'sp-challenge', passkey_policy: 'sp-policy' };

const el = (tag, props = {}) => Object.assign(document.createElement(tag), props);

// ---------- tickets ----------
function setSp(sp) { for (const [k, id] of Object.entries(SP_FIELDS)) $(id).value = sp?.[k] || DEFAULT_SP[k] || ''; }
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
    setSp({ ...DEFAULT_SP, ...(t.sp || {}) });
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
  let group = null;
  for (const t of tickets) {
    const g = t.kind === 'passkey' ? 'Passkey tickets' : 'SAML, OIDC, SCIM and DNS tickets';
    if (g !== group) { group = g; $('tickets').append(el('li', { className: 'queue-group', textContent: g })); }
    const li = el('li'); li.append(ticketButton(t)); $('tickets').append(li);
  }
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
  if (state.ticket && $('input').value !== state.ticket.body) state.ticket = null;
  if (!state.ticket) { $('ticket-chip').textContent = 'Your own input'; $('ticket-chip').hidden = !$('input').value.trim(); }
  countChars();
});
$('use-own').addEventListener('click', () => {
  $('clear').click();
  $('own').open = true;
  $('own').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  $('input').focus();
});
// Decode a sample's base64 SAML response into readable XML so a visitor can edit it and rerun the checks.
$('to-xml').addEventListener('click', async () => {
  let t = state.ticket && /PHNhbWxwOl/.test(state.ticket.body) ? state.ticket : null;
  if (!t) {
    const all = await (await fetch('/tickets.json')).json();
    t = all.find((x) => x.id === 'SSO-3013');
  }
  const blob = t.body.match(/[A-Za-z0-9+/=\n]{200,}/g).sort((a, b) => b.length - a.length)[0].replace(/\s+/g, '');
  const xml = new TextDecoder().decode(Uint8Array.from(atob(blob), (c) => c.charCodeAt(0)))
    .replace(/<ds:SignatureValue>[^<]+<\/ds:SignatureValue>/g, '<ds:SignatureValue>…</ds:SignatureValue>')
    .replace(/></g, '>\n<');
  setSp(t.sp || DEFAULT_SP);
  state.ticket = null;
  $('input').value = xml;
  $('ticket-chip').textContent = `Editable copy of ${t.id}. Change a value, then Run checks.`;
  $('ticket-chip').hidden = false;
  countChars();
  $('input').focus();
  $('input').scrollIntoView({ behavior: 'smooth', block: 'start' });
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

// The same input, SP settings and ticket always map to the same saved diagnosis.
const runKey = () => window.RunCache.key({ tool: 'sso', input: $('input').value, sp: getSp(), ticket: state.ticket?.id || null });

$('check-only').addEventListener('click', async () => {
  showLoading('Decoding and checking…');
  try {
    const r = await post('/api/check', false);
    if (!r.ok) throw new Error(r.body.error || `Request failed (${r.status}).`);
    const out = $('result');
    out.className = 'panel result';
    out.replaceChildren(checksBlock(r.body.analysis));
    const k = await runKey();
    const saved = window.RunCache.get(k);
    if (saved) {
      const note = el('p', { className: 'saved-note' });
      const show = el('button', { type: 'button', className: 'link', textContent: 'Show saved diagnosis' });
      show.addEventListener('click', () => render(saved.data, saved));
      note.append(el('span', { textContent: `You already have a Claude diagnosis for this exact input from ${window.RunCache.time(saved.savedAt)}. ` }), show);
      out.prepend(note);
    }
  } catch (err) { showError(err.message); }
});

let running = false;
async function explain(fresh) {
  if (running) return;
  const k = await runKey();
  const saved = !fresh && window.RunCache.get(k);
  if (saved) return render(saved.data, saved);
  running = true;
  showLoading('Running the checks, then asking Claude to explain…');
  $('explain').disabled = true;
  try {
    const r = await post('/api/diagnose', true);
    if (!r.ok) return showError(r.body.error || `Request failed (${r.status}).`, r.body.analysis);
    r.body.source = state.ticket ? `ticket ${state.ticket.id}` : 'your input';
    window.RunCache.put(k, r.body);
    render(r.body);
    window.DemoAuth.afterCall(r.body.remaining_usd);
  } catch (err) { showError(err.message); } finally { running = false; updateButtons(); }
}
$('explain').addEventListener('click', () => explain(false));

const KIND = { saml: 'SAML response', oidc_token: 'OIDC ID token', oidc_error: 'OIDC error from the IdP', scim_error: 'SCIM error', dns: 'DNS lookup', webauthn: 'Passkey (WebAuthn) response', webauthn_error: 'Browser passkey error', text: 'Ticket text only' };

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

function savedBanner(saved) {
  const box = el('div', { className: 'saved-note' });
  const again = el('button', { type: 'button', className: 'link', textContent: 'Run a fresh diagnosis' });
  again.disabled = !window.DemoAuth?.approved;
  again.addEventListener('click', () => explain(true));
  box.append(el('span', { textContent: `Saved diagnosis from ${window.RunCache.time(saved.savedAt)} for this exact input. No new Claude call, no cost. ` }), again);
  return box;
}

function render(data, saved) {
  const r = data.result;
  const out = $('result');
  out.hidden = false;
  out.className = 'panel result';
  out.replaceChildren($('tpl-result').content.cloneNode(true));
  if (saved) out.prepend(savedBanner(saved));
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
  const when = saved ? `Generated live at ${window.RunCache.time(saved.savedAt)}` : 'Generated live just now';
  f('meta').textContent = `${when} from ${data.source || 'your input'} by ${data.model} in ${data.seconds} s · Claude request ID ${data.claude_request_id || 'not returned'} · ${saved ? 'that run' : 'this run'} cost $${data.cost_usd.toFixed(4)}${data.redactions ? ` · removed ${data.redactions} secret${data.redactions > 1 ? 's' : ''}` : ''}`;
  out.querySelectorAll('.copy').forEach((b) => b.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(b.dataset.copy === 'admin' ? r.admin_reply : r.exec_summary); b.textContent = 'Copied'; } catch { b.textContent = 'Select and copy'; }
    setTimeout(() => { b.textContent = 'Copy'; }, 1800);
  }));
  out.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ---------- live passkey demo ----------
// The browser makes a throwaway passkey for this page; the checks then decode exactly what it sent back.
const pk = { created: null };
const bytesToB64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64urlToBytes = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n));

function credentialJson(cred) {
  if (typeof cred.toJSON === 'function') { try { return cred.toJSON(); } catch { /* fall through */ } }
  const r = cred.response;
  const out = { id: cred.id, rawId: bytesToB64url(cred.rawId), type: cred.type, authenticatorAttachment: cred.authenticatorAttachment ?? null, response: { clientDataJSON: bytesToB64url(r.clientDataJSON) }, clientExtensionResults: cred.getClientExtensionResults?.() || {} };
  if (r.attestationObject) {
    out.response.attestationObject = bytesToB64url(r.attestationObject);
    if (r.getTransports) out.response.transports = r.getTransports();
  } else {
    Object.assign(out.response, { authenticatorData: bytesToB64url(r.authenticatorData), signature: bytesToB64url(r.signature) });
    if (r.userHandle) out.response.userHandle = bytesToB64url(r.userHandle);
  }
  return out;
}

function showLive(text, chip, challenge) {
  state.ticket = null;
  document.querySelectorAll('.ticket').forEach((x) => x.setAttribute('aria-pressed', 'false'));
  $('input').value = text;
  setSp({ ...DEFAULT_SP, rp_id: location.hostname, origin: location.origin, challenge: challenge || '', passkey_policy: $('sp-policy').value });
  document.querySelector('details.sp').open = true;
  $('ticket-chip').textContent = chip;
  $('ticket-chip').hidden = false;
  countChars();
  $('check-only').click();
}

function pkStatus(msg) { $('pk-status').textContent = msg; }

async function createPasskey() {
  if (!window.PublicKeyCredential || !navigator.credentials?.create) return pkStatus('This browser doesn’t support passkeys.');
  const challenge = randomBytes(32);
  try {
    const cred = await navigator.credentials.create({ publicKey: {
      challenge,
      rp: { id: location.hostname, name: 'SSO Assistant demo' },
      user: { id: randomBytes(16), name: 'sso-assistant-demo', displayName: 'SSO Assistant demo' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -8 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { residentKey: 'discouraged', userVerification: 'preferred' },
      attestation: 'none',
      timeout: 120000,
    } });
    const json = credentialJson(cred);
    pk.created = { id: json.rawId || json.id, transports: json.response.transports || [] };
    $('pk-get').disabled = false;
    $('pk-remove').hidden = typeof PublicKeyCredential.signalUnknownCredential !== 'function';
    pkStatus('Created. The checks below show what your authenticator sent. Now try Sign in with it, or edit the RP ID or allowed origins above and run the checks again.');
    showLive(JSON.stringify(json, null, 2), 'Live passkey you just created on this page. Change a passkey setting above and run the checks again.', bytesToB64url(challenge));
  } catch (err) {
    pkStatus('The browser stopped it. The checks below explain the error, the same way they would for a customer.');
    showLive(`${err.name}: ${err.message}\n    at navigator.credentials.create (live demo on ${location.hostname})`, 'Live error from your browser while creating a passkey.');
  }
}

async function usePasskey() {
  if (!pk.created) return;
  const challenge = randomBytes(32);
  try {
    const cred = await navigator.credentials.get({ publicKey: {
      challenge,
      rpId: location.hostname,
      allowCredentials: [{ type: 'public-key', id: b64urlToBytes(pk.created.id), transports: pk.created.transports }],
      userVerification: 'preferred',
      timeout: 120000,
    } });
    pkStatus('Signed in with your test passkey. The response is a real signature over this page’s challenge.');
    showLive(JSON.stringify(credentialJson(cred), null, 2), 'Live sign-in with the passkey you just created. Change a passkey setting above and run the checks again.', bytesToB64url(challenge));
  } catch (err) {
    pkStatus('The browser stopped it. The checks below explain the error.');
    showLive(`${err.name}: ${err.message}\n    at navigator.credentials.get (live demo on ${location.hostname})`, 'Live error from your browser while signing in with a passkey.');
  }
}

async function removePasskey() {
  if (!pk.created) return;
  try {
    await PublicKeyCredential.signalUnknownCredential({ rpId: location.hostname, credentialId: pk.created.id });
    pkStatus('Asked your password manager to remove the test passkey. Some password managers ignore this; you can also delete it in their settings under this site’s name.');
    $('pk-remove').hidden = true;
  } catch { pkStatus('Your password manager didn’t accept the request. You can delete the passkey in its settings under this site’s name.'); }
}

$('pk-create').addEventListener('click', createPasskey);
$('pk-get').addEventListener('click', usePasskey);
$('pk-remove').addEventListener('click', removePasskey);
$('use-passkey').addEventListener('click', () => {
  $('own').open = true;
  $('passkey-recipe').scrollIntoView({ behavior: 'smooth', block: 'center' });
  $('pk-create').focus({ preventScroll: true });
});

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
