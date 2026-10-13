// Sign-in for the live demo. Visitors sign in with Google (or an email link), start as "pending",
// and Casey approves them. The page only ever sends the Supabase access token; the server verifies it.
(function () {
  const cfg = window.DEMO_CONFIG;
  const $ = (id) => document.getElementById(id);
  const el = (tag, props = {}) => Object.assign(document.createElement(tag), props);
  const listeners = [];
  const state = { session: null, status: null };

  // Keep a handed-off ticket (in the URL fragment) across the Google round trip.
  const HANDOFF = 'demo-handoff';
  try {
    if (/^#ticket=/.test(location.hash)) sessionStorage.setItem(HANDOFF, location.hash);
    else if (!location.hash && sessionStorage.getItem(HANDOFF) && /[?&]code=/.test(location.search)) {
      history.replaceState(null, '', location.pathname + sessionStorage.getItem(HANDOFF));
    }
  } catch { /* storage blocked: the handoff just won't survive sign-in */ }

  const client = window.supabase.createClient(cfg.supabaseUrl, cfg.supabaseKey, {
    auth: { flowType: 'pkce', persistSession: true, detectSessionInUrl: true },
  });
  const back = () => location.origin + location.pathname;

  async function refresh() {
    const { data } = await client.auth.getSession();
    state.session = data.session;
    state.status = null;
    if (state.session) {
      try {
        const res = await fetch('/api/session', { method: 'POST', headers: { authorization: `Bearer ${state.session.access_token}` } });
        state.status = await res.json();
        if (res.status === 401) state.status = { status: 'signed_out' };
      } catch { state.status = { status: 'error' }; }
      // The sign-in round trip is done; drop ?code= from the address bar and keep any handoff.
      if (/[?&]code=/.test(location.search)) history.replaceState(null, '', location.pathname + location.hash);
    }
    render();
    listeners.forEach((fn) => fn(api));
  }

  function render() {
    const box = $('auth');
    if (!box) return;
    const s = state.status?.status;
    if (!state.session || s === 'signed_out') return box.replaceChildren(...signedOut());
    const who = state.status?.name || state.status?.email || state.session.user.email;
    const line = el('div', { className: 'signed-in' });
    const dot = el('span', { className: `dot ${s === 'approved' ? '' : 'wait'}` });
    line.append(dot, el('span', { textContent: `Signed in as ${who}` }));
    if (s === 'approved') line.append(el('span', { className: 'muted', textContent: `$${Number(state.status.remaining_usd).toFixed(2)} of budget left` }));
    if (state.status?.is_admin && cfg.adminUrl) line.append(el('a', { href: cfg.adminUrl, textContent: 'Manage access' }));
    const out = el('button', { type: 'button', className: 'link', textContent: 'Sign out' });
    out.addEventListener('click', async () => { window.RunCache?.clear(); await client.auth.signOut(); refresh(); });
    line.append(out);
    const parts = [line];
    const msg = {
      pending: 'Thanks for signing in. Casey approves each person by hand, usually the same day. Once you’re approved, reload this page and the live buttons will work.',
      revoked: 'Your access to the live demo has been turned off.',
      disabled: 'The live demo is turned off right now.',
      error: 'Couldn’t check your access. Try reloading.',
      unknown: 'Your sign-in is still being set up. Reload in a moment.',
    }[s];
    if (msg) parts.push(el('p', { className: s === 'pending' ? 'note' : 'error', textContent: msg }));
    box.replaceChildren(...parts);
  }

  function signedOut() {
    const head = el('div', { className: 'auth-head' });
    head.append(el('b', { textContent: 'Sign in to run live calls' }),
      el('span', { className: 'muted small', textContent: 'Live calls to Claude cost money, so Casey approves each person. You can look around without signing in.' }));
    const row = el('div', { className: 'auth-row' });
    const google = el('button', { type: 'button', className: 'google', textContent: 'Continue with Google' });
    google.addEventListener('click', () => client.auth.signInWithOAuth({ provider: 'google', options: { redirectTo: back() } }));
    row.append(google);
    const parts = [head, row];
    if (cfg.emailSignIn) {
      const form = el('form', { className: 'email-form' });
      const input = el('input', { type: 'email', required: true, placeholder: 'you@company.com', autocomplete: 'email' });
      input.setAttribute('aria-label', 'Email address');
      const send = el('button', { type: 'submit', textContent: 'Email me a sign-in link' });
      const sent = el('p', { className: 'muted small', hidden: true });
      form.append(input, send);
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        send.disabled = true;
        const { error } = await client.auth.signInWithOtp({ email: input.value.trim(), options: { emailRedirectTo: back() } });
        sent.hidden = false;
        sent.textContent = error ? `Couldn’t send the link: ${error.message}` : 'Check your inbox for the sign-in link.';
        send.disabled = false;
      });
      row.append(el('span', { className: 'muted small', textContent: 'or' }), form);
      parts.push(sent);
    }
    parts.push(el('p', { className: 'muted small', textContent: 'Signing in shares your name and email with Casey Ledbetter, who may follow up with you about this demo. They aren’t shared with anyone else.' }));
    return parts;
  }

  const api = {
    get approved() { return state.status?.status === 'approved'; },
    get status() { return state.status; },
    token() { return state.session?.access_token || null; },
    onChange(fn) { listeners.push(fn); fn(api); },
    async afterCall(remaining) {
      if (remaining != null && state.status) { state.status.remaining_usd = remaining; render(); }
    },
    client,
  };
  window.DemoAuth = api;
  client.auth.onAuthStateChange((event) => { if (event === 'SIGNED_IN' || event === 'SIGNED_OUT' || event === 'TOKEN_REFRESHED') refresh(); });
  refresh();
})();
