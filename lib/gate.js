// Who's allowed to spend, and how much. Visitors sign in with Supabase Auth (Google or an email link),
// start as "pending", and Casey approves them. The spending rules live in Postgres
// (supabase/migrations/); this file verifies the visitor's token and calls those rules.

const TOOL = 'sso-assistant';

// Base prices in USD per million tokens (platform.claude.com/docs/en/about-claude/pricing, October 2026).
export const PRICES = {
  'claude-sonnet-5-5': { input: 2, output: 10, cacheWrite: 2.5, cacheRead: 0.1 },
  'claude-haiku-5-5': { input: 0.1, output: 0.5, cacheWrite: 0.125, cacheRead: 0.01 },
  'claude-opus-5-5': { input: 4, output: 20, cacheWrite: 5, cacheRead: 0.2 },
};

export const REASONS = {
  not_signed_in: { status: 401, message: 'Sign in to run live calls.' },
  pending: { status: 403, message: 'You’re signed in. Casey still needs to approve your access.' },
  revoked: { status: 403, message: 'Your access to the live demo has been turned off.' },
  rate_limited: { status: 429, message: 'You’ve hit the hourly request limit. Try again in a bit.' },
  user_cap: { status: 402, message: 'You’ve used your full $5 budget for the demo.' },
  global_cap: { status: 402, message: 'The demo’s total $15 budget is used up.' },
  disabled: { status: 503, message: 'The live demo is turned off right now.' },
};

function config() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) throw new Error('Supabase is not configured');
  return { url, key };
}

async function rpc(fn, args) {
  const { url, key } = config();
  const res = await fetch(`${url}/rest/v1/rpc/${fn}`, {
    method: 'POST',
    headers: { apikey: key, Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(args),
    signal: AbortSignal.timeout(8000),
  });
  if (!res.ok) throw new Error(`Supabase ${fn} failed with ${res.status}`);
  const text = await res.text();
  return text ? JSON.parse(text) : null;
}

// Verify the visitor's Supabase access token with Supabase itself. Returns { id, email } or null.
// The user ID always comes from here, never from the request body.
export async function getUser(req) {
  const m = String(req.headers.authorization || '').match(/^Bearer\s+([A-Za-z0-9._-]{20,})$/);
  if (!m) return null;
  const { url, key } = config();
  const res = await fetch(`${url}/auth/v1/user`, {
    headers: { apikey: key, Authorization: `Bearer ${m[1]}` },
    signal: AbortSignal.timeout(8000),
  });
  if (!res.ok) return null;
  const u = await res.json();
  return u?.id ? { id: u.id, email: (u.email || '').toLowerCase() } : null;
}

export const userStatus = (userId) => rpc('demo_user_status', { p_user_id: userId });

export const begin = (userId, maxCostUsd, ticketId) =>
  rpc('demo_begin_user', { p_user_id: userId, p_tool: TOOL, p_max_cost_usd: round6(maxCostUsd), p_ticket_id: ticketId || null });

export const finish = (requestId, ok, costUsd, usage = {}, model = null) =>
  rpc('demo_finish_call', {
    p_request_id: requestId,
    p_ok: ok,
    p_cost_usd: round6(costUsd),
    p_model: model,
    p_input_tokens: usage.input_tokens ?? null,
    p_output_tokens: usage.output_tokens ?? null,
  });

export const adminList = () => rpc('demo_admin_list', {});
export const adminSet = (userId, status, capUsd) => rpc('demo_admin_set', { p_user_id: userId, p_status: status, p_cap_usd: capUsd ?? null });
export const adminToggle = (enabled) => rpc('demo_admin_toggle', { p_enabled: enabled });
export const ping = () => rpc('demo_ping', {});

export function isAdmin(user) {
  const admin = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  return Boolean(admin && user?.email && user.email === admin);
}

// Worst case for one call: 1 token per 3 characters of input (real text averages closer to 4) plus the full output budget.
export function maxCost(model, inputChars, maxTokens) {
  const p = PRICES[model];
  return (Math.ceil(inputChars / 3) * p.input + maxTokens * p.output) / 1e6;
}

export function actualCost(model, usage) {
  const p = PRICES[model];
  if (!usage) return 0;
  return (
    (usage.input_tokens || 0) * p.input +
    (usage.output_tokens || 0) * p.output +
    (usage.cache_creation_input_tokens || 0) * p.cacheWrite +
    (usage.cache_read_input_tokens || 0) * p.cacheRead
  ) / 1e6;
}

const round6 = (n) => Math.round(n * 1e6) / 1e6;
