// Access codes and the shared spend cap. The rules live in Postgres
// (supabase/migrations/20261013200000_demo_access.sql); this file only calls them.

const TOOL = 'sso-assistant';

// Base prices in USD per million tokens (platform.claude.com/docs/en/about-claude/pricing, October 2026).
export const PRICES = {
  'claude-sonnet-5-5': { input: 2, output: 10, cacheWrite: 2.5, cacheRead: 0.1 },
  'claude-haiku-5-5': { input: 0.1, output: 0.5, cacheWrite: 0.125, cacheRead: 0.01 },
  'claude-opus-5-5': { input: 4, output: 20, cacheWrite: 5, cacheRead: 0.2 },
};

export const REASONS = {
  invalid_code: { status: 401, message: 'That access code isn’t valid or has been turned off.' },
  rate_limited: { status: 429, message: 'This code has hit its hourly request limit. Try again in a bit.' },
  code_cap: { status: 402, message: 'This code has used its full $5 budget.' },
  global_cap: { status: 402, message: 'The demo’s total $15 budget is used up.' },
  disabled: { status: 503, message: 'The live demo is turned off right now.' },
};

async function rpc(fn, args) {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) throw new Error('Supabase is not configured');
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

export function readCode(req) {
  const code = String(req.headers['x-access-code'] || '').trim();
  return /^[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}$/i.test(code) ? code.toLowerCase() : null;
}

export const checkCode = (code) => rpc('demo_check_code', { p_code: code });

export const begin = (code, maxCostUsd, ticketId) =>
  rpc('demo_begin', { p_code: code, p_tool: TOOL, p_max_cost_usd: round6(maxCostUsd), p_ticket_id: ticketId || null });

export const finish = (requestId, ok, costUsd, usage = {}, model = null) =>
  rpc('demo_finish', {
    p_request_id: requestId,
    p_ok: ok,
    p_cost_usd: round6(costUsd),
    p_model: model,
    p_input_tokens: usage.input_tokens ?? null,
    p_output_tokens: usage.output_tokens ?? null,
  });

export const ping = () => rpc('demo_ping', {});

// Worst case for one call: every input character as its own token would be far too pessimistic,
// so use 1 token per 3 characters (real English text averages closer to 4) plus the full output budget.
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
