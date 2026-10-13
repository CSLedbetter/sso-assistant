import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import handler from '../api/diagnose.js';

process.env.SUPABASE_URL = 'https://example.supabase.co';
process.env.SUPABASE_SECRET_KEY = 'test';
process.env.ANTHROPIC_API_KEY = 'test';
const tickets = JSON.parse(readFileSync(new URL('../public/tickets.json', import.meta.url)));
const RESULT = {
  headline: 'Audience mismatch', whose_side: 'idp', confidence: 'high', likely_cause: 'x', evidence: ['a'], fix_steps: ['b'],
  who_is_affected: 'Everyone', docs: [{ url: 'https://support.claude.com/en/articles/13132885-set-up-single-sign-on-sso', why: 'setup' }],
  questions_for_customer: [], admin_reply: 'hi', exec_summary: 'ok', escalate_to_engineering: false, escalation_note: '',
};
let calls, gateReply;
beforeEach(() => {
  calls = [];
  gateReply = { ok: true, request_id: 3, label: 'Tester' };
  globalThis.fetch = async (url, opts) => {
    const body = opts.body ? JSON.parse(opts.body) : null;
    calls.push({ url, body });
    const json = (d, s = 200) => new Response(d === null ? '' : JSON.stringify(d), { status: s });
    if (url.endsWith('/rpc/demo_begin')) return json(gateReply);
    if (url.endsWith('/rpc/demo_finish')) return json(null);
    if (url.endsWith('/rpc/demo_check_code')) return json({ ok: true, remaining_usd: 4.9 });
    if (url.includes('api.anthropic.com')) return json({ stop_reason: 'end_turn', model: 'claude-sonnet-5-5', usage: { input_tokens: 4000, output_tokens: 600 }, content: [{ type: 'text', text: JSON.stringify(RESULT) }] });
    throw new Error(url);
  };
});
const run = (body, code = '1a2b-3c4d-5e6f-7a8b') => new Promise((resolve) => {
  const res = { statusCode: 200, status(c) { this.statusCode = c; return this; }, json(d) { resolve({ status: this.statusCode, body: d }); } };
  handler({ method: 'POST', headers: code ? { 'x-access-code': code } : {}, body }, res);
});

test('sends Claude the decoded XML without signatures or certificate bodies, and records the ticket', async () => {
  const t = tickets[0];
  const r = await run({ input: t.body, sp: t.sp, ticket: t });
  assert.equal(r.status, 200);
  const sent = calls.find((c) => c.url.includes('anthropic')).body.messages[0].content;
  assert.match(sent, /Decoded SAML response/);
  assert.match(sent, /\[FAIL\] Audience doesn’t match/);
  assert.doesNotMatch(sent, /MII[A-Za-z0-9+/]{100}/); // no certificate body
  assert.ok(sent.length < 12000, `sent ${sent.length} chars`);
  assert.equal(calls.find((c) => c.url.endsWith('/rpc/demo_begin')).body.p_tool, 'sso-assistant');
  assert.equal(calls.find((c) => c.url.endsWith('/rpc/demo_begin')).body.p_ticket_id, 'SSO-3001');
  assert.equal(calls.find((c) => c.url.endsWith('/rpc/demo_finish')).body.p_cost_usd, 0.014);
});

test('still returns the free checks when the budget is used up', async () => {
  gateReply = { ok: false, reason: 'code_cap' };
  const r = await run({ input: tickets[2].body, sp: tickets[2].sp });
  assert.equal(r.status, 402);
  assert.ok(r.body.analysis.checks.some((c) => c.id === 'cert_expiry' && c.status === 'fail'));
  assert.ok(!calls.some((c) => c.url.includes('anthropic')));
});

test('removes client secrets and token signatures before calling Claude', async () => {
  const token = tickets.find((x) => x.id === 'SSO-3010').body.match(/eyJ\S+/)[0];
  await run({ input: `client_secret=abcDEF123456789xyz and token ${token}`, sp: { client_id: 'x' } });
  const sent = calls.find((c) => c.url.includes('anthropic')).body.messages[0].content;
  assert.doesNotMatch(sent, /abcDEF123456789xyz/);
  assert.match(sent, /\[signature omitted\]/);
});
