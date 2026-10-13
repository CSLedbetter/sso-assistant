import { getUser, begin, finish, userStatus, maxCost, actualCost, REASONS, PRICES } from '../lib/gate.js';
import { analyze, detect, compactXml } from '../lib/analyze.js';
import { DOCS } from '../lib/docs.js';
import { callClaude, DEFAULT_MODEL } from '../lib/claude.js';
import { SYSTEM, SCHEMA, userMessage } from '../lib/prompt.js';

const MAX_INPUT = 20000; // a base64 SAML response with a certificate runs 8,000 to 12,000 characters
const MAX_TOKENS = 2500;

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Use POST.' });
  const body = typeof req.body === 'object' && req.body ? req.body : {};
  const raw = typeof body.input === 'string' ? body.input.trim() : '';
  if (raw.length < 10) return res.status(400).json({ error: 'Paste a SAML response, token, error, or ticket first.' });
  if (raw.length > MAX_INPUT) return res.status(400).json({ error: `Keep it under ${MAX_INPUT.toLocaleString()} characters.` });

  const ticket = cleanTicket(body.ticket);
  const sp = cleanSp(body.sp);
  const { text: input, redactions } = redact(raw);
  const analysis = analyze(input, sp);
  const forClaude = condense(input);
  const model = PRICES[process.env.CLAUDE_MODEL] ? process.env.CLAUDE_MODEL : DEFAULT_MODEL;
  const user = userMessage({ ticket, analysis, input: forClaude });
  const reserve = maxCost(model, SYSTEM.length + JSON.stringify(SCHEMA).length + user.length, MAX_TOKENS);

  let gate;
  try {
    const user = await getUser(req);
    if (!user) return res.status(401).json({ error: REASONS.not_signed_in.message, reason: 'not_signed_in', analysis });
    gate = { ...(await begin(user.id, reserve, ticket?.id)), user };
  } catch (err) {
    console.error(err);
    return res.status(503).json({ error: 'The demo’s access service is unavailable right now.' });
  }
  if (!gate?.ok) {
    const r = REASONS[gate?.reason] || REASONS.disabled;
    // The code checks are free, so still return them when the budget is the only problem.
    return res.status(r.status).json({ error: r.message, reason: gate?.reason, analysis });
  }

  const started = Date.now();
  try {
    const { data, usage, model: used, requestId } = await callClaude({ model, system: SYSTEM, user, schema: SCHEMA, maxTokens: MAX_TOKENS });
    const cost = actualCost(model, usage);
    await finish(gate.request_id, true, cost, usage, used).catch((e) => console.error(e));
    const after = await userStatus(gate.user.id).catch(() => null);
    data.docs = data.docs.map((d) => ({ ...d, title: DOCS.find((x) => x.url === d.url)?.title || d.url }));
    return res.status(200).json({
      analysis, redactions, result: data, model: used,
      cost_usd: Number(cost.toFixed(4)),
      seconds: Math.round((Date.now() - started) / 100) / 10,
      claude_request_id: requestId,
      remaining_usd: after?.remaining_usd ?? null,
    });
  } catch (err) {
    console.error(err);
    const cost = err.usage ? actualCost(model, err.usage) : err.reachedClaude === 'unknown' ? reserve : 0;
    await finish(gate.request_id, false, cost, err.usage || {}, model).catch((e) => console.error(e));
    return res.status(502).json({ error: `Couldn’t get an explanation: ${err.message}.`, analysis });
  }
}

// Send Claude the decoded XML without signatures and certificate bodies, and never a token's signature.
function condense(input) {
  const d = detect(input);
  if (d.kind === 'saml') {
    const blob = input.match(/[A-Za-z0-9+/=\r\n]{200,}/g)?.sort((a, b) => b.length - a.length)[0];
    const note = d.encoding === 'xml' ? input.slice(0, input.search(/<(?:[\w-]+:)?Response\b/i)) : (blob ? input.replace(blob, '\n[SAML response, decoded below]\n') : '');
    return `${note.trim()}\n\nDecoded SAML response:\n${compactXml(d.xml)}`.trim();
  }
  return input.replace(/(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.)[A-Za-z0-9_-]+/g, '$1[signature omitted]').slice(0, 8000);
}

function redact(text) {
  let count = 0;
  const clean = text
    .replace(/sk-ant-[A-Za-z0-9_-]{8,}/g, () => (count++, 'sk-ant-[REDACTED]'))
    .replace(/(client_secret|password|x-api-key|authorization)(["']?\s*[:=]\s*["']?)(?:Bearer\s+)?[^\s"'&,]{8,}/gi, (_, h, sep) => (count++, `${h}${sep}[REDACTED]`));
  return { text: clean, redactions: count };
}

function cleanTicket(t) {
  if (!t || typeof t !== 'object') return null;
  const s = (v, n) => (typeof v === 'string' ? v.slice(0, n) : '');
  const id = s(t.id, 40).replace(/[^\w-]/g, '');
  return id ? { id, subject: s(t.subject, 200), plan: s(t.plan, 40), idp: s(t.idp, 40) } : null;
}

function cleanSp(sp) {
  const out = {};
  if (!sp || typeof sp !== 'object') return out;
  for (const k of ['entity_id', 'acs_url', 'cert_fingerprint', 'client_id']) {
    if (typeof sp[k] === 'string' && sp[k].trim()) out[k] = sp[k].trim().slice(0, 300);
  }
  out.nameid = sp.nameid === 'any' ? 'any' : 'email';
  return out;
}
