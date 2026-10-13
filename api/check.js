import { analyze } from '../lib/analyze.js';

// The code-only checks. No Claude call and no cost, so no access code is needed.
export default function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Use POST.' });
  const body = typeof req.body === 'object' && req.body ? req.body : {};
  const input = typeof body.input === 'string' ? body.input.trim() : '';
  if (input.length < 10) return res.status(400).json({ error: 'Paste a SAML response, token, error, or ticket first.' });
  if (input.length > 20000) return res.status(400).json({ error: 'Keep it under 20,000 characters.' });
  const sp = {};
  for (const k of ['entity_id', 'acs_url', 'cert_fingerprint', 'client_id']) {
    if (typeof body.sp?.[k] === 'string' && body.sp[k].trim()) sp[k] = body.sp[k].trim().slice(0, 300);
  }
  return res.status(200).json({ analysis: analyze(input, sp) });
}
