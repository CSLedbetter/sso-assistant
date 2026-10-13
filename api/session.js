import { readCode, checkCode, REASONS } from '../lib/gate.js';

// Signs a visitor in: checks the code and returns whose it is and how much budget is left. Spends nothing.
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Use POST.' });
  const code = readCode(req);
  if (!code) return res.status(401).json({ error: REASONS.invalid_code.message });
  try {
    const r = await checkCode(code);
    if (!r?.ok) {
      const reason = REASONS[r?.reason] || REASONS.invalid_code;
      return res.status(reason.status).json({ error: reason.message, reason: r?.reason });
    }
    return res.status(200).json({ label: r.label, remaining_usd: r.remaining_usd });
  } catch (err) {
    console.error(err);
    return res.status(503).json({ error: 'The demo’s access service is unavailable right now.' });
  }
}
