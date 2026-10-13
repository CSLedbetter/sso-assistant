import { getUser, userStatus } from '../lib/gate.js';

// Tells the page who's signed in and whether they're approved. Spends nothing.
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Use POST.' });
  try {
    const user = await getUser(req);
    if (!user) return res.status(401).json({ status: 'signed_out' });
    const s = await userStatus(user.id);
    return res.status(200).json(s);
  } catch (err) {
    console.error(err);
    return res.status(503).json({ error: 'The demo’s access service is unavailable right now.' });
  }
}
