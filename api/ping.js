import { ping } from '../lib/gate.js';

// Daily cron (vercel.json) so the free Supabase project never pauses before a live demo.
export default async function handler(req, res) {
  try {
    await ping();
    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error(err);
    return res.status(503).json({ ok: false });
  }
}
