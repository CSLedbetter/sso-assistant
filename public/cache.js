// Saves paid diagnoses in this browser tab, keyed by a SHA-256 hash of the exact input,
// so clicking the paid button again on the same input shows the saved result instead of
// making (and paying for) another Claude call. sessionStorage survives a reload but is
// cleared when the tab closes; the pasted input itself is never stored, only its hash.
(function () {
  const STORE = 'demo-run-cache';
  const MAX = 20;
  const mem = new Map();

  function load() {
    try { return JSON.parse(sessionStorage.getItem(STORE) || '{}'); } catch { return {}; }
  }
  function save(all) {
    try { sessionStorage.setItem(STORE, JSON.stringify(all)); } catch { /* storage full or blocked: memory copy still works */ }
  }

  async function key(parts) {
    const text = JSON.stringify(parts);
    try {
      const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
      return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
    } catch {
      return `raw:${text}`; // no WebCrypto (non-HTTPS preview): fall back to the text itself, memory only
    }
  }

  function get(k) {
    if (mem.has(k)) return mem.get(k);
    if (k.startsWith('raw:')) return null;
    return load()[k] || null;
  }

  function put(k, data) {
    const entry = { savedAt: Date.now(), data };
    mem.set(k, entry);
    if (k.startsWith('raw:')) return entry;
    const all = load();
    all[k] = entry;
    const keys = Object.keys(all).sort((a, b) => all[a].savedAt - all[b].savedAt);
    while (keys.length > MAX) delete all[keys.shift()];
    save(all);
    return entry;
  }

  function clear() {
    mem.clear();
    try { sessionStorage.removeItem(STORE); } catch { /* nothing to clear */ }
  }

  const time = (ms) => new Date(ms).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });

  window.RunCache = { key, get, put, clear, time };
})();
