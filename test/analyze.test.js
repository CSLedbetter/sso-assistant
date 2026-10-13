import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { analyze } from '../lib/analyze.js';

const tickets = JSON.parse(readFileSync(new URL('../public/tickets.json', import.meta.url)));
const run = (id) => { const t = tickets.find((x) => x.id === id); return analyze(t.body, t.sp); };
const failed = (r) => r.checks.filter((c) => c.status === 'fail').map((c) => c.id);

test('each sample ticket fails exactly the check it was built to fail', () => {
  const expect = {
    'SSO-3001': ['audience'], 'SSO-3002': ['acs'], 'SSO-3003': ['cert_expiry'], 'SSO-3004': ['cert_match'],
    'SSO-3005': ['clock'], 'SSO-3006': ['nameid'], 'SSO-3007': ['status'], 'SSO-3008': ['signature'],
    'SSO-3009': ['secret'], 'SSO-3010': ['aud'], 'SSO-3011': ['dns'], 'SSO-3012': [], 'SSO-3013': [],
  };
  for (const [id, fails] of Object.entries(expect)) assert.deepEqual(failed(run(id)), fails, id);
});

test('detects what kind of thing was pasted', () => {
  assert.equal(run('SSO-3001').kind, 'saml');
  assert.equal(run('SSO-3001').encoding, 'base64');
  assert.equal(run('SSO-3009').kind, 'oidc_error');
  assert.equal(run('SSO-3010').kind, 'oidc_token');
  assert.equal(run('SSO-3011').kind, 'dns');
  assert.equal(run('SSO-3012').kind, 'text');
});

test('reads the certificate from the response', () => {
  const c = run('SSO-3003').facts.certificate;
  assert.match(c.valid_to, /^2026-10-05/);
  assert.match(c.sha256_fingerprint, /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
});

test('accepts raw XML and URL-encoded base64 too', () => {
  const t = tickets.find((x) => x.id === 'SSO-3001');
  const b64 = t.body.split('\n\n').slice(1).join('').replace(/\n/g, '');
  const xml = Buffer.from(b64, 'base64').toString('utf8');
  assert.deepEqual(failed(analyze(xml, t.sp)), ['audience']);
  assert.deepEqual(failed(analyze(`SAMLResponse=${encodeURIComponent(b64)}`, t.sp)), ['audience']);
});
