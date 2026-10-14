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
    'SSO-3014': ['rp_id'], 'SSO-3015': ['origin'], 'SSO-3016': ['uv'], 'SSO-3017': ['challenge'], 'SSO-3018': ['synced'],
    'SSO-3019': ['webauthn_error'], 'SSO-3020': ['webauthn_error'],
  };
  assert.equal(tickets.length, Object.keys(expect).length, 'every ticket has an expectation');
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

test('decodes passkey registration and sign-in data', () => {
  const reg = run('SSO-3016');
  assert.equal(reg.kind, 'webauthn');
  assert.equal(reg.facts.algorithm, 'ES256');
  assert.equal(reg.facts.attestation_format, 'none');
  assert.equal(reg.facts.user_verified, false);
  assert.equal(reg.facts.backup_eligible, false);
  const signIn = run('SSO-3017');
  assert.equal(signIn.facts.ceremony, 'sign-in (use a passkey)');
  assert.equal(signIn.facts.signature_present, true);
  assert.equal(signIn.facts.backed_up, true);
});

test('names the RP ID an orphaned passkey was made for', () => {
  const c = run('SSO-3014').checks.find((x) => x.id === 'rp_id');
  assert.match(c.detail, /created for “login\.northwind\.example”/);
});

test('passkey checks follow the settings, so a visitor can break a sample', () => {
  const t = tickets.find((x) => x.id === 'SSO-3017');
  assert.deepEqual(failed(analyze(t.body, { ...t.sp, challenge: undefined })), []);
  assert.deepEqual(failed(analyze(t.body, { ...t.sp, challenge: undefined, origin: 'https://id.stackmint-login.example' })), ['origin']);
  assert.deepEqual(failed(analyze(t.body, { ...t.sp, challenge: undefined, passkey_policy: 'device_bound' })), ['synced']);
  const reg = tickets.find((x) => x.id === 'SSO-3016');
  assert.deepEqual(failed(analyze(reg.body, { ...reg.sp, passkey_policy: 'any' })), []);
});

test('accepts standard base64 and a credential wrapped in another object', () => {
  const t = tickets.find((x) => x.id === 'SSO-3015');
  const cred = JSON.parse(t.body.slice(t.body.indexOf('{')));
  const std = (s) => Buffer.from(s, 'base64url').toString('base64');
  for (const k of ['clientDataJSON', 'authenticatorData', 'signature']) cred.response[k] = std(cred.response[k]);
  assert.deepEqual(failed(analyze(JSON.stringify({ credential: cred }), t.sp)), ['origin']);
});

test('explains browser passkey errors and when they happened', () => {
  assert.equal(run('SSO-3019').kind, 'webauthn_error');
  assert.deepEqual([run('SSO-3019').facts.error, run('SSO-3019').facts.during], ['NotAllowedError', 'sign-in']);
  assert.deepEqual([run('SSO-3020').facts.error, run('SSO-3020').facts.during], ['SecurityError', 'registration']);
});

test('reports unreadable passkey data instead of crashing', () => {
  const r = analyze('{"response":{"clientDataJSON":"not-json","authenticatorData":"AAAA"}}');
  assert.equal(r.kind, 'webauthn');
  assert.deepEqual(failed(r), ['decode']);
});
