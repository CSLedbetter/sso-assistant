// Deterministic passkey (WebAuthn) checks. Like the SAML checks, these run with code before Claude reads anything.
// Input is a PublicKeyCredential as JSON (what credential.toJSON() returns), or a browser error such as NotAllowedError.
import { createHash } from 'node:crypto';

const check = (id, status, title, detail) => ({ id, status, title, detail });
const sha256hex = (s) => createHash('sha256').update(s).digest('hex');
const b64 = (s) => Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
const b64url = (buf) => Buffer.from(buf).toString('base64url');
const normB64url = (s) => (s ? b64url(b64(s)) : '');

const ALGS = { '-7': 'ES256', '-8': 'EdDSA', '-35': 'ES384', '-36': 'ES512', '-257': 'RS256', '-37': 'PS256' };
export const POLICIES = ['any', 'uv', 'device_bound'];
const ERRORS = /\b(NotAllowedError|InvalidStateError|SecurityError|NotSupportedError|AbortError|ConstraintError)\b/;

// ---------- detection ----------
export function findCredential(input) {
  if (!/clientDataJSON/.test(input)) return null;
  const s = input.indexOf('{'), e = input.lastIndexOf('}');
  if (s < 0 || e < s) return null;
  try {
    const j = JSON.parse(input.slice(s, e + 1));
    const c = j.credential || j; // tolerate { credential: {...} } wrappers
    return c?.response?.clientDataJSON ? c : null;
  } catch { return null; }
}
export const findBrowserError = (input) => input.match(ERRORS)?.[1] || null;

// ---------- a small CBOR reader (enough for attestation objects and COSE keys) ----------
export function cbor(buf) {
  let i = 0;
  const len = (info) => {
    if (info < 24) return info;
    if (info === 24) return buf[i++];
    if (info === 25) { const v = buf.readUInt16BE(i); i += 2; return v; }
    if (info === 26) { const v = buf.readUInt32BE(i); i += 4; return v; }
    if (info === 27) { const v = Number(buf.readBigUInt64BE(i)); i += 8; return v; }
    throw new Error('Unsupported CBOR length');
  };
  const item = () => {
    const b = buf[i++];
    if (b === undefined) throw new Error('CBOR ran out of bytes');
    const major = b >> 5, info = b & 31;
    if (major === 0) return len(info);
    if (major === 1) return -1 - len(info);
    if (major === 2) { const n = len(info); const v = buf.subarray(i, i + n); i += n; return v; }
    if (major === 3) { const n = len(info); const v = buf.subarray(i, i + n).toString('utf8'); i += n; return v; }
    if (major === 4) { const n = len(info); return Array.from({ length: n }, item); }
    if (major === 5) { const n = len(info); const m = new Map(); for (let k = 0; k < n; k++) { const key = item(); m.set(key, item()); } return m; }
    if (major === 7) return { 20: false, 21: true, 22: null }[info] ?? undefined;
    throw new Error(`Unsupported CBOR type ${major}`);
  };
  const value = item();
  return { value, used: i };
}

// ---------- authenticator data ----------
export function parseAuthData(buf) {
  if (buf.length < 37) throw new Error('Authenticator data is too short');
  const flagsByte = buf[32];
  const flags = {
    user_present: Boolean(flagsByte & 0x01),
    user_verified: Boolean(flagsByte & 0x04),
    backup_eligible: Boolean(flagsByte & 0x08),
    backed_up: Boolean(flagsByte & 0x10),
    attested_credential: Boolean(flagsByte & 0x40),
    extensions: Boolean(flagsByte & 0x80),
  };
  const out = { rp_id_hash: buf.subarray(0, 32).toString('hex'), flags, sign_count: buf.readUInt32BE(33) };
  if (flags.attested_credential && buf.length >= 55) {
    const aaguid = buf.subarray(37, 53).toString('hex');
    const idLen = buf.readUInt16BE(53);
    const credId = buf.subarray(55, 55 + idLen);
    const key = cbor(buf.subarray(55 + idLen)).value;
    out.aaguid = aaguid.replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');
    out.credential_id = b64url(credId);
    out.cose_alg = key instanceof Map ? key.get(3) : undefined;
  }
  return out;
}

// ---------- the checks ----------
export function analyzeWebauthn(cred, sp = {}) {
  const checks = [];
  const r = cred.response || {};
  let client, auth, attFmt = null;
  try {
    client = JSON.parse(b64(r.clientDataJSON).toString('utf8'));
    if (r.attestationObject) {
      const att = cbor(b64(r.attestationObject)).value;
      attFmt = att.get('fmt');
      auth = parseAuthData(Buffer.from(att.get('authData')));
    } else if (r.authenticatorData) {
      auth = parseAuthData(b64(r.authenticatorData));
    } else throw new Error('No attestationObject or authenticatorData');
  } catch (err) {
    return { kind: 'webauthn', facts: {}, checks: [check('decode', 'fail', 'Couldn’t decode the passkey data', `${err.message}. Paste the whole credential as JSON (credential.toJSON() in the browser console).`)] };
  }

  const registration = Boolean(r.attestationObject);
  const shortId = (s) => (s && s.length > 24 ? `${s.slice(0, 12)}…${s.slice(-6)}` : s);
  const facts = {
    ceremony: registration ? 'registration (create a passkey)' : 'sign-in (use a passkey)',
    credential_id: shortId(cred.id || auth.credential_id),
    client_data_type: client.type,
    origin: client.origin,
    cross_origin: client.crossOrigin ?? false,
    challenge: client.challenge,
    rp_id_hash: auth.rp_id_hash,
    user_present: auth.flags.user_present,
    user_verified: auth.flags.user_verified,
    backup_eligible: auth.flags.backup_eligible,
    backed_up: auth.flags.backed_up,
    sign_count: auth.sign_count,
    authenticator_attachment: cred.authenticatorAttachment || null,
    transports: r.transports || null,
  };
  if (registration) Object.assign(facts, { attestation_format: attFmt, aaguid: auth.aaguid, algorithm: ALGS[String(auth.cose_alg)] || (auth.cose_alg ?? null) });
  if (!registration) facts.signature_present = Boolean(r.signature);

  // Ceremony type
  const wantType = registration ? 'webauthn.create' : 'webauthn.get';
  checks.push(client.type === wantType
    ? check('ceremony', 'pass', registration ? 'Registration data' : 'Sign-in data', `clientDataJSON type is ${client.type}.`)
    : check('ceremony', 'fail', 'Ceremony type doesn’t match the data', `clientDataJSON says “${client.type}” but this looks like ${registration ? 'a registration' : 'a sign-in'}, which should say ${wantType}.`));

  // Origin: the phishing-resistance check
  let originHost = null;
  try { originHost = new URL(client.origin).hostname; } catch { /* checked below */ }
  const local = originHost === 'localhost' || originHost?.endsWith('.localhost');
  if (!originHost || (!client.origin.startsWith('https://') && !local)) {
    checks.push(check('origin', 'fail', 'Origin isn’t an HTTPS site', `The browser recorded “${client.origin}”. Passkeys only work on HTTPS pages (or localhost).`));
  } else if (sp.origin) {
    const allowed = sp.origin.split(/[\s,]+/).filter(Boolean).map((o) => o.replace(/\/+$/, ''));
    checks.push(allowed.includes(client.origin)
      ? check('origin', 'pass', 'Origin matches', `The browser recorded ${client.origin}, which the relying party expects.`)
      : check('origin', 'fail', 'Origin isn’t one the relying party expects', `The browser recorded “${client.origin}” but the relying party only accepts ${allowed.join(', ')}. If that’s a domain the customer owns (a new login page, a custom domain), add it to the allowed origins. If it isn’t, this is what a look-alike phishing page produces, and rejecting it is the point: the browser writes the real origin into data the passkey signs.`));
  }
  if (client.crossOrigin) checks.push(check('cross_origin', 'warn', 'Created inside a cross-origin iframe', 'crossOrigin is true. Most relying parties reject this unless they embed sign-in on purpose.'));

  // RP ID: the passkey is bound to this domain
  if (sp.rp_id) {
    const want = sp.rp_id.trim().toLowerCase();
    if (sha256hex(want) === auth.rp_id_hash) {
      checks.push(check('rp_id', 'pass', 'RP ID matches', `The passkey is bound to ${want}.`));
      if (originHost && originHost !== want && !originHost.endsWith(`.${want}`)) checks.push(check('rp_scope', 'fail', 'RP ID doesn’t cover the origin', `${want} isn’t ${originHost} or a parent domain of it, so browsers won’t allow this pairing.`));
    } else {
      const candidates = new Set([originHost, `www.${want}`, want.replace(/^[^.]+\./, '')]);
      if (originHost) { const parts = originHost.split('.'); for (let k = 0; k < parts.length - 1; k++) candidates.add(parts.slice(k).join('.')); }
      const actual = [...candidates].filter(Boolean).find((c) => sha256hex(c) === auth.rp_id_hash);
      checks.push(check('rp_id', 'fail', 'Passkey belongs to a different RP ID', actual
        ? `It was created for “${actual}”, but the relying party now uses “${want}”. A passkey only works for the RP ID it was made for, so after a domain change users must register new passkeys. A passkey made for a parent domain works on its subdomains, but not the other way around.`
        : `Its RP ID hash doesn’t match “${want}”. The passkey was made for another domain, so it can’t sign in here. Ask which domain the user registered it on.`));
    }
  }

  // Challenge: proves this response answers the request the server just made
  if (sp.challenge) {
    checks.push(normB64url(sp.challenge) === normB64url(client.challenge)
      ? check('challenge', 'pass', 'Challenge matches', 'The response answers the challenge the server issued.')
      : check('challenge', 'fail', 'Challenge doesn’t match', 'The response answers a different challenge than the one the server expects. Usually a stale page: a second tab, the back button, or a sign-in page left open until the server issued a new challenge. It can also be a replayed response. Reload and try again.'));
  }

  // Flags
  const f = auth.flags;
  if (!f.user_present) checks.push(check('up', 'fail', 'User presence flag not set', 'The authenticator didn’t confirm a person was there. Relying parties reject this.'));
  const policy = POLICIES.includes(sp.passkey_policy) ? sp.passkey_policy : 'any';
  if (f.user_verified) checks.push(check('uv', 'pass', 'User verified', 'The authenticator checked a PIN, fingerprint or face, so the passkey counts as two factors.'));
  else if (policy !== 'any') checks.push(check('uv', 'fail', 'User wasn’t verified, but policy requires it', 'The authenticator confirmed presence (a tap) but no PIN or biometric. Policies that treat passkeys as phishing-resistant MFA require verification. Set userVerification to "required" in the request, and make sure the authenticator has a PIN or biometric set up.'));
  else checks.push(check('uv', 'info', 'User presence only', 'No PIN or biometric was checked. Fine as a second factor; not enough where passkeys replace passwords and MFA.'));
  if (f.backed_up && !f.backup_eligible) checks.push(check('flags', 'fail', 'Flags contradict each other', 'Backed up is set but backup eligible isn’t. Valid authenticators never send this.'));
  else if (policy === 'device_bound' && f.backup_eligible) checks.push(check('synced', 'fail', 'Synced passkey, but policy requires device-bound', 'This passkey can sync through a password manager (iCloud Keychain, Google Password Manager and similar), so it isn’t tied to one device. Policies that require device-bound credentials reject it. The user needs a hardware security key or a platform authenticator that keeps the key on the device.'));
  else checks.push(check('sync', 'info', f.backup_eligible ? `Synced passkey${f.backed_up ? ', backed up' : ''}` : 'Device-bound passkey', f.backup_eligible ? 'It can copy to the user’s other devices through their password manager.' : 'It stays on one authenticator, such as a security key.'));

  // Registration details
  if (registration) {
    const alg = ALGS[String(auth.cose_alg)];
    checks.push(alg ? check('alg', 'pass', `Key algorithm ${alg}`, 'A standard WebAuthn algorithm.') : check('alg', 'warn', 'Unusual key algorithm', `COSE algorithm ${auth.cose_alg}. Make sure the server supports it.`));
    checks.push(check('attestation', 'info', `Attestation: ${attFmt || 'unknown'}`, attFmt === 'none' || /^0{8}-/.test(auth.aaguid || '')
      ? 'The authenticator didn’t identify its make and model. That’s normal for consumer passkeys; policies that allow only specific security keys need attestation.'
      : `AAGUID ${auth.aaguid} identifies the authenticator model.`));
  } else {
    checks.push(r.signature
      ? check('signature', 'pass', 'Signature present', 'Verifying it needs the public key the server saved at registration; this demo checks presence only.')
      : check('signature', 'fail', 'No signature', 'A sign-in response must include a signature.'));
    if (auth.sign_count === 0) checks.push(check('counter', 'info', 'Signature counter is 0', 'Synced passkeys usually report 0, so the counter can’t help detect a cloned key. That’s expected.'));
  }
  return { kind: 'webauthn', facts, checks };
}

const ERROR_HELP = {
  NotAllowedError: ['The ceremony was cancelled, timed out, or found no passkey', 'The user closed the prompt, it timed out, or (when signing in) no passkey on this device or password manager belongs to this site. Browsers keep this error vague on purpose so a site can’t probe which passkeys exist. Ask whether they saw a prompt, and which device and browser they registered on.'],
  InvalidStateError: ['This authenticator already has a passkey for this account', 'The server listed an existing credential in excludeCredentials and this authenticator holds it. The user can sign in with the passkey they already have, or remove it before registering again.'],
  SecurityError: ['RP ID isn’t valid for this page', 'The request’s RP ID must be the page’s own domain or a parent of it, on HTTPS. For example a page on example.com can’t ask for login.example.com. Check the rpId the server sends against the address in the browser.'],
  NotSupportedError: ['Requested options aren’t supported', 'None of the requested key algorithms or authenticator options are supported by this browser and authenticator. Offering ES256 (-7) and RS256 (-257) covers nearly every authenticator.'],
  AbortError: ['The page cancelled the request', 'The site aborted the ceremony, often because a second request started or the user navigated away.'],
  ConstraintError: ['The authenticator can’t meet a required option', 'The request required user verification or a discoverable credential the authenticator can’t provide. Use an authenticator with a PIN or biometric.'],
};

export function analyzeWebauthnError(input) {
  const name = findBrowserError(input);
  const [title, detail] = ERROR_HELP[name];
  const op = /\bcreate\b|regist/i.test(input) ? 'registration' : /\bget\b|sign[ -]?in|log[ -]?in|authenticat/i.test(input) ? 'sign-in' : null;
  const message = input.match(new RegExp(`${name}[:\\s]+([^\\n]{0,240})`))?.[1]?.trim() || null;
  return { kind: 'webauthn_error', facts: { error: name, during: op, message }, checks: [check('webauthn_error', name === 'AbortError' ? 'warn' : 'fail', title, detail)] };
}

// What Claude sees: decoded fields only, never the raw signature, attestation or public key.
export function condenseCredential(input, analysis) {
  const s = input.indexOf('{'), e = input.lastIndexOf('}');
  const note = `${input.slice(0, s)}\n${input.slice(e + 1)}`.trim();
  return `${note}\n\n[Passkey credential JSON, decoded by code; signature, attestation and public key removed]\n${JSON.stringify(analysis.facts, null, 2)}`.trim().slice(0, 8000);
}
