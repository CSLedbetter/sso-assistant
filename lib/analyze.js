// Deterministic SSO checks. Everything here runs with code, before Claude reads anything,
// so the page can show hard pass/fail results separately from Claude's explanation.
import { X509Certificate } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';

const STATUS_PREFIX = 'urn:oasis:names:tc:SAML:2.0:status:';
const SKEW_TOLERANCE_S = 60;

// ---------- small helpers (namespace-agnostic, no XML library needed for these fields) ----------
const tagRe = (name) => new RegExp(`<(?:[\\w-]+:)?${name}\\b([^>]*)>([\\s\\S]*?)</(?:[\\w-]+:)?${name}>`, 'i');
const emptyTagRe = (name) => new RegExp(`<(?:[\\w-]+:)?${name}\\b([^>]*?)/?>`, 'i');
const attr = (attrs, name) => attrs?.match(new RegExp(`\\b${name}="([^"]*)"`))?.[1];
const text = (xml, name) => xml.match(tagRe(name))?.[2]?.trim();
const tagAttrs = (xml, name) => xml.match(tagRe(name))?.[1] ?? xml.match(emptyTagRe(name))?.[1];
const toDate = (s) => (s ? new Date(s) : null);
const secs = (a, b) => Math.round((a - b) / 1000);

function check(id, status, title, detail) {
  return { id, status, title, detail };
}

// ---------- find what was pasted ----------
export function detect(input) {
  const t = input.trim();
  const saml = findSaml(t);
  if (saml) return { kind: 'saml', xml: saml.xml, encoding: saml.encoding };
  const jwt = t.match(/eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/);
  if (jwt) return { kind: 'oidc_token', token: jwt[0] };
  if (/urn:ietf:params:scim:api:messages:2\.0:Error/.test(t) || /"scimType"\s*:/.test(t)) return { kind: 'scim_error' };
  if (/"error"\s*:\s*"(invalid_client|invalid_grant|unauthorized_client|invalid_request|access_denied)"/.test(t) || /\bAADSTS\d{5,}/.test(t)) return { kind: 'oidc_error' };
  if (/anthropic-domain-verification-/i.test(t) || /\bdig\b.*\bTXT\b/i.test(t)) return { kind: 'dns' };
  return { kind: 'text' };
}

function findSaml(t) {
  if (/<(?:[\w-]+:)?Response\b[\s\S]*urn:oasis:names:tc:SAML/i.test(t)) return { xml: t.slice(t.search(/<(?:[\w-]+:)?Response\b/i)), encoding: 'xml' };
  // Base64 from a form post or the network tab: the longest base64 run, with line breaks and URL encoding removed.
  const candidates = t.replace(/%2B/gi, '+').replace(/%2F/gi, '/').replace(/%3D/gi, '=')
    .replace(/SAMLResponse=/g, ' ')
    .match(/[A-Za-z0-9+/=\r\n]{200,}/g) || [];
  for (const c of candidates.sort((a, b) => b.length - a.length)) {
    const b64 = c.replace(/\s+/g, '');
    const buf = Buffer.from(b64, 'base64');
    const plain = buf.toString('utf8');
    if (/urn:oasis:names:tc:SAML/.test(plain)) return { xml: plain, encoding: 'base64' };
    try {
      const inflated = inflateRawSync(buf).toString('utf8');
      if (/urn:oasis:names:tc:SAML/.test(inflated)) return { xml: inflated, encoding: 'deflate+base64' };
    } catch { /* not deflated */ }
  }
  return null;
}

// ---------- SAML ----------
export function analyzeSaml(xml, sp = {}) {
  const checks = [];
  const respAttrs = xml.match(/<(?:[\w-]+:)?Response\b([^>]*)>/i)?.[1] || '';
  const issued = toDate(attr(respAttrs, 'IssueInstant'));
  const facts = {
    issuer: text(xml, 'Issuer'),
    issue_instant: attr(respAttrs, 'IssueInstant'),
    destination: attr(respAttrs, 'Destination'),
    in_response_to: attr(respAttrs, 'InResponseTo') || null,
    status: attr(tagAttrs(xml, 'StatusCode'), 'Value')?.replace(STATUS_PREFIX, ''),
    status_message: text(xml, 'StatusMessage') || null,
    audience: text(xml, 'Audience') || null,
    recipient: attr(tagAttrs(xml, 'SubjectConfirmationData'), 'Recipient') || null,
    name_id: text(xml, 'NameID') || null,
    name_id_format: attr(tagAttrs(xml, 'NameID'), 'Format')?.split(':').pop() || null,
    not_before: attr(tagAttrs(xml, 'Conditions'), 'NotBefore') || null,
    not_on_or_after: attr(tagAttrs(xml, 'Conditions'), 'NotOnOrAfter') || null,
    attributes: [...xml.matchAll(/<(?:[\w-]+:)?Attribute\b[^>]*\bName="([^"]+)"/gi)].map((m) => m[1]),
    encrypted_assertion: /<(?:[\w-]+:)?EncryptedAssertion\b/i.test(xml),
  };
  const nested = [...xml.matchAll(/<(?:[\w-]+:)?StatusCode\b[^>]*Value="[^"]*status:([A-Za-z]+)"/g)].map((m) => m[1]);
  if (nested.length > 1) facts.status_detail = nested.slice(1).join(', ');

  // Status
  if (facts.status === 'Success') checks.push(check('status', 'pass', 'IdP reported success', 'The response status is Success.'));
  else checks.push(check('status', 'fail', `IdP returned ${facts.status || 'no status'}${facts.status_detail ? ` / ${facts.status_detail}` : ''}`,
    facts.status_message ? `The IdP said: “${facts.status_message}”. No assertion was issued, so the problem is on the IdP side.` : 'No assertion was issued.'));

  // Signatures
  const assertion = xml.match(tagRe('Assertion'))?.[0] || '';
  const responseOnly = xml.replace(assertion, '');
  const responseSigned = /<(?:[\w-]+:)?Signature\b/i.test(responseOnly);
  const assertionSigned = /<(?:[\w-]+:)?Signature\b/i.test(assertion);
  facts.signed = { response: responseSigned, assertion: assertionSigned };
  if (facts.status === 'Success') {
    if (!responseSigned && !assertionSigned && !facts.encrypted_assertion) checks.push(check('signature', 'fail', 'Nothing is signed', 'Neither the response nor the assertion has a signature. Service providers reject unsigned SAML, so turn on signing in the IdP app.'));
    else checks.push(check('signature', 'pass', 'Signature present', `Signed: ${[responseSigned && 'response', assertionSigned && 'assertion'].filter(Boolean).join(' and ') || 'encrypted assertion'}. This demo checks that a signature exists and inspects the certificate; it doesn't verify the signature cryptographically.`));
  }

  // Certificate
  const certB64 = text(xml, 'X509Certificate')?.replace(/\s+/g, '');
  if (certB64) {
    try {
      const cert = new X509Certificate(Buffer.from(certB64, 'base64'));
      const validTo = new Date(cert.validTo);
      const validFrom = new Date(cert.validFrom);
      const at = issued || new Date();
      facts.certificate = { subject: cert.subject.replace(/\n/g, ', '), valid_from: validFrom.toISOString(), valid_to: validTo.toISOString(), sha256_fingerprint: cert.fingerprint256 };
      if (validTo < at) checks.push(check('cert_expiry', 'fail', 'Signing certificate had expired', `It expired ${validTo.toISOString().slice(0, 10)}, before this response was issued. Generate a new certificate in the IdP, then update it in the service provider's SSO settings.`));
      else if (validFrom > at) checks.push(check('cert_expiry', 'fail', 'Signing certificate not valid yet', `It's valid from ${validFrom.toISOString().slice(0, 10)}.`));
      else {
        const days = Math.floor((validTo - at) / 86400000);
        checks.push(check('cert_expiry', days < 30 ? 'warn' : 'pass', days < 30 ? `Certificate expires in ${days} days` : 'Certificate in date', `Valid until ${validTo.toISOString().slice(0, 10)}.`));
      }
      if (sp.cert_fingerprint) {
        const norm = (s) => s.replace(/[^0-9a-f]/gi, '').toUpperCase();
        const match = norm(sp.cert_fingerprint) === norm(cert.fingerprint256);
        checks.push(check('cert_match', match ? 'pass' : 'fail', match ? 'Certificate matches the SP settings' : 'Certificate doesn’t match the SP settings',
          match ? 'The SHA-256 fingerprint matches the one configured.' : 'The IdP is signing with a different certificate than the one saved in the service provider, which usually means it was rotated in the IdP but not updated in the SSO settings.'));
      }
    } catch {
      checks.push(check('cert_parse', 'warn', 'Couldn’t read the certificate', 'The X509Certificate element isn’t a valid certificate.'));
    }
  } else if (facts.status === 'Success') {
    checks.push(check('cert_missing', 'info', 'No certificate in the response', 'Some IdPs leave it out. The service provider then uses the certificate saved in its settings.'));
  }

  if (facts.status === 'Success') {
    // Audience and recipient
    if (sp.entity_id) checks.push(facts.audience === sp.entity_id
      ? check('audience', 'pass', 'Audience matches the SP entity ID', facts.audience)
      : check('audience', 'fail', 'Audience doesn’t match the SP entity ID', `The IdP sent “${facts.audience ?? 'none'}” but the service provider expects “${sp.entity_id}”. Fix the Audience URI / SP Entity ID field in the IdP app.`));
    if (sp.acs_url) {
      const urls = [facts.destination, facts.recipient].filter(Boolean);
      const bad = urls.filter((u) => u !== sp.acs_url);
      checks.push(bad.length
        ? check('acs', 'fail', 'Sent to the wrong ACS URL', `Destination/Recipient is “${bad[0]}” but the service provider’s ACS URL is “${sp.acs_url}”. Fix the Single sign-on URL / Reply URL in the IdP app.`)
        : check('acs', 'pass', 'ACS URL matches', sp.acs_url));
    }

    // Time window and clock skew, judged at the moment the IdP issued the response
    const nb = toDate(facts.not_before), na = toDate(facts.not_on_or_after);
    if (issued && nb && secs(nb, issued) > SKEW_TOLERANCE_S) {
      checks.push(check('clock', 'fail', 'Assertion starts in the future', `NotBefore is ${secs(nb, issued)} seconds after the IdP issued it. The IdP server’s clock is likely wrong; sync it with NTP. Most SPs allow only a minute or so of skew.`));
    } else if (issued && na && secs(na, issued) < 60) {
      checks.push(check('clock', 'warn', 'Very short validity window', `The assertion is valid for only ${secs(na, issued)} seconds after issue.`));
    } else if (nb || na) {
      checks.push(check('clock', 'pass', 'Validity window looks normal', `${facts.not_before ?? '?'} to ${facts.not_on_or_after ?? '?'}`));
    }

    // NameID
    const isEmail = /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(facts.name_id || '');
    if ((sp.nameid || 'email') === 'email') {
      if (!isEmail) checks.push(check('nameid', 'fail', 'NameID isn’t an email address', `NameID is “${facts.name_id}” (format: ${facts.name_id_format}). Set the IdP app to send the user’s email as NameID with the emailAddress format.`));
      else if (facts.name_id_format && facts.name_id_format !== 'emailAddress') checks.push(check('nameid', 'warn', 'NameID format isn’t emailAddress', `The value is an email, but the format is ${facts.name_id_format}.`));
      else checks.push(check('nameid', 'pass', 'NameID is an email address', facts.name_id));
    }
    if (!facts.attributes.some((a) => /mail/i.test(a)) && !isEmail) checks.push(check('email_attr', 'warn', 'No email attribute', 'There’s no email attribute either, so the SP can’t match the user to an account.'));
  }
  return { kind: 'saml', facts, checks };
}

// ---------- OIDC ID token ----------
export function analyzeToken(token, sp = {}, at = new Date()) {
  const [h, p] = token.split('.');
  const dec = (s) => JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));
  let header, payload;
  try { header = dec(h); payload = dec(p); } catch { return { kind: 'oidc_token', facts: {}, checks: [check('decode', 'fail', 'Not a readable JWT', 'The token couldn’t be decoded.')] }; }
  const checks = [];
  const t = (n) => (n ? new Date(n * 1000).toISOString() : null);
  const facts = { alg: header.alg, kid: header.kid, iss: payload.iss, aud: payload.aud, sub: payload.sub, email: payload.email || null, issued_at: t(payload.iat), expires_at: t(payload.exp), nonce: payload.nonce || null };
  if (!header.alg || header.alg.toLowerCase() === 'none') checks.push(check('alg', 'fail', 'Token isn’t signed', 'alg is “none”. Reject it.'));
  else checks.push(check('alg', 'pass', `Signed with ${header.alg}`, 'This demo reads the token; it doesn’t verify the signature.'));
  if (sp.client_id) {
    const auds = [].concat(payload.aud || []);
    checks.push(auds.includes(sp.client_id)
      ? check('aud', 'pass', 'Audience matches the client ID', sp.client_id)
      : check('aud', 'fail', 'Token was issued to a different app', `aud is “${auds.join(', ')}” but the expected client ID is “${sp.client_id}”. The IdP is using the wrong app registration.`));
  }
  if (payload.exp && payload.iat && payload.exp - payload.iat > 86400) checks.push(check('lifetime', 'warn', 'Unusually long token lifetime', `${Math.round((payload.exp - payload.iat) / 3600)} hours.`));
  if (!payload.email) checks.push(check('email', 'warn', 'No email claim', 'Ask for the email scope so the SP can match the user.'));
  else checks.push(check('email', 'pass', 'Email claim present', payload.email));
  if (payload.exp && payload.exp * 1000 < at.getTime()) checks.push(check('exp', 'info', 'Token has since expired', `It expired ${facts.expires_at}. That’s expected for a token copied from logs.`));
  return { kind: 'oidc_token', facts, checks };
}

// ---------- OIDC error, SCIM error, DNS ----------
export function analyzeOidcError(input) {
  const json = safeJson(input);
  const code = input.match(/\bAADSTS(\d{5,})/)?.[0];
  const facts = { error: json?.error || input.match(/"error"\s*:\s*"([a-z_]+)"/)?.[1] || null, error_description: json?.error_description || null, provider_code: code || null };
  const checks = [];
  if (code === 'AADSTS7000222' || /client secret[^.]*expired/i.test(input)) checks.push(check('secret', 'fail', 'Client secret expired', 'Create a new client secret in the IdP, then paste it into the service provider’s SSO settings.'));
  else if (facts.error === 'invalid_client') checks.push(check('client', 'fail', 'Client authentication failed', 'The client ID or secret the SP is using doesn’t match the IdP app.'));
  else checks.push(check('oidc', 'info', `OIDC error: ${facts.error || 'unknown'}`, facts.error_description || ''));
  return { kind: 'oidc_error', facts, checks };
}

export function analyzeScim(input) {
  const json = safeJson(input);
  const facts = { status: json?.status ?? null, scim_type: json?.scimType ?? null, detail: json?.detail ?? null };
  const label = { uniqueness: 'A user or group with that value already exists', mutability: 'Tried to change a read-only attribute', invalidValue: 'An attribute value was rejected', invalidFilter: 'The filter syntax was rejected', noTarget: 'The target wasn’t found' }[facts.scim_type];
  return { kind: 'scim_error', facts, checks: [check('scim', 'fail', label || `SCIM error ${facts.status ?? ''}`.trim(), facts.detail || '')] };
}

export function analyzeDns(input) {
  const blocks = [...input.matchAll(/dig\b[^\n]*\bTXT\s+(\S+)\s*\n([\s\S]*?)(?=\n\s*\$|\n\s*\n|$)/gi)].map((m) => ({ host: m[1].replace(/\.$/, ''), records: m[2].trim() }));
  const facts = { lookups: blocks };
  const checks = [];
  const withToken = blocks.filter((b) => /anthropic-domain-verification-/i.test(b.records));
  if (!blocks.length) checks.push(check('dns', 'info', 'No dig output found', 'Paste the output of dig TXT for the domain.'));
  else if (!withToken.length) checks.push(check('dns', 'fail', 'No verification record found', 'None of the lookups show a TXT record starting with anthropic-domain-verification-.'));
  else {
    const root = blocks.reduce((a, b) => (b.host.split('.').length < a.host.split('.').length ? b : a));
    const onRoot = withToken.some((b) => b.host === root.host);
    checks.push(onRoot
      ? check('dns', 'pass', 'Verification record is on the domain itself', root.host)
      : check('dns', 'fail', 'Verification record is on the wrong host', `It’s on ${withToken[0].host}, not ${root.host}. Add the TXT record at the domain root (host “@” in most DNS tools).`));
  }
  return { kind: 'dns', facts, checks };
}

function safeJson(input) {
  const s = input.indexOf('{'), e = input.lastIndexOf('}');
  if (s < 0 || e < s) return null;
  try { return JSON.parse(input.slice(s, e + 1)); } catch { return null; }
}

export function analyze(input, sp = {}) {
  const d = detect(input);
  if (d.kind === 'saml') return { ...analyzeSaml(d.xml, sp), encoding: d.encoding };
  if (d.kind === 'oidc_token') return analyzeToken(d.token, sp);
  if (d.kind === 'oidc_error') return analyzeOidcError(input);
  if (d.kind === 'scim_error') return analyzeScim(input);
  if (d.kind === 'dns') return analyzeDns(input);
  return { kind: 'text', facts: {}, checks: [check('none', 'info', 'No SAML, token, or error payload found', 'Claude will work from the ticket text alone.')] };
}

// Strip signatures and certificate bodies before the XML goes to Claude: they're long and carry no meaning for it.
export function compactXml(xml) {
  return xml
    .replace(/<(?:[\w-]+:)?SignatureValue>[\s\S]*?<\/(?:[\w-]+:)?SignatureValue>/gi, '<ds:SignatureValue>[omitted]</ds:SignatureValue>')
    .replace(/<(?:[\w-]+:)?X509Certificate>[\s\S]*?<\/(?:[\w-]+:)?X509Certificate>/gi, '<ds:X509Certificate>[omitted, see facts]</ds:X509Certificate>')
    .replace(/<(?:[\w-]+:)?DigestValue>[\s\S]*?<\/(?:[\w-]+:)?DigestValue>/gi, '<ds:DigestValue>[omitted]</ds:DigestValue>')
    .slice(0, 6000);
}
