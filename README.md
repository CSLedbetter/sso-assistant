# SSO Assistant

Paste what a customer sent about a broken single sign-on: a SAML response (base64, URL-encoded, or XML), an OIDC ID token, an IdP error, a SCIM error, a passkey (WebAuthn) response or browser passkey error, `dig` output for domain verification, or just their ticket. Code decodes it and runs the checks people usually get wrong by eye. Then Claude explains the failure, says where the fix lives (their IdP, their Claude SSO settings, or their DNS), links the right help center article, and drafts a reply for the IT admin and a summary for an executive.

- **Live demo:** https://sso-assistant.caseyledbetter.com (running the checks is free; explaining needs an approved sign-in)
- **Sibling tools:** [Doc Gap Finder](https://doc-gap-finder.caseyledbetter.com) and [API Error Explainer](https://api-error-explainer.caseyledbetter.com)
- **Stack:** static HTML/CSS/JS, Vercel functions in Node with no dependencies (`node:crypto` reads the certificates), Claude API with structured outputs, Supabase Auth for sign-in and Postgres for approvals and the shared spend cap.

## What code checks

| Pasted | Checks |
|---|---|
| SAML response | IdP status (for example Responder/RequestDenied for an unassigned user), signatures present on the response or assertion, certificate dates and SHA-256 fingerprint against the one saved in the SP, Audience against the SP entity ID, Destination and Recipient against the ACS URL, NotBefore/NotOnOrAfter against the issue time (clock skew), NameID is an email |
| OIDC ID token | `alg` isn't `none`, `aud` matches the client ID, email claim present, lifetime |
| OIDC error | Expired client secret (Entra `AADSTS7000222`), `invalid_client` |
| SCIM error | `scimType` translated (uniqueness, mutability, ...) |
| Passkey response (`credential.toJSON()`) | Origin against the allowed origins (the phishing-resistance check), RP ID hash against the RP ID (and which domain an orphaned passkey was really made for), challenge, user present and user verified flags, synced versus device-bound against the passkey policy, key algorithm and attestation format, signature presence |
| Browser passkey error | `NotAllowedError`, `InvalidStateError`, `SecurityError`, `NotSupportedError`, `AbortError`, `ConstraintError`, and whether it happened during registration or sign-in |
| `dig` output | The `anthropic-domain-verification-` TXT record is on the domain root, not `www` |

Signatures are checked for presence and the certificate is inspected; the demo doesn't verify SAML or passkey signatures cryptographically.

For passkeys, Claude gets only the decoded fields. The signature, attestation object, authenticator data and public key never leave the server.

## Live passkey demo

The page can create a throwaway passkey for its own domain with `navigator.credentials.create()`, run the checks on what the browser returned, then sign in with it. A visitor can then change the RP ID, allowed origins or policy and rerun the checks to see what a look-alike phishing page, a domain migration, or a device-bound policy does to the same passkey. Cancelling the prompt shows the `NotAllowedError` a customer would report. The passkey's account name is `sso-assistant-demo`, nothing is stored on the server, and where the browser supports the Signal API the page can ask the password manager to remove it.

Claude gets the decoded XML with signature values and certificate bodies stripped, the decoded fields, and the check results. Its doc links are limited to four Claude help center articles on SSO, provisioning and domains, and its facts come from those articles.

## Sample tickets

`public/tickets.json` has 20 fictional tickets. `data/make_samples.py` builds the 13 SAML, OIDC, SCIM and DNS tickets with real, freshly generated X.509 certificates so the responses decode exactly like real ones. `data/make_passkey_samples.py` adds 7 passkey tickets with real P-256 keys, CBOR attestation objects and ES256 signatures; run it after `make_samples.py`, which rewrites the file (`npm run samples` runs both). Each one is built to fail one check (or none, for the two where the problem is somewhere code can't see), and `npm test` confirms it.

## Sign-in, approval, and the $15 cap

Running the checks is free and needs no sign-in. Explaining calls Claude, so visitors sign in with Google through Supabase Auth and wait for the owner to approve them. This tool shares one $15 budget with API Error Explainer, enforced in Postgres before Claude is called: $5 per approved person by default and 30 requests per person per hour, with every request reserving its worst-case cost before settling to the real one. The approval page, schema and SQL are in the [API Error Explainer repo](https://github.com/CSLedbetter/api-error-explainer#sign-in-approval-and-the-15-cap).

## Saved diagnoses

Each paid diagnosis is saved in the visitor's browser tab, keyed by a SHA-256 hash of the exact input (plus the ticket, and the SP settings in SSO Assistant). Clicking the paid button again on the same input shows the saved result with its original time and Claude request ID, and makes no new call. A **Run a fresh diagnosis** link forces a new one. Saved results live in `sessionStorage`, so they survive a reload, clear when the tab closes or the visitor signs out, and never include the pasted text itself.

## Run it locally

```
cp .env.example .env.local   # add your own keys
npm test
npx vercel dev
npm run samples              # regenerate the sample tickets (needs the cryptography package)
```

## Environment variables

Server-side only, set in Vercel: `ADMIN_EMAIL`, `ANTHROPIC_API_KEY`, `SUPABASE_URL`, `SUPABASE_SECRET_KEY`, and optionally `CLAUDE_MODEL` (defaults to `claude-sonnet-5-5`).
