# SSO Assistant

Paste what a customer sent about a broken single sign-on: a SAML response (base64, URL-encoded, or XML), an OIDC ID token, an IdP error, a SCIM error, `dig` output for domain verification, or just their ticket. Code decodes it and runs the checks people usually get wrong by eye. Then Claude explains the failure, says where the fix lives (their IdP, their Claude SSO settings, or their DNS), links the right help center article, and drafts a reply for the IT admin and a summary for an executive.

- **Live demo:** https://sso-assistant.caseyledbetter.com (running the checks is free; explaining needs an access code)
- **Sibling tools:** [Doc Gap Finder](https://doc-gap-finder.caseyledbetter.com) and [API Error Explainer](https://api-error-explainer.caseyledbetter.com)
- **Stack:** static HTML/CSS/JS, Vercel functions in Node with no dependencies (`node:crypto` reads the certificates), Claude API with structured outputs, Supabase for access codes and the shared spend cap.

## What code checks

| Pasted | Checks |
|---|---|
| SAML response | IdP status (for example Responder/RequestDenied for an unassigned user), signatures present on the response or assertion, certificate dates and SHA-256 fingerprint against the one saved in the SP, Audience against the SP entity ID, Destination and Recipient against the ACS URL, NotBefore/NotOnOrAfter against the issue time (clock skew), NameID is an email |
| OIDC ID token | `alg` isn't `none`, `aud` matches the client ID, email claim present, lifetime |
| OIDC error | Expired client secret (Entra `AADSTS7000222`), `invalid_client` |
| SCIM error | `scimType` translated (uniqueness, mutability, ...) |
| `dig` output | The `anthropic-domain-verification-` TXT record is on the domain root, not `www` |

Signatures are checked for presence and the certificate is inspected; the demo doesn't verify signatures cryptographically.

Claude gets the decoded XML with signature values and certificate bodies stripped, the decoded fields, and the check results. Its doc links are limited to four Claude help center articles on SSO, provisioning and domains, and its facts come from those articles.

## Sample tickets

`public/tickets.json` has 13 fictional tickets. `data/make_samples.py` builds them with real, freshly generated X.509 certificates so the responses decode exactly like real ones. Each one is built to fail one check (or none, for the two where the problem is somewhere code can't see), and `npm test` confirms it.

## Access codes and the $15 cap

This tool shares one $15 budget with API Error Explainer, enforced in Postgres before Claude is called: $5 per access code, 30 requests per code per hour, and every request reserves its worst-case cost before settling to the real one. Codes are stored as SHA-256 hashes, and only the server's secret key can check or spend them. The schema and the SQL for creating, revoking and auditing codes are in the [API Error Explainer repo](https://github.com/CSLedbetter/api-error-explainer#access-codes-and-the-15-cap).

## Run it locally

```
cp .env.example .env.local   # add your own keys
npm test
npx vercel dev
python3 data/make_samples.py # regenerate the sample tickets (needs the cryptography package)
```

## Environment variables

Server-side only, set in Vercel: `ANTHROPIC_API_KEY`, `SUPABASE_URL`, `SUPABASE_SECRET_KEY`, and optionally `CLAUDE_MODEL` (defaults to `claude-sonnet-5-5`).
